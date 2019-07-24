//! Contains all cryptographic algorithms we need.
//!
//! This is pretty messy code since we still need openssl to parse PEM-encoded
//! keys. Once there's a good Rust crate for that, we should switch to it.

use crate::utils::Blob;
use crate::{AesKey, Error, ErrorKind, P256KeyPair, P256PublicKey};

use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::PointConversionForm;
use openssl::symm::{self, Cipher, Crypter};
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature;

/// Generates a random 12-Byte nonce using the OS random number generator.
///
/// If obtaining the random data fails, this function will panic. This should
/// not really happen during normal usage.
pub fn random_nonce() -> [u8; 12] {
    let mut nonce = [0; 12];
    SystemRandom::new()
        .fill(&mut nonce)
        .expect("unable to obtain random bytes");
    nonce
}

/// Builds the 16-byte IV from the 12-byte nonce stored in the encryption init
/// header.
fn build_iv(nonce: [u8; 12]) -> [u8; 16] {
    let mut iv = [0; 16];
    // first byte is... magic, I guess
    iv[0] = 0x02;
    iv[1..13].copy_from_slice(&nonce);
    // 24-bit counter, apparently (starting at 1, not 0!)
    iv[13..16].copy_from_slice(&[0x00, 0x00, 0x01]);

    debug!("using nonce: {:?}", Blob(&nonce));
    debug!("using    iv: {:?}", Blob(&iv));

    iv
}

/// Encrypts or decrypts a list of sections, returning each
/// section as raw bytes.
///
/// # Parameters
///
/// * `key`: The 128-bit AES key.
/// * `nonce`: The 12-byte nonce stored in the encryption header of the GBL
///   file.
/// * `sections`: Iterator over the sections of the GBL.
///   Will be encrypted or decrypted in series.
pub fn crypt<S: AsRef<[u8]>>(key: AesKey, nonce: [u8; 12], sections: &[S]) -> Vec<Vec<u8>> {
    // FIXME(perf): Optimize storage of return type (`Vec<&[u8]>` with shared backing store)

    let iv = build_iv(nonce);

    let cipher = Cipher::aes_128_ctr();
    let block_size = cipher.block_size();
    debug!(
        "key size: {}, iv size: {:?}, block size: {}",
        cipher.key_len(),
        cipher.iv_len(),
        block_size
    );

    let mut crypter = Crypter::new(cipher, symm::Mode::Decrypt, key.as_raw(), Some(&iv)).unwrap();

    sections
        .into_iter()
        .map(|section| {
            let section = section.as_ref();
            let mut data = vec![0; section.len() + block_size];
            let size = crypter.update(&section, &mut data).unwrap();
            let data = &data[..size];
            assert_eq!(
                section.len(),
                size,
                "input {} bytes, got {} bytes out",
                section.len(),
                size
            );

            data.to_vec()
        })
        .collect()
}

pub fn verify_signature(
    pubkey: &P256PublicKey,
    signature: &[u8; 64],
    data: &[u8],
) -> Result<(), Error> {
    // Use OpenSSL to convert the key to uncompressed point format.
    // FIXME: Using both OpenSSL and ring is a bit dumb - we'd need to parse
    // the PEM file (there's a `pem` crate that works), then the contained
    // DER (?) encoded ASN.1 data, then get the contained pubkey and convert
    // it to an "uncompressed point", which I don't think there are crates
    // for.

    // Dump the raw pubkey
    let mut bncx = BigNumContext::new().unwrap();
    let group = pubkey.inner.group();
    let pubkey = pubkey.inner.public_key();
    {
        let (mut x, mut y) = (BigNum::new().unwrap(), BigNum::new().unwrap());
        pubkey
            .affine_coordinates_gfp(group, &mut x, &mut y, &mut bncx)
            .unwrap();
        trace!(
            "verify_signature: pubkey (affine_coordinates_gfp):  ({},{})",
            x.to_hex_str().unwrap(),
            y.to_hex_str().unwrap()
        );
        pubkey
            .affine_coordinates_gf2m(group, &mut x, &mut y, &mut bncx)
            .unwrap();
        trace!(
            "verify_signature: pubkey (affine_coordinates_gf2m): ({},{})",
            x.to_hex_str().unwrap(),
            y.to_hex_str().unwrap()
        );
    }

    let uncompressed_bytes = pubkey
        .to_bytes(group, PointConversionForm::UNCOMPRESSED, &mut bncx)
        .unwrap();

    signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, &uncompressed_bytes)
        .verify(&data, &signature[..])
        .map_err(|_| ErrorKind::InvalidSignature)?;

    Ok(())
}

pub fn create_signature(keypair: &P256KeyPair, data_to_sign: &[u8]) -> Result<[u8; 64], Error> {
    // TODO: Support signing via hardware security module and via locked key.

    let priv_key = keypair.inner.private_key().to_vec(); // big-endian encoding of the bignum
    let pub_key = keypair
        .inner
        .public_key()
        .to_bytes(
            keypair.inner.group(),
            PointConversionForm::UNCOMPRESSED,
            &mut BigNumContext::new().unwrap(),
        )
        .unwrap();

    let keypair = signature::EcdsaKeyPair::from_private_key_and_public_key(
        &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        &priv_key,
        &pub_key,
    )
    .map_err(|_| ErrorKind::ParseError)?;

    let sig = keypair
        .sign(&ring::rand::SystemRandom::new(), data_to_sign)
        .map_err(|e| Error::with_details(ErrorKind::Other, e.to_string()))?
        .as_ref()
        .to_vec();
    assert_eq!(sig.len(), 64, "expected a 64 byte signature");

    if cfg!(debug_assertions) {
        // Just to make sure everything worked, verify the created signature right
        // afterwards.
        signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, &pub_key)
            .verify(data_to_sign, &sig)
            .expect("created signature could not be verified");
    }

    let mut raw_sig = [0; 64];
    raw_sig.copy_from_slice(&sig);
    Ok(raw_sig)
}
