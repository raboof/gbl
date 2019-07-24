extern crate gbl;

use gbl::marker::{MaybeEncrypted, MaybeSigned};
use gbl::{AesKey, AppImage, Gbl, P256KeyPair, P256PublicKey};

/// Includes a binary or text file from the test data directory.
macro_rules! test_data {
    ( bytes $file:tt ) => {{
        &include_bytes!(concat!("../test-data/", $file))[..]
    }};
    ( array $file:tt ) => {{
        *include_bytes!(concat!("../test-data/", $file))
    }};
    ( str $file:tt ) => {
        include_str!(concat!("../test-data/", $file))
    };
}

#[test]
fn parse_empty_gbl() {
    let gbl = Gbl::parse(test_data!(bytes "empty/empty.gbl")).unwrap();
    assert!(!gbl.is_encrypted());
    assert!(!gbl.is_signed());

    let gbl = Gbl::parse(test_data!(bytes "empty/empty-signed.gbl")).unwrap();
    assert!(!gbl.is_encrypted());
    assert!(gbl.is_signed());

    let gbl = Gbl::parse(test_data!(bytes "empty/empty-encrypted.gbl")).unwrap();
    assert!(gbl.is_encrypted());
    assert!(!gbl.is_signed());

    let gbl = Gbl::parse(test_data!(bytes "empty/empty-signed-encrypted.gbl")).unwrap();
    assert!(gbl.is_encrypted());
    assert!(gbl.is_signed());
}

/// Tests that creating `empty.gbl` from `empty.bin` results in the same file
/// that's already there (which was created by the reference implementation).
#[test]
fn create_empty_gbl() {
    let bin = AppImage::parse(test_data!(bytes "empty/empty.bin")).unwrap();
    let gbl = Gbl::from_app_image(bin);
    let gbl = gbl.to_bytes();

    assert_eq!(gbl, &test_data!(bytes "empty/empty.gbl")[..]);
}

/// Here, the input image has a broken appinfo magic number.
#[test]
fn create_from_invalid_magic() {
    let bin = test_data!(bytes "empty/empty-invalid-appinfo-magic.bin");
    assert!(AppImage::parse(bin)
        .unwrap_err()
        .to_string()
        .contains("could not find application info in binary image"));
}

/// Test that GBL creation from an app image that's too small to contain the
/// app info fails properly.
#[test]
fn create_from_too_short_image() {
    let bin = test_data!(bytes "empty/empty-too-short.bin");
    assert!(AppImage::parse(bin)
        .unwrap_err()
        .to_string()
        .contains("too small"));
}

/// Tests that decrypting `empty-encrypted.gbl` and `empty-signed-encrypted.gbl`
/// both yield the original `empty.gbl`.
#[test]
fn decrypt_empty_gbl() {
    let original = Gbl::parse(test_data!(bytes "empty/empty.gbl"))
        .unwrap()
        .to_bytes();

    let enc = Gbl::parse(test_data!(bytes "empty/empty-encrypted.gbl")).unwrap();
    assert!(enc.is_encrypted());
    assert!(!enc.is_signed());
    let enc = enc.into_encrypted().unwrap().into_not_signed().unwrap();
    assert!(enc.is_encrypted());
    assert!(!enc.is_signed());
    let decrypted = enc
        .clone()
        .decrypt(AesKey::from_token_file(test_data!(str "aes-key-tokens")).unwrap())
        .unwrap();
    assert!(!decrypted.is_encrypted());
    assert!(!decrypted.is_signed());

    assert_eq!(decrypted.to_bytes(), original);

    let raw_key = [
        0xE7, 0xE5, 0x56, 0xB6, 0x35, 0xA3, 0x52, 0x06, 0x59, 0xA2, 0xE1, 0x61, 0xCB, 0xDF, 0x4B,
        0xC2,
    ];
    let decrypted = enc.clone().decrypt(AesKey::from_raw(raw_key)).unwrap();
    assert!(!decrypted.is_encrypted());
    assert!(!decrypted.is_signed());

    assert_eq!(decrypted.to_bytes(), original);

    let enc_signed = Gbl::parse(test_data!(bytes "empty/empty-signed-encrypted.gbl")).unwrap();
    let enc_signed = enc_signed.into_encrypted().unwrap().into_signed().unwrap();
    let decrypted = enc_signed
        .remove_signature()
        .decrypt(AesKey::from_token_file(test_data!(str "aes-key-tokens")).unwrap())
        .unwrap();
    assert!(!decrypted.is_encrypted());
    assert!(!decrypted.is_signed());

    assert_eq!(decrypted.to_bytes(), original);
}

// Tests the property that encrypt and decrypt are inverse functions for data `empty.gbl` and `empty-encrypted.gbl`
#[test]
fn crypto_roundtrip() {
    let normal = Gbl::parse(test_data!(bytes "empty/empty.gbl")).unwrap();
    let encrypted = Gbl::parse(test_data!(bytes "empty/empty-encrypted.gbl")).unwrap();
    let encrypted = encrypted
        .into_encrypted()
        .unwrap()
        .into_not_signed()
        .unwrap();

    let raw_key = [
        0xE7, 0xE5, 0x56, 0xB6, 0x35, 0xA3, 0x52, 0x06, 0x59, 0xA2, 0xE1, 0x61, 0xCB, 0xDF, 0x4B,
        0xC2,
    ];

    assert_eq!(
        encrypted
            .clone()
            .decrypt(AesKey::from_raw(raw_key))
            .unwrap()
            .encrypt(AesKey::from_raw(raw_key))
            .decrypt(AesKey::from_raw(raw_key))
            .unwrap()
            .to_bytes(),
        normal.to_bytes(),
    );

    let token = test_data!(str "aes-key-tokens");

    assert_eq!(
        encrypted
            .clone()
            .decrypt(AesKey::from_token_file(token).unwrap())
            .unwrap()
            .encrypt(AesKey::from_token_file(token).unwrap())
            .decrypt(AesKey::from_token_file(token).unwrap())
            .unwrap()
            .to_bytes(),
        normal.to_bytes(),
    );
}

/// Tests that the signature in `empty-signed.gbl` can be verified.
#[test]
fn verify_empty_gbl() {
    let signed = Gbl::parse(test_data!(bytes "empty/empty-signed.gbl")).unwrap();
    let signed = signed.into_signed().unwrap();
    signed
        .verify_signature(&P256PublicKey::from_pem(test_data!(str "signing-key.pub")).unwrap())
        .unwrap();

    let signed = Gbl::parse(test_data!(bytes "empty/empty-signed-encrypted.gbl")).unwrap();
    let signed = signed.into_signed().unwrap();
    signed
        .verify_signature(&P256PublicKey::from_pem(test_data!(str "signing-key.pub")).unwrap())
        .unwrap();
}

#[test]
fn verify_unsigned_gbl() {
    // unsigned GBLs cannot be signature-verified - conversion will fail
    let unsigned = Gbl::parse(test_data!(bytes "empty/empty.gbl")).unwrap();
    unsigned.clone().into_signed().unwrap_err();
    unsigned.into_not_signed().unwrap();
}

/// Tests cases in which `verify_signature` should fail.
#[test]
fn verify_empty_gbl_negative() {
    fn verify_gbl(signed: Gbl<MaybeEncrypted, MaybeSigned>) {
        assert!(signed.is_signed());
        let signed = signed.into_signed().unwrap();

        // Signature made by different key
        signed
            .verify_signature(
                &P256PublicKey::from_pem(test_data!(str "different-key.pub")).unwrap(),
            )
            .unwrap_err();

        // Key invalid
        P256PublicKey::from_pem(test_data!(str "different-key-tokens.txt"))
            .err()
            .unwrap();

        // Parse a private key as a public key
        P256PublicKey::from_pem(test_data!(str "different-key"))
            .err()
            .unwrap();

        // RSA key (we need an EC key)
        P256PublicKey::from_pem(test_data!(str "rsa-key.pub"))
            .err()
            .unwrap();

        // RSA private key (even wronger)
        P256PublicKey::from_pem(test_data!(str "rsa-key"))
            .err()
            .unwrap();
    }

    let signed = Gbl::parse(test_data!(bytes "empty/empty-signed.gbl")).unwrap();
    verify_gbl(signed);

    let signed = Gbl::parse(test_data!(bytes "empty/empty-signed-encrypted.gbl")).unwrap();
    verify_gbl(signed);
}

#[test]
fn sign_empty_gbl() {
    let original = Gbl::parse(test_data!(bytes "empty/empty.gbl")).unwrap();
    let original = original
        .into_not_encrypted()
        .unwrap()
        .into_not_signed()
        .unwrap();
    let signed = Gbl::parse(test_data!(bytes "empty/empty-signed.gbl")).unwrap();
    let signed = signed.into_signed().unwrap();

    let signed2 = original
        .sign(&P256KeyPair::from_pem(test_data!(str "signing-key")).unwrap())
        .unwrap();
    assert!(signed2.is_signed());
    assert!(!signed2.is_encrypted());

    signed
        .verify_signature(&P256PublicKey::from_pem(test_data!(str "signing-key.pub")).unwrap())
        .unwrap();
    signed2
        .verify_signature(&P256PublicKey::from_pem(test_data!(str "/signing-key.pub")).unwrap())
        .unwrap();

    // `signed` and `signed2` won't contain the exact same bytes since ECDSA
    // signatures are random.

    // Sign `signed` again - this should overwrite the signature - this time
    // with a different key.
    let signed2 = signed
        .remove_signature()
        .sign(&P256KeyPair::from_pem(test_data!(str "different-key")).unwrap())
        .unwrap();
    assert!(signed2.is_signed());
    assert!(!signed2.is_encrypted());

    signed2
        .verify_signature(&P256PublicKey::from_pem(test_data!(str "signing-key.pub")).unwrap())
        .unwrap_err();
    signed2
        .verify_signature(&P256PublicKey::from_pem(test_data!(str "different-key.pub")).unwrap())
        .unwrap();

    let enc = Gbl::parse(test_data!(bytes "empty/empty-encrypted.gbl")).unwrap();
    assert!(!enc.is_signed());
    assert!(enc.is_encrypted());
    let enc = enc.into_encrypted().unwrap().into_not_signed().unwrap();
    assert!(!enc.is_signed());
    assert!(enc.is_encrypted());
    let signed_enc = enc
        .clone()
        .sign(&P256KeyPair::from_pem(test_data!(str "signing-key")).unwrap())
        .unwrap();
    assert!(signed_enc.is_signed());
    assert!(signed_enc.is_encrypted());
    signed_enc
        .verify_signature(&P256PublicKey::from_pem(test_data!(str "signing-key.pub")).unwrap())
        .unwrap();

    P256KeyPair::from_pem(test_data!(str "rsa-key"))
        .err()
        .unwrap();
}

/// Tests that signing an already signed GBL overwrites the signature.
#[test]
fn sign_twice() {
    let original = Gbl::parse(test_data!(bytes "empty/empty.gbl")).unwrap();
    let original = original.into_not_signed().unwrap();

    let signed = original
        .sign(&P256KeyPair::from_pem(test_data!(str "signing-key")).unwrap())
        .unwrap();
    assert!(signed.is_signed());
    assert!(!signed.is_encrypted());

    let signed_twice = signed
        .clone()
        .remove_signature()
        .sign(&P256KeyPair::from_pem(test_data!(str "different-key")).unwrap())
        .unwrap();
    assert!(signed_twice.is_signed());
    assert!(!signed_twice.is_encrypted());

    signed
        .verify_signature(&P256PublicKey::from_pem(test_data!(str "signing-key.pub")).unwrap())
        .unwrap();
    signed_twice
        .verify_signature(&P256PublicKey::from_pem(test_data!(str "different-key.pub")).unwrap())
        .unwrap();
}

#[test]
fn wrong_crc() {
    // Change the CRC
    let mut bytes = test_data!(array "empty/empty.gbl");
    bytes[bytes.len() - 1] = 0;

    assert!(Gbl::parse(&bytes[..])
        .unwrap_err()
        .to_string()
        .contains("invalid CRC checksum"));

    // Change the program data
    let mut bytes = test_data!(array "empty/empty.gbl");
    bytes[bytes.len() - 1 - 12] = 0xff;

    assert!(Gbl::parse(&bytes[..])
        .unwrap_err()
        .to_string()
        .contains("invalid CRC checksum"));
}

#[test]
fn sign_app_image() {
    let data = test_data!(bytes "empty/empty.bin");
    let app_image = AppImage::parse(data).unwrap();
    assert!(!app_image.is_signed());
    assert!(app_image.ecdsa_signature().is_none());

    let signed = app_image
        .sign(&P256KeyPair::from_pem(test_data!(str "signing-key")).unwrap())
        .unwrap();
    assert!(signed.is_signed());
    assert!(signed.ecdsa_signature().is_some());

    // we expect the raw image to grow by exactly 64 bytes:
    let raw = signed.into_raw();
    assert_eq!(raw.len(), data.len() + 64);
    let signed = AppImage::parse(&raw).unwrap();

    // signing it again should replace the existing signature and not grow the image
    let signed_again = signed
        .sign(&P256KeyPair::from_pem(test_data!(str "signing-key")).unwrap())
        .unwrap();
    assert!(signed_again.is_signed());
    assert!(signed_again.ecdsa_signature().is_some());
    assert_eq!(signed_again.into_raw().len(), raw.len());
}
