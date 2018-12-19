//! Method and apparatus for creating, parsing and manipulating GBL firmware
//! update files.
//!
//! GBL files are used to implement Over-the-Air (OTA) updates for some
//! microcontrollers. GBL is a container format wrapping the actual flash image.
//! GBL container files can optionally be [encrypted] and [signed].
//!
//! Existing GBL files can be loaded using [`Gbl::from_bytes`], an application
//! image can be packed into a GBL file using [`Gbl::from_app_image`].
//!
//! In addition to that, the crate also contains utilities for reading and
//! signing raw application images created by the firmware build process, which
//! can be used to enable secure boot. Refer to the [`AppImage`] type and the
//! below example for details.
//!
//! # Examples
//!
//! Demonstrates signing an app image for secure boot, then building, signing
//! and encrypting a GBL file containing it:
//!
//! ```
//! # use gbl::{Gbl, AppImage, AesKey};
//! # use failure::Error;
//! # fn run() -> Result<(), Error> {
//! let image_bytes = include_bytes!("../test-data/empty/empty.bin");
//! let signing_key = include_str!("../test-data/signing-key");  // in PEM format
//! let encrypt_key = include_str!("../test-data/aes-key-tokens");
//!
//! let image = AppImage::parse(image_bytes.as_ref())?;
//! let signed_image = image.sign(signing_key)?;
//!
//! let gbl = Gbl::from_app_image(signed_image);
//! // Use `gbl.push_data_section` here to add more data to the container
//! let enc = gbl.encrypt(AesKey::from_token_file(encrypt_key)?);
//! let signed = enc.sign(signing_key)?;
//! # Ok(()) } run().unwrap();
//! ```
//!
//! [encrypted]: struct.Gbl.html#method.encrypt
//! [signed]: struct.Gbl.html#method.sign
//! [`Gbl::from_bytes`]: struct.Gbl.html#method.from_bytes
//! [`Gbl::from_app_image`]: struct.Gbl.html#method.from_app_image
//! [`AppImage`]: struct.AppImage.html

/*

A note on implementation details for zero-copy parsing:

Calling `<Cow as Clone>::clone` on an owned Cow will clone the owned value,
which might be expensive. There's no other way to implement `Clone`, but a
method like this could work (note the `&'a self`, which is incompatible with
`Clone`):

```
fn clone(&'a self) -> Self {}
```

Many types in this module don't derive `Clone`, but instead implement the above
method.

*/

#[macro_use]
extern crate num_derive;
#[macro_use]
extern crate log;
#[macro_use]
extern crate failure;

pub extern crate uuid;

mod appimage;
mod crypto;
mod error;
mod key;
pub mod marker;
mod utils;

pub use crate::appimage::{AppImage, AppInfo};
pub use crate::error::{Error, ErrorKind};
pub use crate::key::AesKey;

use crate::marker::private::*;
use crate::marker::*;
use crate::utils::{Blob, Crc32Writer};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use either::Either;
use num_traits::FromPrimitive;
use std::borrow::Cow;
use std::io;
use std::io::prelude::*;
use std::u32;

// TODO: Bootloader Tag, Metadata Tag.

/// Size limit of tags.
///
/// Since tags specify their length as a u32, not having a limit would allow
/// malicious files to allocate a lot of memory.
const TAG_SIZE_LIMIT: u32 = 10 * 1024 * 1024;

/// Limits the number of tags in a single GBL file during parsing.
///
/// Since GBLs can contain an arbitrary number of tags, we need an artificial
/// limit.
///
/// Maximum memory use when parsing an untrusted GBL thus is roughly
/// `TAG_COUNT_LIMIT * TAG_SIZE_LIMIT`, or 160 MiB.
const TAG_COUNT_LIMIT: u32 = 16;

/// In-memory representation of a GBL file.
///
/// # Typestate
///
/// This struct makes heavy use of typestate to track whether the GBL is
/// encrypted or contains an ECDSA signature: The `E` type parameter can be
/// any of [`Encrypted`], [`NotEncrypted`] or [`MaybeEncrypted`] to indicate
/// whether the program data in the GBL is encrypted, while `S` can be any of
/// [`Signed`], [`NotSigned`] or [`MaybeSigned`] to indicate the presence of a
/// signature.
///
/// Typestate is used to make misuse of the APIs in this crate as difficult as
/// possible. It rules out *many* possibly unwanted operations statically, such
/// as:
///
/// * Encrypting an already-encrypted GBL.
/// * Decrypting a GBL that is not encrypted.
/// * Signing a GBL that already has a signature.
/// * Adding a [`ProgramData`] section to an encrypted GBL (only encrypted
///   section are allowed there) or to a signed GBL (which would invalidate the
///   signature).
/// * Accessing the plain-text data sections using [`data_sections()`] on an
///   encrypted GBL.
///
/// Attempting to perform any of those operations will make the program fail
/// compilation. The only operations that perform runtime checking are the
/// `into_encrypted/signed` methods mentioned above.
///
/// The downside of such a typestate-based API is that it is rather cumbersome
/// and complex. However, correctness was deemed more important here (in fact,
/// we've already had internal API-misuse accidents that would've been prevented
/// by the typestate-based API).
///
/// ## Maybe
///
/// The `Maybe*` typestates indicate that there is no compile-time knowledge of
/// the state. They are present when parsing an external GBL file and provide
/// their information only at *runtime*.
///
/// On `Gbl` objects containing `Maybe*`, only a few general methods are
/// available. To get access to the methods that require more precise typestate,
/// [`into_encrypted`], [`into_not_encrypted`], [`into_signed`], or
/// [`into_not_signed`] can be called to effectively downcast from `MaybeX` to
/// `X` or `NotX`.
///
/// # Examples
///
/// A simple example that shows how to deal with `Maybe*` typestate:
///
/// ```
/// # use gbl::{Gbl, AppImage, AesKey};
/// # use failure::Error;
/// # fn run() -> Result<(), Error> {
/// use gbl::Gbl;
/// use gbl::marker::*;
///
/// // This GBL is neither signed nor encrypted
/// let raw_bytes: &[u8] = include_bytes!("../test-data/empty/empty.gbl");
///
/// let gbl: Gbl<MaybeEncrypted, MaybeSigned> = Gbl::parse(raw_bytes)?;
/// match gbl.into_not_encrypted() {
/// 	// `into_not_encrypted` returns a `Gbl<NotEncrypted, _>` in the success case
/// 	Ok(not_encrypted) => {
/// 		// Let's write out the type we get in the `Ok` branch:
/// 		let not_encrypted: Gbl<NotEncrypted, MaybeSigned> = not_encrypted;
///
/// 		// Getting a `NotEncrypted` GBL just made the `data_sections()` accessor available:
/// 		not_encrypted.data_sections();
///
/// 		// In almost all cases, you want to get rid of the `MaybeSigned` as well.
/// 		// Let's just unwrap that one to keep it simple:
/// 		let gbl: Gbl<NotEncrypted, NotSigned> = not_encrypted.into_not_signed().unwrap();
/// 		// (you can remove the `MaybeEncrypted` and `MaybeSigned` in any order)
///
/// 		// Now that we have a `Gbl<NotEncrypted, NotSigned>`, a lot of useful methods
/// 		// just became available: `push_data_section`, `encrypt`, `sign`, ...
///			// Refer to the API documentation for more details on methods and their availability.
/// 	}
/// 	Err(encrypted) => {
///			// The GBL *is* encrypted. We won't handle that case here and leave it as an
/// 		// exercise to the reader.
/// 		unimplemented!("GBL is encrypted");
/// 	}
/// }
/// # Ok(()) } run().unwrap();
/// ```
///
/// [`Encrypted`]: marker/struct.Encrypted.html
/// [`NotEncrypted`]: marker/struct.NotEncrypted.html
/// [`MaybeEncrypted`]: marker/struct.MaybeEncrypted.html
/// [`Signed`]: marker/struct.Signed.html
/// [`NotSigned`]: marker/struct.NotSigned.html
/// [`MaybeSigned`]: marker/struct.MaybeSigned.html
/// [`ProgramData`]: struct.ProgramData.html
/// [`into_encrypted`]: #method.into_encrypted
/// [`into_not_encrypted`]: #method.into_not_encrypted
/// [`into_signed`]: #method.into_signed
/// [`into_not_signed`]: #method.into_not_signed
/// [`data_sections()`]: #method.data_sections
#[derive(Debug)]
pub struct Gbl<E, S> {
    // We don't store the header because it only seems to contain 2 flags for
    // whether the GBL is encrypted or signed, which the type state already
    // expresses.
    enc: E,
    sig: S,
}

impl<'a> Gbl<MaybeEncrypted<'a>, MaybeSigned<'a>> {
    /// Parses a GBL file from raw bytes.
    ///
    /// The resulting `Gbl` will be `MaybeEncrypted` and `MaybeSigned`, because
    /// those states can't be statically determined when parsing an existing
    /// GBL. You can use [`into_encrypted`], [`into_signed`], etc. to downcast
    /// to a more specific typestate that has more methods available.
    ///
    /// Parsing is protected against malicious GBL files that specify very large
    /// sizes or contain an abnormal number of tags to cause a DoS via memory
    /// exhaustion. Note that this protection does not extend to the user code
    /// that reads the GBL file into memory.
    ///
    /// [`into_encrypted`]: #method.into_encrypted
    /// [`into_signed`]: #method.into_signed
    pub fn parse<T: AsRef<[u8]> + ?Sized>(bytes: &'a T) -> Result<Self, Error> {
        Self::parse_impl(bytes.as_ref())
    }

    fn parse_impl(mut bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() < 4 {
            return Err(Error::parse_err("GBL file too small to be valid"));
        }

        // We *always* have an END tag at the very end of the file, which means
        // that the checksum always ends up in the last 4 bytes of the file.
        // Cut it off and calculate the checksum in order to verify it.
        // It's the IEEE variant of CRC-32 (the most common one).
        let mut w = crc32fast::Hasher::new();
        w.update(&bytes[..bytes.len() - 4]);
        let checksum_computed = w.finalize();

        let reader = &mut bytes;

        let mut tag_count = 0;
        let mut header = None;
        let mut app_info = None;
        let mut sections = Vec::new(); // unencrypted program data sections
        let mut signature = None;
        let mut enc_header = None;
        let mut enc_sections = Vec::new(); // EncryptedProgramData sections
        let checksum;

        loop {
            tag_count += 1;
            if tag_count > TAG_COUNT_LIMIT {
                return Err(Error::parse_err(format!(
                    "exceeded the tag count limit of {} during \
                     parsing",
                    TAG_COUNT_LIMIT
                )));
            }

            match Tag::parse(reader)? {
                Tag::Header(hdr) => {
                    if header.is_some() {
                        return Err(Error::parse_err("duplicate header"));
                    }

                    header = Some(hdr);
                }
                Tag::End(c) => {
                    if reader.is_empty() {
                        // 0 bytes remaining in buffer
                        checksum = c;
                        break;
                    } else {
                        return Err(Error::parse_err("trailing data after end tag"));
                    }
                }
                Tag::EncryptionHeader(header) => {
                    if enc_header.is_some() {
                        return Err(Error::parse_err("duplicate encryption header"));
                    }

                    enc_header = Some(header);
                }
                Tag::Signature(sig) => {
                    if signature.is_some() {
                        return Err(Error::parse_err("duplicate signature"));
                    }

                    // The signature is computed over all preceding data.
                    // However, the signature tag is only valid just before the
                    // end tag, so we can just serialize `self` into the
                    // hasher/verifier.
                    signature = Some(sig);
                }
                Tag::AppInfo(info) => {
                    if app_info.is_some() {
                        return Err(Error::parse_err("duplicate appinfo section"));
                    }

                    app_info = Some(info);
                }
                Tag::ProgramData(data) => sections.push(data),
                Tag::EncryptedData(data) => enc_sections.push(Blob(data)),
            }
        }

        let header = header.ok_or_else(|| Error::parse_err("invalid GBL: no header found"))?;

        // Error on wrong checksum, except when we're fuzzing
        if checksum != checksum_computed && !cfg!(fuzzing) {
            return Err(Error::parse_err(format!(
                "invalid CRC checksum: got {:#010X}, expected {:#010X}",
                checksum, checksum_computed
            )));
        }

        // Sanity check header against actual contents
        if header.signed != signature.is_some() {
            return Err(Error::parse_err(format!(
                "header sign bit: {}; signature present: {}",
                header.signed,
                signature.is_some()
            )));
        }

        if header.encrypted != enc_header.is_some() {
            return Err(Error::parse_err(format!(
                "header encryption bit: {}; encryption header present: {}",
                header.encrypted,
                enc_header.is_some()
            )));
        }

        if header.encrypted && !sections.is_empty() {
            return Err(Error::parse_err(
                "unencrypted program data sections present, but header claims \
                 that encryption is used",
            ));
        }

        if !header.encrypted && !enc_sections.is_empty() {
            return Err(Error::parse_err(
                "encrypted program data sections present, but header claims \
                 that encryption isn't used",
            ));
        }

        if let Some(enc) = &enc_header {
            let actual_bytes = enc_sections.iter().map(|sec| sec.len()).sum();
            if enc.total_bytes as usize != actual_bytes {
                return Err(Error::parse_err(format!(
                    "encryption header specifies {} encrypted bytes, but total is {}",
                    enc.total_bytes, actual_bytes
                )));
            }
        }

        Ok(Gbl {
            enc: MaybeEncrypted {
                inner: if header.encrypted {
                    Either::Left(Encrypted {
                        enc_header: enc_header.unwrap(),
                        enc_sections,
                    })
                } else {
                    Either::Right(NotEncrypted {
                        app_info: app_info.unwrap(),
                        sections,
                    })
                },
            },
            sig: MaybeSigned {
                inner: if let Some(signature) = signature {
                    Either::Left(Signed { signature })
                } else {
                    Either::Right(NotSigned::new())
                },
            },
        })
    }
}

/// Methods that only work on non-encrypted and non-signed GBLs.
impl<'a> Gbl<NotEncrypted<'a>, NotSigned<'a>> {
    /// Creates a `Gbl` object from a raw application image.
    ///
    /// The resulting GBL file will contain the [`AppInfo`] from the given image
    /// as well as a single [`ProgramData`] section writing the raw image data
    /// to the device flash.
    ///
    /// [`AppInfo`]: struct.AppInfo.html
    /// [`ProgramData`]: struct.ProgramData.html
    pub fn from_app_image(image: AppImage<'a>) -> Self {
        Gbl {
            enc: NotEncrypted {
                app_info: *image.app_info(),
                sections: vec![ProgramData {
                    flash_addr: 0,
                    data: Blob(image.into_raw()),
                }],
            },
            sig: NotSigned::new(),
        }
    }

    /// Creates a new GBL file from an existing [`AppInfo`] structure and a
    /// [`ProgramData`] section.
    ///
    /// Additional program data sections can be added by calling
    /// [`push_data_section`].
    ///
    /// [`AppInfo`]: struct.AppInfo.html
    /// [`ProgramData`]: struct.ProgramData.html
    /// [`push_data_section`]: #method.push_data_section
    pub fn from_parts(app_info: AppInfo, data: ProgramData<'a>) -> Self {
        Self {
            enc: NotEncrypted {
                app_info,
                sections: vec![data],
            },
            sig: NotSigned::new(),
        }
    }

    /// Appends a [`ProgramData`] section to the data section list.
    ///
    /// It is the user's responsibility to ensure that no sections overlap (or
    /// reference invalid addresses).
    ///
    /// Also see [`data_sections`] for read-only access to all [`ProgramData`]
    /// sections.
    ///
    /// [`data_sections`]: #method.data_sections
    /// [`ProgramData`]: struct.ProgramData.html
    pub fn push_data_section(&mut self, section: ProgramData<'a>) {
        self.enc.sections.push(section);
    }

    /// Encrypts the content of this GBL file using an AES-128 key.
    ///
    /// This will generate a random 12-Byte nonce using the operating
    /// system's random number generator. The nonce will be used for encryption
    /// and decryption and is stored inside the encryption header inside the
    /// encrypted GBL.
    ///
    /// Note that the validity of the key cannot be checked: Passing an invalid
    /// key will result in encryption succeeding, but resulting in garbage data,
    /// which will then fail to parse properly.
    ///
    /// # Method availability
    ///
    /// This method is only available when `self` is `NotEncrypted` and
    /// `NotSigned`. It turns a `NotEncrypted` and `NotSigned` GBL into an
    /// `Encrypted` and `NotSigned` GBL.
    pub fn encrypt(self, key: AesKey) -> Gbl<Encrypted<'a>, NotSigned<'a>> {
        debug_assert!(!self.is_encrypted());

        let nonce = rand::random::<[u8; 12]>();
        // FIXME(perf): Optimize storage (`Vec<&[u8]>` with a shared backing store)
        let sec_count = self.enc.sections.len() + 1; // + 1 for AppData
        let mut sections: Vec<Vec<u8>> = Vec::with_capacity(sec_count);
        {
            let mut buf: Vec<u8> = Vec::new();
            Tag::AppInfo(self.enc.app_info)
                .write(&mut buf)
                .expect("failed to write to `Vec`");
            sections.push(buf);
        }
        for sec in &self.enc.sections {
            let mut buf: Vec<u8> = Vec::new();
            Tag::ProgramData(sec.clone())
                .write(&mut buf)
                .expect("failed to write to `Vec`");
            sections.push(buf);
        }

        let encrypted = crypto::crypt(key, nonce, &sections);
        info!("parsing {} sections", encrypted.len());

        let mut total_bytes: u32 = 0;
        let mut enc_sections = Vec::new();
        for sec in encrypted {
            total_bytes += sec.len() as u32;
            enc_sections.push(Blob(Cow::from(sec)));
        }

        Gbl {
            enc: Encrypted {
                enc_header: EncryptionHeader {
                    total_bytes,
                    nonce: Blob(nonce),
                },
                enc_sections,
            },
            sig: self.sig,
        }
    }
}

/// `MaybeEncrypted` -> `(Not)Encrypted` downcasting methods.
impl<'a, S> Gbl<MaybeEncrypted<'a>, S>
where
    S: SignatureState<'a>,
{
    /// If `self` is encrypted, downcasts it to a `Gbl<Encrypted, _>`.
    ///
    /// Otherwise, downcasts `self` to a `Gbl<NotEncrypted, _>`. This means that
    /// the `Maybe*` gets stripped in either case.
    pub fn into_encrypted(self) -> Result<Gbl<Encrypted<'a>, S>, Gbl<NotEncrypted<'a>, S>> {
        match self.enc.inner {
            Either::Left(enc) => Ok(Gbl { enc, sig: self.sig }),
            Either::Right(not_enc) => Err(Gbl {
                enc: not_enc,
                sig: self.sig,
            }),
        }
    }

    /// If `self` is not encrypted, downcasts it to a `Gbl<NotEncrypted, _>`.
    ///
    /// Otherwise, downcasts `self` to a `Gbl<Encrypted, _>`. This means that the
    /// `Maybe*` gets stripped in either case.
    pub fn into_not_encrypted(self) -> Result<Gbl<NotEncrypted<'a>, S>, Gbl<Encrypted<'a>, S>> {
        match self.enc.inner {
            Either::Left(enc) => Err(Gbl { enc, sig: self.sig }),
            Either::Right(not_enc) => Ok(Gbl {
                enc: not_enc,
                sig: self.sig,
            }),
        }
    }
}

/// `MaybeSigned` -> `(Not)Signed` downcasting methods.
impl<'a, E> Gbl<E, MaybeSigned<'a>>
where
    E: EncryptionState<'a>,
{
    /// If `self` is signed, downcasts it to a `Gbl<_, Signed>`.
    ///
    /// Otherwise, downcasts `self` to a `Gbl<_, NotSigned>`.
    pub fn into_signed(self) -> Result<Gbl<E, Signed<'a>>, Gbl<E, NotSigned<'a>>> {
        match self.sig.inner {
            Either::Left(signed) => Ok(Gbl {
                enc: self.enc,
                sig: signed,
            }),
            Either::Right(not_signed) => Err(Gbl {
                enc: self.enc,
                sig: not_signed,
            }),
        }
    }

    /// If `self` is not signed, downcasts it to a `Gbl<_, NotSigned>`.
    ///
    /// Otherwise (if `self` *is* signed), downcasts `self` to a
    /// `Gbl<_, Signed>`.
    pub fn into_not_signed(self) -> Result<Gbl<E, NotSigned<'a>>, Gbl<E, Signed<'a>>> {
        match self.sig.inner {
            Either::Left(signed) => Err(Gbl {
                enc: self.enc,
                sig: signed,
            }),
            Either::Right(not_signed) => Ok(Gbl {
                enc: self.enc,
                sig: not_signed,
            }),
        }
    }
}

/// Methods available only on non-encrypted GBLs. Signature may or may not be
/// present.
impl<'a, S> Gbl<NotEncrypted<'a>, S>
where
    S: SignatureState<'a>,
{
    /// Returns the data sections to be programmed to the device's flash memory.
    ///
    /// This method is only available if `self` is `NotEncrypted`, because an
    /// encrypted GBL does not allow reading the data sections.
    ///
    /// Also see [`push_data_section`].
    ///
    /// [`push_data_section`]: #method.push_data_section
    pub fn data_sections(&self) -> &[ProgramData<'a>] {
        &self.enc.sections
    }
}

impl<'a, E> Gbl<E, Signed<'a>>
where
    E: EncryptionState<'a>,
{
    /// Attempts to verify the ECDSA signature attached to the GBL.
    ///
    /// If the signature was not created by the private key belonging to
    /// `pem_pubkey`, the signature was probably forged and an error will be
    /// returned. An error will also be returned if the public key is malformed
    /// or otherwise invalid.
    ///
    /// If the GBL is encrypted, the signature is computed over the encrypted
    /// data. Consequently, decrypting the GBL disposes of the signature. Check
    /// the signature before decrypting!
    ///
    /// # Parameters
    ///
    /// * `pem_pubkey`: The public key in PEM ASCII format
    ///   (`-----BEGIN PUBLIC KEY-----` etc.).
    pub fn verify_signature(&self, pem_pubkey: &str) -> Result<(), Error> {
        let signature = &self.sig.signature;
        let mut signed_data = Vec::new();
        self.write_data_to_sign(&mut signed_data)
            .expect("writing into `Vec` failed");

        // *chants* GIVE US CONST GENERICS NOW!
        let mut raw_signature = [0; 64];
        raw_signature.copy_from_slice(&signature.raw);
        crypto::verify_signature(pem_pubkey, &raw_signature, &signed_data)
    }

    /// Strips the signature from `self` without verifying it.
    ///
    /// This converts a `Signed` GBL into a `NotSigned` one, enabling methods
    /// that require the GBL to have no signature (such as [`push_data_section`]
    /// and [`encrypt`]).
    ///
    /// [`push_data_section`]: #method.push_data_section
    /// [`encrypt`]: #method.encrypt
    pub fn remove_signature(self) -> Gbl<E, NotSigned<'a>> {
        Gbl {
            enc: self.enc,
            sig: NotSigned::new(),
        }
    }
}

impl<'a, E> Gbl<E, NotSigned<'a>>
where
    E: EncryptionState<'a>,
{
    /// Creates and appends a digital signature for `self` using a private EC
    /// key.
    ///
    /// Returns the signed GBL.
    ///
    /// Note that the signature created by this method is attached to the
    /// *GBL container*, not the contained application image. In other words,
    /// this signature can **not** be checked by the bootloader during secure
    /// boot. If you want to use secure boot, you need to sign the *application
    /// image* itself by using [`AppImage::sign`]. Also be aware that flashing
    /// an application image with an invalid signature will prevent the device
    /// from rebooting back into it, so you likely want to have *both* a signed
    /// application image *and* a signed GBL container you can check *before*
    /// flashing.
    ///
    /// # Parameters
    ///
    /// * `pem_private_key`: The unencrypted private key in PEM ASCII format
    ///   (`-----BEGIN EC PRIVATE KEY-----` etc.).
    ///
    /// [`AppImage::sign`]: struct.AppImage.html#method.sign
    pub fn sign(self, pem_private_key: &str) -> Result<Gbl<E, Signed<'a>>, Error> {
        // Obtain the blob we want to sign
        let mut sign_data = Vec::with_capacity(1024); // save the first few likely resizes
        self.write_data_to_sign(&mut sign_data)
            .expect("writing into `Vec` failed");

        let sig = crypto::create_signature(pem_private_key, &sign_data)?;

        // Now just attach the signature and we're done.
        Ok(Gbl {
            enc: self.enc,
            sig: Signed {
                signature: Signature {
                    raw: Blob(sig.to_vec().into()),
                },
            },
        })
    }
}

impl<'a> Gbl<Encrypted<'a>, NotSigned<'a>> {
    /// Decrypts the content of this GBL file using a raw AES-128 key.
    ///
    /// The decrypted data will be parsed into GBL tags and returned as a new
    /// `Gbl` object based on `self`.
    ///
    /// Note that the validity of the key cannot be checked: Passing an invalid
    /// key will result in decryption succeeding, but results in garbage data,
    /// which will then fail to parse properly.
    pub fn decrypt(self, key: AesKey) -> Result<Gbl<NotEncrypted<'a>, NotSigned<'a>>, Error> {
        let enc_header = &self.enc.enc_header;
        let nonce = enc_header.nonce.0;

        let decrypted = crypto::crypt(key, nonce, &self.enc.enc_sections);
        info!("parsing {} decrypted sections", decrypted.len());

        // Preallocate section storage. 1 encrypted section is the AppData, so subtract 1.
        let mut sections = Vec::with_capacity(self.enc.enc_sections.len() - 1);
        let mut appinfo = None;

        for section in decrypted {
            let section = Blob(section);
            debug!("decrypted data: {:?}", section);

            let reader: &mut &[u8] = &mut &*section;
            let tag = Tag::parse(reader)?;
            if !reader.is_empty() {
                return Err(Error::parse_err(format!(
                    "trailing bytes in encrypted section of {} bytes",
                    section.len()
                )));
            }

            match tag {
                Tag::AppInfo(info) => {
                    if appinfo.is_some() {
                        return Err(Error::parse_err("duplicate appinfo section"));
                    }

                    appinfo = Some(info);
                }
                Tag::ProgramData(data) => sections.push(data.into_owned()),
                _ => {
                    return Err(Error::parse_err(format!(
                        "decrypted tag {:?} is invalid in an encrypted section",
                        tag.tag_id()
                    )));
                }
            }
        }

        Ok(Gbl {
            enc: NotEncrypted {
                app_info: appinfo.unwrap(),
                sections,
            },
            sig: NotSigned::new(),
        })
    }
}

/// General methods that work on GBLs regardless of encryption/signing state.
impl<'a, E, S> Gbl<E, S>
where
    E: EncryptionState<'a>,
    S: SignatureState<'a>,
{
    /// Takes ownership of any borrowed data in `self`.
    ///
    /// This will heap-allocate owned storage for all data in `self` and copy
    /// the data there.
    pub fn into_owned(self) -> Gbl<E::StaticSelf, S::StaticSelf> {
        // This could reuse all `Vec`s, since only lifetimes change, not the
        // sizes of types/vectors, but that'd need something like ye olde
        // `Vec::map_in_place`.
        Gbl {
            enc: self.enc.into_owned(),
            sig: self.sig.into_owned(),
        }
    }

    /// A cheap-ish, lifetime-restricted version of `Clone`.
    ///
    /// The returned object will share as much data as possible with `self`, but
    /// cannot outlive it. You can call `.into_owned()` on the returned object
    /// to make it own all of its data.
    pub fn clone(&'a self) -> Self {
        Self {
            enc: self.enc.clone(),
            sig: self.sig.clone(),
        }
    }

    /// Converts the GBL file to its binary representation.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.write(&mut buf).expect("writing into `Vec<u8>` failed");
        buf
    }

    /// Serializes the binary representation of this GBL into a writer.
    pub fn write<W: Write>(&self, writer: W) -> io::Result<()> {
        // Before writing anything, wrap the writer so we can calculate CRC32
        // on the fly.
        let mut writer = Crc32Writer::new(writer);

        // Serialize all normal tags (excluding the end tag)
        self.to_tags(|tag| tag.write(&mut writer))?;

        // Writing the final checksum is a bit annoying since its tag ID and
        // length are part of the checksum.
        writer.write_u32::<LittleEndian>(TagId::End as u32)?;
        writer.write_u32::<LittleEndian>(4)?; // 4 byte CRC32 checksum
        let crc = writer.digest.finalize();
        writer.inner.write_u32::<LittleEndian>(crc)?;

        Ok(())
    }

    /// Serialize this GBL to a sequence of tags (excluding the end tag) and
    /// pass each tag to a closure.
    fn to_tags<F, Er>(&self, mut f: F) -> Result<(), Er>
    where
        F: FnMut(&Tag) -> Result<(), Er>,
    {
        f(&Tag::Header(Header {
            signed: self.is_signed(),
            encrypted: self.is_encrypted(),
        }))?;

        // Write data tags, encrypted or non-encrypted
        match self.enc.as_either_ref() {
            Either::Left(enc) => {
                f(&Tag::EncryptionHeader(enc.enc_header))?;
                for section in &enc.enc_sections {
                    f(&Tag::EncryptedData(Cow::Borrowed(&section.0)))?;
                }
            }
            Either::Right(not_enc) => {
                f(&Tag::AppInfo(not_enc.app_info))?;
                // TODO: Bootloader
                for programdata in &not_enc.sections {
                    f(&Tag::ProgramData(programdata.clone()))?;
                }
            }
        }

        if let Either::Left(sig) = self.sig.as_either_ref() {
            f(&Tag::Signature(sig.signature.clone()))?;
        }

        Ok(())
    }

    /// Returns whether `self` contains a digital signature.
    ///
    /// Call `verify_signature` to check if the signature belongs to a known key
    /// pair.
    pub fn is_signed(&self) -> bool {
        self.sig.as_either_ref().is_left()
    }

    /// Returns whether `self` contains encrypted program data.
    ///
    /// If this is the case, you must call `decrypt` to get access to the
    /// contained data.
    pub fn is_encrypted(&self) -> bool {
        self.enc.as_either_ref().is_left()
    }

    /// Writes the bytes that make up the signature to a writer.
    fn write_data_to_sign<W: Write>(&self, mut w: W) -> io::Result<()> {
        self.to_tags(|tag| match tag {
            Tag::Header(h) => Tag::Header(Header {
                signed: true,
                encrypted: h.encrypted,
            })
            .write(&mut w), // force the `signed` flag to `true`
            Tag::Signature(_) => Ok(()), // signature doesnt't sign itself
            other => other.write(&mut w),
        })
    }
}

enum Tag<'a> {
    Header(Header),
    AppInfo(AppInfo),
    //Bootloader, // TODO
    ProgramData(ProgramData<'a>),
    //Metadata(Vec<u8>),  // TODO
    Signature(Signature<'a>),
    End(u32),

    EncryptionHeader(EncryptionHeader),
    EncryptedData(Cow<'a, [u8]>),
}

impl<'a> Tag<'a> {
    /// Parses a tag from `reader`, adjusting it to point after the tag.
    fn parse(reader: &mut &'a [u8]) -> Result<Self, Error> {
        let tag_id = reader.read_u32::<LittleEndian>()?;
        let tag_len = reader.read_u32::<LittleEndian>()?;

        if tag_len > TAG_SIZE_LIMIT {
            return Err(Error::parse_err(format!(
                "tag {:04X} exceeds size limit of {} bytes (length = {} bytes)",
                tag_id, TAG_SIZE_LIMIT, tag_len
            )));
        }

        // zero-copy-read the tag contents and move `reader` to point after that
        let mut tag_buf = reader.get(..tag_len as usize).ok_or_else(|| {
            Error::parse_err(format!("tag length {} exceeds total file length", tag_len))
        })?;
        *reader = &reader[tag_len as usize..];

        let tag_id = TagId::from_u32(tag_id)
            .ok_or_else(|| Error::parse_err(format!("invalid GBL tag {:010X}", tag_id)))?;
        debug!("tag {:?}, {} bytes", tag_id, tag_len);
        match tag_id {
            TagId::Header => Ok(Tag::Header(Header::parse(&tag_buf)?)),
            TagId::End => {
                // end tag contains CRC32 checksum
                if tag_len != 4 {
                    return Err(Error::parse_err(format!(
                        "invalid end tag length: expected 4 bytes, got {}",
                        tag_len
                    )));
                }

                let checksum = tag_buf.read_u32::<LittleEndian>()?;
                info!("checksum: {:#010X}", checksum);
                Ok(Tag::End(checksum))
            }
            TagId::AppInfo => {
                debug!("raw appinfo: {:?}", Blob(tag_buf));

                Ok(Tag::AppInfo(AppInfo::parse(&tag_buf)?))
            }
            TagId::EncryptionInitHeader => {
                debug!("raw encryption header: {:?}", Blob(tag_buf));
                // According to the PDF, this contains the used nonce and
                // the total amount of encrypted data.
                // Encryption is done using AES-CTR-128.

                if tag_len != 4 + 12 {
                    // 4 byte length, 12 byte IV
                    return Err(Error::parse_err(format!(
                        "unexpected length of encryption init header: got {}, expected 16",
                        tag_len
                    )));
                }

                // Total number of encrypted bytes (summation of the lengths
                // of all EncryptedProgramData tags).
                let total_enc_bytes = tag_buf.read_u32::<LittleEndian>()?;

                // The rest should be exactly 12 Bytes, which (96 bits) is the
                // nonce used for the IV (see `aes::build_iv`).
                let mut nonce = [0; 12];
                tag_buf.read_exact(&mut nonce)?;

                let parsed = EncryptionHeader {
                    total_bytes: total_enc_bytes,
                    nonce: nonce.into(),
                };
                debug!("encryption header: {:?}", parsed);
                Ok(Tag::EncryptionHeader(parsed))
            }
            TagId::ProgramData | TagId::ProgramData2 => {
                let data = if tag_len > 64 {
                    &tag_buf[..64]
                } else {
                    &tag_buf
                };
                debug!("raw program data: {:?}", Blob(data));

                // The raw data to be programmed is prefixed by its offset
                // into flash memory.
                let flash_addr = tag_buf.read_u32::<LittleEndian>()?;
                Ok(Tag::ProgramData(ProgramData {
                    flash_addr,
                    data: Blob(tag_buf.into()),
                }))
            }
            TagId::EncryptedProgramData => Ok(Tag::EncryptedData(tag_buf.into())),
            TagId::Signature => {
                debug!("raw signature: {:?}", Blob(tag_buf));

                if tag_len != 64 {
                    return Err(Error::parse_err(format!(
                        "signature is {} Bytes, expected 64",
                        tag_len
                    )));
                }

                Ok(Tag::Signature(Signature {
                    raw: Blob(tag_buf.into()),
                }))
            }
            TagId::Bootloader | TagId::Metadata => {
                if cfg!(fuzzing) {
                    // When fuzzing, we don't want to panic
                    Err(Error::parse_err("NYI: bootloader/metadata tag"))
                } else {
                    unimplemented!()
                }
            }
        }
    }

    fn tag_id(&self) -> TagId {
        match self {
            Tag::Header(_) => TagId::Header,
            Tag::AppInfo(_) => TagId::AppInfo,
            Tag::ProgramData(_) => TagId::ProgramData2,
            Tag::Signature(_) => TagId::Signature,
            Tag::End(_) => TagId::End,
            Tag::EncryptionHeader(_) => TagId::EncryptionInitHeader,
            Tag::EncryptedData(_) => TagId::EncryptedProgramData,
        }
    }

    /// Writes this tag, along with tag ID and length, into a GBL file stream.
    fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        let mut buf = Vec::new();
        self.write_raw(&mut buf)
            .expect("writing into a Vec<u8> failed");

        writer.write_u32::<LittleEndian>(self.tag_id() as u32)?;
        writer.write_u32::<LittleEndian>(buf.len() as u32)?;
        writer.write_all(&buf)?;
        Ok(())
    }

    /// Writes this tag into a writer, without its tag ID and length.
    fn write_raw<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        match self {
            Tag::Header(hdr) => {
                writer.write_u32::<LittleEndian>(0x03000000)?;
                writer.write_u8(if hdr.encrypted { 1 } else { 0 })?;
                writer.write_u8(if hdr.signed { 1 } else { 0 })?;
                writer.write_u8(0)?;
                writer.write_u8(0)?;
            }
            Tag::AppInfo(appinfo) => {
                appinfo.write(writer)?;
            }
            Tag::ProgramData(data) => {
                writer.write_u32::<LittleEndian>(data.flash_addr)?;
                writer.write_all(&data.data)?;
            }
            Tag::Signature(sig) => {
                writer.write_all(&sig.raw)?;
            }
            Tag::End(crc) => {
                writer.write_u32::<LittleEndian>(*crc)?;
            }
            Tag::EncryptionHeader(hdr) => {
                writer.write_u32::<LittleEndian>(hdr.total_bytes)?;
                writer.write_all(&hdr.nonce)?;
            }
            Tag::EncryptedData(data) => {
                writer.write_all(data)?;
            }
        }

        Ok(())
    }
}

#[derive(FromPrimitive, Debug)]
#[repr(u32)]
enum TagId {
    Header = 0x03A617EB,
    AppInfo = 0xF40A0AF4,
    Bootloader = 0xF50909F5,
    ProgramData = 0xFE0101FE,
    ProgramData2 = 0xFD0303FD, // alternate Tag ID for program data
    Metadata = 0xF60808F6,
    Signature = 0xF70A0AF7,
    End = 0xFC0404FC,

    EncryptionInitHeader = 0xFA0606FA,
    EncryptedProgramData = 0xF90707F9,
}

#[derive(Debug, Copy, Clone)]
struct Header {
    signed: bool,
    encrypted: bool,
}

impl Header {
    fn parse(mut bytes: &[u8]) -> Result<Self, Error> {
        debug!("raw header: {:?}", bytes);

        if bytes.len() != 8 {
            return Err(Error::parse_err(format!(
                "got {} header bytes, expected 8",
                bytes.len()
            )));
        }

        // The first 4 bytes of the header tag are apparently always "0 0 0 3"
        let mut fixed = [0u8; 4];
        bytes.read_exact(&mut fixed)?;
        if fixed != [0, 0, 0, 3] {
            return Err(Error::parse_err(format!(
                "invalid or unknown header format: {:?}",
                fixed
            )));
        }

        // The next 4 bytes contain flags
        // First byte:  1=encrypted, 0=unencrypted
        // Second byte: 1=signed,    0=not signed
        // Rest: Unknown (always 0)
        let encrypted = match bytes.read_u8()? {
            0 => false,
            1 => true,
            invalid => {
                return Err(Error::parse_err(format!(
                    "invalid value for encryption byte: {:#04X} (expected 0 or 1)",
                    invalid
                )));
            }
        };

        let signed = match bytes.read_u8()? {
            0 => false,
            1 => true,
            invalid => {
                return Err(Error::parse_err(format!(
                    "invalid value for sign byte: {:#04X} (expected 0 or 1)",
                    invalid
                )));
            }
        };

        let zero = bytes.read_u16::<LittleEndian>()?;
        if zero != 0 {
            return Err(Error::parse_err(format!(
                "invalid trailing word in header (expected 0, got {:#06X})",
                zero
            )));
        }

        Ok(Header { signed, encrypted })
    }
}

/// A chunk of program data to be programmed to a specified flash address.
#[derive(Debug)]
pub struct ProgramData<'a> {
    // FIXME: On EFR32xG1 devices, the first part of flash is the bootloader.
    // Does that mean this can overwrite it?
    flash_addr: u32,
    data: Blob<Cow<'a, [u8]>>,
}

impl<'a> ProgramData<'a> {
    /// Creates a new `ProgramData` section for flashing `data` at `addr`.
    ///
    /// It is the users responsibility to ensure that no `ProgramData` section
    /// writes out of bounds of flash memory.
    pub fn new<D>(addr: u32, data: D) -> Self
    where
        D: Into<Cow<'a, [u8]>>,
    {
        Self {
            flash_addr: addr,
            data: Blob(data.into()),
        }
    }

    /// Returns the target address in the device flash.
    pub fn start_addr(&self) -> u32 {
        self.flash_addr
    }

    /// Returns the bytes to be written.
    pub fn bytes(&self) -> &[u8] {
        &self.data
    }

    /// Converts `self` into another `ProgramData` instance that fully owns its
    /// contents.
    ///
    /// This does basically the same operation as `clone`, but the resulting
    /// type reflects that fact in its `'static` lifetime.
    fn into_owned(self) -> ProgramData<'static> {
        ProgramData {
            flash_addr: self.flash_addr,
            data: Blob(self.data.0.into_owned().into()),
        }
    }

    /// Cheaply creates another `ProgramData` struct borrowing the data from
    /// `self`.
    ///
    /// This can be used as a cheap `clone` replacement when the lifetime of the
    /// result may be shorter than that of `self`.
    fn clone(&'a self) -> Self {
        ProgramData {
            flash_addr: self.flash_addr,
            data: Blob(Cow::Borrowed(&self.data.0)),
        }
    }
}

impl<'a> From<AppImage<'a>> for ProgramData<'a> {
    fn from(image: AppImage<'a>) -> Self {
        Self {
            flash_addr: 0,
            data: Blob(image.into_raw()),
        }
    }
}

/// An ECDSA-P256 signature.
///
/// The signature is computed over all preceding data in the file. It uses
/// ECDSA-P256. The P-256 curve is the same as the `secp256r1` curve, which in
/// turn is called `prime256v1` by OpenSSL.
#[derive(Debug)]
struct Signature<'a> {
    /// Raw signature blob. Always contains 64 Bytes.
    raw: Blob<Cow<'a, [u8]>>, // WE (probably still) WANT CONST GENERICS!
}

impl<'a> Signature<'a> {
    fn into_owned(self) -> Signature<'static> {
        Signature {
            raw: Blob(self.raw.0.into_owned().into()),
        }
    }

    fn clone(&'a self) -> Self {
        Signature {
            raw: Blob(Cow::Borrowed(&self.raw.0)),
        }
    }
}

/// Contains initialization info for encrypted blocks.
#[derive(Debug, Copy, Clone)]
struct EncryptionHeader {
    /// Total number of encrypted bytes.
    ///
    /// This is the sum of the lengths of all `EncryptedProgramData` blocks.
    total_bytes: u32,

    /// The nonce for the IV of the AES-CTR-128 encryption.
    nonce: Blob<[u8; 12]>,
}
