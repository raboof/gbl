//! Application image manipulation.
//!
//! This isn't technically part of the GBL container format, but can be very
//! useful nonetheless.

use crate::crypto;
use crate::error::Error;
use crate::utils::Blob;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use num_traits::FromPrimitive;
use std::borrow::Cow;
use std::io::{self, Write};
use std::u32;
use uuid::Uuid;

/// An application info structure.
///
/// This structure is generally ignored by the bootloader and can be used to
/// implement custom checks. For example, the `version` field can be used to
/// encode the firmware revision and prevent firmware downgrades.
///
/// Can be passed to [`Gbl::from_parts`] to create a fully custom GBL container.
///
/// [`Gbl::from_parts`]: struct.Gbl.html#method.from_parts
#[derive(Debug, Copy, Clone)]
pub struct AppInfo {
    /// Application type. Bitfield.
    type_: u32,
    /// Application version.
    version: u32,
    capabilities: u32,
    product_id: Uuid,
}

impl AppInfo {
    /// The length of the `AppInfo` structure in a raw byte stream.
    const LENGTH: usize = 28;

    /// Parse `AppInfo` from the contents of a corresponding GBL tag.
    pub(crate) fn parse(mut bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 28 {
            return Err(Error::parse_err(format!(
                "invalid length for app info: {} bytes (expected 28)",
                bytes.len()
            )));
        }

        let type_ = bytes.read_u32::<LittleEndian>()?;
        let version = bytes.read_u32::<LittleEndian>()?;
        let capabilities = bytes.read_u32::<LittleEndian>()?;
        let mut product_id = [0; 16];
        product_id.copy_from_slice(bytes);

        Ok(Self {
            type_,
            version,
            capabilities,
            product_id: Uuid::from_bytes(product_id),
        })
    }

    pub(crate) fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_u32::<LittleEndian>(self.type_)?;
        w.write_u32::<LittleEndian>(self.version)?;
        w.write_u32::<LittleEndian>(self.capabilities)?;
        w.write_all(self.product_id.as_bytes())?;
        Ok(())
    }

    /// Creates a new application info section from its raw components.
    ///
    /// Note that these values are basically ignored by the bootloader, but can
    /// be used by the application before initiating a firmware upgrade.
    ///
    /// # Parameters
    ///
    /// * `type_`: Type of the application (might be a bitfield).
    /// * `version`: App version (can be used to prevent firmware downgrades).
    /// * `capabilities`: Capability bitfield (can be used for anything).
    /// * `product_id`: A UUID identifying the application.
    pub fn new(type_: u32, version: u32, capabilities: u32, product_id: Uuid) -> Self {
        Self {
            type_,
            version,
            capabilities,
            product_id,
        }
    }

    /// Returns the application type field.
    pub fn type_(&self) -> u32 {
        self.type_
    }

    /// Returns the app version field.
    pub fn version(&self) -> u32 {
        self.version
    }

    /// Returns the capabilities field.
    pub fn capabilities(&self) -> u32 {
        self.capabilities
    }

    /// Returns the product ID field.
    pub fn product_id(&self) -> Uuid {
        self.product_id
    }
}

#[derive(FromPrimitive, Debug, Copy, Clone)]
enum SignatureType {
    None = 0,
    EcdsaP256 = 1,
    Crc32 = 2,
}

/// Application property structure.
///
/// This must be present in an application binary and is located using its
/// 16-Byte magic number. The bootloader uses this structure to find and verify
/// the app signature during secure boot.
#[derive(Debug)]
pub struct AppProperties {
    /// Position of the `AppProperties` struct itself (starting at the magic
    /// bytes).
    position: u32,

    version: u32,
    signature_type: SignatureType,
    signature_location: u32,
    app_info: AppInfo,
}

impl AppProperties {
    const MAGIC: &'static [u8; 16] = &[
        0x13, 0xB7, 0x79, 0xFA, 0xC9, 0x25, 0xDD, 0xB7, 0xAD, 0xF3, 0xCF, 0xE0, 0xF1, 0xB6, 0x14,
        0xB8,
    ];

    /// Number of bytes occupied by the app properties in the image.
    const LENGTH: usize = 16 /* magic */ + 3 * 4 /* version, sig type/loc */ + AppInfo::LENGTH;

    /// Supported version.
    const VERSION: u32 = 0x00000100;

    const MAX_RAW_LEN: u32 = 0x80000000;

    /// Extracts the application property structure from a raw app image.
    pub(crate) fn extract(image: &[u8]) -> Result<Self, Error> {
        let complete_image = image;
        if image.len() > Self::MAX_RAW_LEN as usize {
            return Err(Error::parse_err(format!(
				"could not get application properties from binary image (image larger than limit of {} bytes)",
				Self::MAX_RAW_LEN
			)));
        }

        if let Some(pos) = image
            .windows(Self::MAGIC.len())
            .position(|win| win == Self::MAGIC)
        {
            if image.len() < pos + Self::LENGTH {
                return Err(Error::parse_err(
                    "could not get application properties from binary image (image too small)",
                ));
            }

            info!(
                "app properties at {:#X}: {:?}",
                pos,
                Blob(&image[pos..pos + Self::LENGTH])
            );

            let mut image = &image[pos + Self::MAGIC.len()..];
            let version = image.read_u32::<LittleEndian>()?;
            if version > Self::VERSION {
                return Err(Error::parse_err(format!(
                    "unsupported app property struct version {:#010X} (expected {:#010X})",
                    version,
                    Self::VERSION
                )));
            }

            let signature_type = image.read_u32::<LittleEndian>()?;
            let signature_location = image.read_u32::<LittleEndian>()?;
            let app_info = AppInfo::parse(&image[..AppInfo::LENGTH])?;

            let signature_type = SignatureType::from_u32(signature_type).ok_or_else(|| {
                Error::parse_err(format!(
                    "invalid signature type {} in app properties",
                    signature_type,
                ))
            })?;
            let signature_len = match signature_type {
                SignatureType::None => 0,
                SignatureType::Crc32 => {
                    // FIXME
                    return Err(Error::parse_err(r#"CRC-32 "signatures" not yet supported"#));
                }
                SignatureType::EcdsaP256 => 64,
            };
            if signature_location != 0 {
                if signature_location as usize + signature_len > complete_image.len() {
                    return Err(Error::parse_err(format!(
						"invalid signature location {:#010X} (length is {} bytes, image length is {:#010X})",
						signature_location,
						signature_len,
						complete_image.len(),
					)));
                }

                if let SignatureType::None = signature_type {
                    return Err(Error::parse_err(format!(
                        "non-zero signature location {:#010X} but signature type 'None'",
                        signature_location,
                    )));
                }
            }

            let this = Self {
                position: pos as u32,
                version,
                signature_type,
                signature_location,
                app_info,
            };
            debug!("parsed app properties: {:?}", this);
            Ok(this)
        } else {
            Err(Error::parse_err(
                "could not find application info in binary image",
            ))
        }
    }

    /// Writes the app properties, including the magic string, to `w`.
    fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(Self::MAGIC)?;
        w.write_u32::<LittleEndian>(self.version)?;
        w.write_u32::<LittleEndian>(self.signature_type as u32)?;
        w.write_u32::<LittleEndian>(self.signature_location)?;
        self.app_info.write(w)?;
        Ok(())
    }

    pub(crate) fn app_info(&self) -> &AppInfo {
        &self.app_info
    }
}

/// A flash image containing application data.
///
/// It is expected that every application embeds an "application properties"
/// data structure, which will be located by [`AppImage::parse`] and contains an
/// [`AppInfo`] structure which can be accessed using [`AppImage::app_info`].
///
/// Can be turned into a [`Gbl`] by calling [`Gbl::from_app_image`] or into a
/// [`ProgramData`] section using `From`/`Into` conversion. The resulting
/// section will be flashed at offset 0. It is the user's responsibility to
/// ensure that the whole image fits in the target device's flash memory
/// (this library is completely device-agnostic and thus cannot check that
/// device-specific constraints are satisfied).
///
/// [`Gbl`]: struct.Gbl.html
/// [`Gbl::from_app_image`]: struct.Gbl.html#method.from_app_image
/// [`AppImage::parse`]: #method.parse
/// [`AppInfo`]: struct.AppInfo.html
/// [`AppImage::app_info`]: #method.app_info
/// [`ProgramData`]: struct.ProgramData.html
#[derive(Debug)]
pub struct AppImage<'a> {
    raw: Blob<Cow<'a, [u8]>>,
    app_props_pos: u32,
    app_props: AppProperties,
}

impl<'a> AppImage<'a> {
    /// Parses a raw application image by extracting the application properties.
    ///
    /// # Errors
    ///
    /// Returns an error if `image` does not contain a valid application
    /// properties structure.
    pub fn parse<T: AsRef<[u8]> + ?Sized>(image: &'a T) -> Result<Self, Error> {
        let image = image.as_ref();
        let props = AppProperties::extract(image)?;
        Ok(Self {
            raw: Blob(image.into()),
            app_props_pos: props.position,
            app_props: props,
        })
    }

    /// Consumes `self` and returns the raw bytes making up the application
    /// image.
    pub fn into_raw(self) -> Cow<'a, [u8]> {
        self.raw.0
    }

    /// Returns the [`AppInfo`] structure extracted from the application image.
    ///
    /// [`AppInfo`]: struct.AppInfo.html
    pub fn app_info(&self) -> &AppInfo {
        &self.app_props.app_info()
    }

    /// Returns whether a cryptographic signature is embedded into the
    /// application image.
    pub fn is_signed(&self) -> bool {
        match (
            self.app_props.signature_location,
            &self.app_props.signature_type,
        ) {
            (0, _) => false,
            (_, SignatureType::EcdsaP256) => true,
            _ => false,
        }
    }

    /// If present, returns the embedded ECDSA P-256 signature blob.
    pub fn ecdsa_signature(&self) -> Option<[u8; 64]> {
        match (
            self.app_props.signature_location,
            &self.app_props.signature_type,
        ) {
            (0, _) => None,
            (pos, SignatureType::EcdsaP256) => {
                let mut signature = [0; 64];
                signature.copy_from_slice(&self.raw[pos as usize..pos as usize + 64]);
                Some(signature)
            }
            _ => None,
        }
    }

    /// Signs this application image.
    ///
    /// The signature will be embedded into the flashed data, and the
    /// application properties structure will be updated to point at the
    /// signature. If the signature pointer is non-zero and the signature type
    /// indicates an ECDSA P-256 signature, an existing signature is assumed to
    /// be present at that offset and will be overwritten with a new signature.
    ///
    /// If no signature is present, this will append the new signature to the
    /// raw image, enlarging it.
    ///
    /// If secure boot is enabled in the bootloader, a valid signature must be
    /// present for boot to continue.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    ///
    /// * `pem_private_key` is malformed or does not contain an ECDSA P-256
    ///   private key.
    /// * there is a problem accessing the system's random number generator.
    pub fn sign(mut self, pem_private_key: &str) -> Result<Self, Error> {
        // The data that appears to be signed is the raw app image, with the
        // app properties already pointing to the new signature position, but
        // not including the space allocated for that signature.

        let sig_pos = self.make_ecdsa_signature_space() as usize;

        let signature = crypto::create_signature(pem_private_key, &self.raw[..sig_pos])?;
        self.raw.0.to_mut()[sig_pos..sig_pos + 64].copy_from_slice(&signature);

        Ok(self)
    }

    /// Returns the existing signature space, or allocates a new signature at
    /// the end of the image.
    ///
    /// When allocating new space for the signature, this will update the
    /// application property structure inside the raw data.
    ///
    /// Returns the position of the signature data.
    fn make_ecdsa_signature_space(&mut self) -> u32 {
        if let SignatureType::EcdsaP256 = self.app_props.signature_type {
            if self.app_props.signature_location != 0 {
                // signature already present
                return self.app_props.signature_location;
            }
        }

        // Allocate a new signature at the very end of the app image
        let location = self.raw.len() as u32;

        // Reallocate raw image buffer, allocating 0s for signature
        let mut raw = vec![0; self.raw.len() + 64];
        raw[..self.raw.len()].copy_from_slice(&self.raw);

        // Modify app props accordingly and write them back
        self.app_props.signature_type = SignatureType::EcdsaP256;
        self.app_props.signature_location = location;

        let props_pos = self.app_props_pos as usize;
        self.app_props
            .write(&mut &mut raw[props_pos..props_pos + AppProperties::LENGTH])
            .expect("serializing properties to byte slice failed");

        // Now use the larger buffer as the raw image
        self.raw = Blob(Cow::Owned(raw));

        location
    }
}
