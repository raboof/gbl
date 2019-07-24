extern crate gbl;

extern crate env_logger;
#[macro_use]
extern crate failure;
#[macro_use]
#[allow(unused)] // the #[macro_use] warns on nightly since it's not needed
extern crate structopt;

use gbl::uuid::Uuid;
use gbl::{AesKey, AppImage, AppInfo, Gbl, P256KeyPair, P256PublicKey, ProgramData};

use failure::{err_msg, Error, ResultExt};
use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;
use std::{fs, process};
use structopt::StructOpt;

fn aes_key_from_hex(raw: &str) -> Result<AesKey, gbl::Error> {
    AesKey::from_hex_str(raw)
}

#[derive(StructOpt)]
#[structopt(name = "gbl", about = "GBL file creation, signing and encryption")]
enum Opts {
    /// Parses an existing GBL file and dumps its structure to the console.
    #[structopt(name = "dump")]
    Dump {
        /// Path to the GBL file.
        #[structopt(parse(from_os_str))]
        gbl: PathBuf,

        /// Write the parsed GBL file back to this file instead of outputting
        /// info to the console.
        #[structopt(parse(from_os_str))]
        #[structopt(long = "output")]
        output: Option<PathBuf>,

        /// Extract the raw flash image and write it to this binary file.
        #[structopt(parse(from_os_str))]
        #[structopt(long = "raw-app")]
        raw_app: Option<PathBuf>,
    },

    /// Create a GBL file from raw application data.
    #[structopt(name = "create")]
    Create {
        /// Path to the raw `.bin` application image.
        #[structopt(parse(from_os_str))]
        #[structopt(long = "app")]
        app: PathBuf,

        /// Do not extract the appinfo struct from the application image.
        /// Instead, use an empty appinfo struct.
        #[structopt(long = "empty-appinfo")]
        empty_appinfo: bool,

        /// GBL output path.
        #[structopt(parse(from_os_str))]
        output: PathBuf,
        // TODO: support signing and encrypting in one step here
    },

    /// Sign a GBL file using a private ECDSA key.
    #[structopt(name = "sign")]
    Sign {
        /// The private ECDSA key to use (in PEM format).
        #[structopt(long = "privkey")]
        #[structopt(parse(from_os_str))]
        privkey: PathBuf,

        /// Path to the GBL file to sign. If the file is already signed, the
        /// signature will be replaced.
        #[structopt(parse(from_os_str))]
        gbl: PathBuf,

        /// Write the parsed GBL file back to this file instead of outputting
        /// info to the console.
        #[structopt(parse(from_os_str))]
        #[structopt(long = "output")]
        output: PathBuf,
    },

    /// Verifies the signature of a signed GBL file.
    #[structopt(name = "verify")]
    Verify {
        /// Path to the public key to use for verifying the signature.
        ///
        /// The key must be in PEM format (`-----BEGIN PUBLIC KEY-----` etc.).
        #[structopt(long = "pubkey")]
        #[structopt(parse(from_os_str))]
        pubkey: PathBuf,

        /// Path to the GBL file to verify.
        #[structopt(parse(from_os_str))]
        gbl: PathBuf,
    },

    /// Decrypts an encrypted GBL file with a shared AES key.
    #[structopt(name = "decrypt")]
    Decrypt {
        /// Path to the AES key file in bootloader token format.
        #[structopt(long = "keyfile")]
        #[structopt(parse(from_os_str))]
        keyfile: Option<PathBuf>,

        /// Raw 128-bit AES key to use for decryption, in hexadecimal.
        #[structopt(name = "aes-key", long = "raw-key")]
        #[structopt(parse(try_from_str = "aes_key_from_hex"))]
        raw_key: Option<AesKey>,

        /// Path to the encrypted GBL file.
        #[structopt(parse(from_os_str))]
        gbl: PathBuf,

        /// Write the decrypted GBL file to this file. If not specified, info
        /// about the decrypted GBL will be dumped to stdout and no GBL will be
        /// written.
        #[structopt(parse(from_os_str))]
        #[structopt(long = "output")]
        output: Option<PathBuf>,
    },

    #[structopt(name = "encrypt")]
    Encrypt {
        /// Path to the AES key file in bootloader token format.
        #[structopt(long = "keyfile")]
        #[structopt(parse(from_os_str))]
        keyfile: Option<PathBuf>,

        /// Raw 128-bit AES key to use for encryption, in hexadecimal.
        #[structopt(name = "aes-key", long = "raw-key")]
        #[structopt(parse(try_from_str = "aes_key_from_hex"))]
        raw_key: Option<AesKey>,

        /// Path to the GBL file (must not be encrypted).
        #[structopt(parse(from_os_str))]
        gbl: PathBuf,

        /// Write the encrypted GBL file to this file. If not specified, info
        /// about the encrypted GBL will be dumped to stdout and no GBL will be
        /// written.
        #[structopt(parse(from_os_str))]
        #[structopt(long = "output")]
        output: Option<PathBuf>,
    },

    /// Raw application image manipulation.
    #[structopt(name = "app-image")]
    AppImage {
        #[structopt(flatten)]
        opts: AppImageOpts,
    },
}

/// Raw application image manipulation.
#[derive(StructOpt)]
enum AppImageOpts {
    /// Sign the application image for secure boot.
    #[structopt(name = "sign")]
    Sign {
        /// The private ECDSA key to use (in PEM format).
        #[structopt(long = "privkey")]
        #[structopt(parse(from_os_str))]
        privkey: PathBuf,

        /// Path to the application image to sign.
        #[structopt(parse(from_os_str))]
        image: PathBuf,

        #[structopt(parse(from_os_str))]
        #[structopt(long = "output")]
        output: PathBuf,
    },
}

fn appimage(opts: AppImageOpts) -> Result<(), Error> {
    match opts {
        AppImageOpts::Sign {
            privkey,
            image,
            output,
        } => {
            let appimage = fs::read(image)?;
            let key_str = fs::read_to_string(privkey)?;
            let key = P256KeyPair::from_pem(key_str)?;
            let appimage = AppImage::parse(&appimage)?;
            let signed = appimage.sign(&key)?;
            fs::write(&output, signed.into_raw())?;
            println!("Wrote signed application image to {}", output.display());

            Ok(())
        }
    }
}

fn run() -> Result<(), Error> {
    env_logger::init();

    let opts = Opts::from_args();
    match opts {
        Opts::Dump {
            gbl,
            output,
            raw_app,
        } => {
            let content = fs::read(gbl)?;
            let gbl = Gbl::parse(&content)?;

            if let Some(raw_app) = raw_app {
                let unencrypted_gbl = match gbl.clone().into_not_encrypted() {
                    Ok(g) => g,
                    Err(_) => bail!("`--raw-app` cannot be used with encrypted GBLs"),
                };

                let mut buf = Vec::new();
                for section in unencrypted_gbl.data_sections() {
                    let end = section.start_addr() as usize + section.bytes().len();
                    buf.resize(end, 0);
                    buf[section.start_addr() as usize..end].copy_from_slice(section.bytes());
                }

                File::create(&raw_app)?.write_all(&buf)?;
                println!("Wrote flash image to {}", raw_app.display());
            }

            if let Some(output) = output {
                gbl.write(&mut File::create(&output)?)?;
                println!("Wrote GBL to {}", output.display());
            } else {
                println!("{:#?}", gbl);
            }
        }
        Opts::Create {
            app,
            empty_appinfo,
            output,
        } => {
            let file_contents = fs::read(&app)?;
            let app_image = match app.extension() {
                Some(ext) => match &*ext.to_string_lossy() {
                    "bin" => file_contents,
                    ext => bail!(
                        "unsupported file extension '{}' (at the moment, only raw `.bin` \
                         files are supported)",
                        ext
                    ),
                },
                None => bail!("application image must have a supported file extension"),
            };

            let gbl = if empty_appinfo {
                Gbl::from_parts(
                    AppInfo::new(0, 0, 0, Uuid::nil()),
                    ProgramData::new(0, app_image),
                )
            } else {
                let app_image = AppImage::parse(&app_image)?;
                Gbl::from_app_image(app_image)
            };
            gbl.write(&mut File::create(&output)?)?;
            println!("Wrote GBL to {}", output.display());
        }
        Opts::Sign {
            gbl,
            privkey,
            output,
        } => {
            let content = fs::read(gbl)?;
            let key_str = fs::read_to_string(&privkey).context(privkey.display().to_string())?;
            let key = P256KeyPair::from_pem(key_str)?;
            let gbl = Gbl::parse(&content)?;
            let gbl = gbl.into_not_signed().unwrap_or_else(|signed| {
                println!("Warning: GBL is already signed. Removing old signature.");
                signed.remove_signature()
            });
            let gbl = gbl.sign(&key)?;
            gbl.write(&mut File::create(&output)?)?;
            println!("Wrote signed GBL to {}", output.display());
        }
        Opts::Verify { gbl, pubkey } => {
            let content = fs::read(gbl)?;
            let gbl = Gbl::parse(&content)?;
            let pubkey_str = fs::read_to_string(pubkey)?;
            let pubkey = P256PublicKey::from_pem(pubkey_str)?;
            gbl.into_signed()
                .map_err(|_| err_msg("file is not signed"))?
                .verify_signature(&pubkey)?;
            println!("Signature is valid!");
        }
        Opts::Encrypt {
            keyfile,
            raw_key,
            gbl,
            output,
        } => {
            let aes_key = match (keyfile, raw_key) {
                (None, None) => {
                    bail!("either `--keyfile` or `--raw-key` must be specified");
                }
                (Some(file), None) => AesKey::from_token_file(fs::read_to_string(file)?)?,
                (None, Some(aes_key)) => aes_key,
                (Some(_), Some(_)) => {
                    bail!("cannot specify both `--keyfile` and `--raw-key`");
                }
            };

            let gbl_path = &gbl;
            let content = fs::read(&gbl)?;
            let gbl = Gbl::parse(&content)?;
            let gbl = gbl.into_not_encrypted().map_err(|_| {
                format_err!("the GBL file '{}' is already encrypted", gbl_path.display())
            })?;
            let gbl = gbl.into_not_signed().unwrap_or_else(|gbl| {
                println!(
                    "Warning: Attempting to encrypt a signed GBL. This will remove the signature."
                );
                gbl.remove_signature()
            });

            let encrypted = gbl.encrypt(aes_key);

            if let Some(output) = output {
                encrypted.write(&mut File::create(&output)?)?;
                println!("Wrote decrypted GBL to {}", output.display());
            } else {
                println!("{:#?}", encrypted);
            }
        }
        Opts::Decrypt {
            keyfile,
            raw_key,
            gbl,
            output,
        } => {
            let aes_key = match (keyfile, raw_key) {
                (None, None) => {
                    bail!("either `--keyfile` or `--raw-key` must be specified");
                }
                (Some(file), None) => AesKey::from_token_file(fs::read_to_string(file)?)?,
                (None, Some(aes_key)) => aes_key,
                (Some(_), Some(_)) => {
                    bail!("cannot specify both `--keyfile` and `--raw-key`");
                }
            };

            let gbl_path = &gbl;
            let content = fs::read(&gbl)?;
            let gbl = Gbl::parse(&content)?;
            let gbl = gbl.into_encrypted().map_err(|_| {
                format_err!(
                    "the GBL file '{}' doesn't seem to be encrypted",
                    gbl_path.display()
                )
            })?;
            let gbl = gbl.into_not_signed().unwrap_or_else(|gbl| {
                println!(
                    "Warning: Attempting to decrypt a signed GBL. This will remove the signature."
                );
                gbl.remove_signature()
            });

            let result = gbl.decrypt(aes_key);
            let decrypted = result.with_context(|e| {
                format!(
                    "decryption failed: {} (make sure the right AES key was used)",
                    e
                )
            })?;

            if let Some(output) = output {
                decrypted.write(&mut File::create(&output)?)?;
                println!("Wrote decrypted GBL to {}", output.display());
            } else {
                println!("{:#?}", decrypted);
            }
        }
        Opts::AppImage { opts } => appimage(opts)?,
    }

    Ok(())
}

fn main() {
    match run() {
        Ok(()) => {}
        Err(e) => {
            eprintln!("ERROR: {}", e);
            process::exit(1);
        }
    }
}
