use std::{fmt, io};

/// The error type used by this library.
#[derive(Fail, Debug)]
pub struct Error {
    kind: ErrorKind,
    details: Option<String>,
}

impl Error {
    pub(crate) fn with_details<D>(kind: ErrorKind, details: D) -> Self
    where
        D: Into<String>,
    {
        Self {
            kind,
            details: Some(details.into()),
        }
    }

    pub(crate) fn parse_err<T: Into<String>>(msg: T) -> Error {
        Error::with_details(ErrorKind::ParseError, msg.into())
    }

    /// Returns the `ErrorKind` classifying this error further.
    pub fn kind(&self) -> ErrorKind {
        self.kind.clone()
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Error {
            kind,
            details: None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Self {
            kind: ErrorKind::ParseError,
            details: Some(err.to_string()),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match &self.details {
            Some(details) => write!(fmt, "{}: {}", self.kind, details),
            None => write!(fmt, "{}", self.kind),
        }
    }
}

/// The different kinds of errors that can occur.
#[derive(Fail, Debug, Clone)]
pub enum ErrorKind {
    /// Attempted to encrypt a GBL file that is already encrypted.
    ///
    /// It is only possible to encrypt the file once.
    #[fail(display = "attempted to encrypt a GBL file that is already encrypted")]
    AlreadyEncrypted,

    /// Attempted to verify the signature of a GBL file that does not contain a
    /// signature.
    #[fail(display = "attempted to verify the signature of a GBL file that isn't signed")]
    NotSigned,

    /// Attempted to decrypt a GBL file that wasn't encrypted.
    #[fail(display = "attempted to decrypt a GBL file that isn't encrypted")]
    NotEncrypted,

    /// Data could not be parsed because it is malformed.
    ///
    /// "Data" in this case can be the GBL file, an ECDSA or an AES key file.
    /// This error can also mean that an invalid key was provided (eg. a
    /// non-ECDSA key).
    ///
    /// When this is returned by [`Gbl::decrypt`], it most likely means that the
    /// wrong AES key was provided, resulting in garbage data.
    ///
    /// [`Gbl::decrypt`]: struct.Gbl.html#method.decrypt
    #[fail(display = "data could not be parsed")]
    ParseError,

    /// Signature was not created by the private key belonging to the provided
    /// public key.
    #[fail(display = "the signature is invalid")]
    InvalidSignature,

    /// An unspecified error occurred.
    ///
    /// Displaying the `Error` should result in a more useful message. This
    /// error is generally used for errors in ring and OpenSSL.
    #[fail(display = "error")]
    Other,

    #[doc(hidden)]
    #[fail(display = "__NonExhaustive")]
    __NonExhaustive,
}
