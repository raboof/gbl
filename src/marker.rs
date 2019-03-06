//! Contains marker types used to implement type state for encrypted and signed
//! GBLs.

use self::private::*;
use super::*;
use crate::utils::Blob;

use either::Either;
use std::borrow::Cow;
use std::fmt;
use std::marker::PhantomData;

mod sealed {
    use super::*;

    pub trait Sealed {}

    impl<'a> Sealed for Encrypted<'a> {}
    impl<'a> Sealed for NotEncrypted<'a> {}
    impl<'a> Sealed for MaybeEncrypted<'a> {}

    impl<'a> Sealed for Signed<'a> {}
    impl<'a> Sealed for NotSigned<'a> {}
    impl<'a> Sealed for MaybeSigned<'a> {}
}

pub(crate) mod private {
    use super::*;

    /// Trait implemented by marker types specifying the encryption state of a
    /// GBL.
    ///
    /// This is an internal trait that should not be publicly reachable.
    pub trait EncryptionState<'a>: sealed::Sealed {
        /// The `Self` type, but with all lifetime parameters set to `'static`.
        type StaticSelf: EncryptionState<'static> + 'static;

        fn into_owned(self) -> Self::StaticSelf;
        fn clone(&'a self) -> Self;

        fn into_either(self) -> Either<Encrypted<'a>, NotEncrypted<'a>>;
        fn as_either_ref(&self) -> Either<&Encrypted<'a>, &NotEncrypted<'a>>;
    }

    /// Trait implemented by marker types specifying the signature state of a
    /// GBL.
    ///
    /// This is an internal trait that should not be publicly reachable.
    pub trait SignatureState<'a>: sealed::Sealed {
        /// The `Self` type, but with all lifetime parameters set to `'static`.
        type StaticSelf: SignatureState<'static> + 'static;

        fn into_owned(self) -> Self::StaticSelf;
        fn clone(&'a self) -> Self;

        fn into_either(self) -> Either<Signed<'a>, NotSigned<'a>>;
        fn as_either_ref(&self) -> Either<&Signed<'a>, &NotSigned<'a>>;
    }
}

/// The GBL is encrypted.
#[derive(Debug)]
pub struct Encrypted<'a> {
    pub(crate) enc_header: EncryptionHeader,
    pub(crate) enc_sections: Vec<Blob<Cow<'a, [u8]>>>,
}

/// The GBL is not encrypted.
#[derive(Debug)]
pub struct NotEncrypted<'a> {
    pub(crate) app_info: AppInfo,
    pub(crate) sections: Vec<ProgramData<'a>>,
}

/// The GBL may or may not be encrypted.
pub struct MaybeEncrypted<'a> {
    pub(crate) inner: Either<Encrypted<'a>, NotEncrypted<'a>>,
}

impl<'a> EncryptionState<'a> for Encrypted<'a> {
    type StaticSelf = Encrypted<'static>;

    fn into_owned(self) -> Self::StaticSelf {
        Encrypted {
            enc_header: self.enc_header,
            enc_sections: self
                .enc_sections
                .into_iter()
                .map(|section| Blob(section.0.into_owned().into()))
                .collect(),
        }
    }

    fn clone(&'a self) -> Self {
        Self {
            enc_header: self.enc_header,
            enc_sections: self
                .enc_sections
                .iter()
                .map(|section| Blob(Cow::Borrowed(&**section)))
                .collect(),
        }
    }

    fn into_either(self) -> Either<Encrypted<'a>, NotEncrypted<'a>> {
        Either::Left(self)
    }

    fn as_either_ref(&self) -> Either<&Encrypted<'a>, &NotEncrypted<'a>> {
        Either::Left(self)
    }
}

impl<'a> EncryptionState<'a> for NotEncrypted<'a> {
    type StaticSelf = NotEncrypted<'static>;

    fn into_owned(self) -> Self::StaticSelf {
        NotEncrypted {
            app_info: self.app_info,
            sections: self
                .sections
                .into_iter()
                .map(|section| section.into_owned())
                .collect(),
        }
    }

    fn clone(&'a self) -> Self {
        Self {
            app_info: self.app_info,
            sections: self.sections.iter().map(ProgramData::clone).collect(),
        }
    }

    fn into_either(self) -> Either<Encrypted<'a>, NotEncrypted<'a>> {
        Either::Right(self)
    }

    fn as_either_ref(&self) -> Either<&Encrypted<'a>, &NotEncrypted<'a>> {
        Either::Right(self)
    }
}

impl<'a> EncryptionState<'a> for MaybeEncrypted<'a> {
    type StaticSelf = MaybeEncrypted<'static>;

    fn into_owned(self) -> Self::StaticSelf {
        MaybeEncrypted {
            inner: self.inner.either(
                |enc| Either::Left(enc.into_owned()),
                |not_enc| Either::Right(not_enc.into_owned()),
            ),
        }
    }

    fn clone(&'a self) -> Self {
        Self {
            inner: self
                .inner
                .as_ref()
                .map_left(Encrypted::clone)
                .map_right(NotEncrypted::clone),
        }
    }

    fn into_either(self) -> Either<Encrypted<'a>, NotEncrypted<'a>> {
        self.inner
    }

    fn as_either_ref(&self) -> Either<&Encrypted<'a>, &NotEncrypted<'a>> {
        self.inner.as_ref()
    }
}

impl<'a> fmt::Debug for MaybeEncrypted<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.inner {
            Either::Left(l) => l.fmt(f),
            Either::Right(r) => r.fmt(f),
        }
    }
}

/// The GBL is signed with an ECDSA signature.
#[derive(Debug)]
pub struct Signed<'a> {
    pub(crate) signature: Signature<'a>,
}

/// The GBL is not signed.
pub struct NotSigned<'a> {
    pub(crate) _p: PhantomData<&'a ()>,
}
impl<'a> NotSigned<'a> {
    pub(crate) fn new() -> Self {
        Self { _p: PhantomData }
    }
}

/// The GBL may or may not contain a signature.
pub struct MaybeSigned<'a> {
    pub(crate) inner: Either<Signed<'a>, NotSigned<'a>>,
}

impl<'a> SignatureState<'a> for Signed<'a> {
    type StaticSelf = Signed<'static>;

    fn into_owned(self) -> Self::StaticSelf {
        Signed {
            signature: self.signature.into_owned(),
        }
    }

    fn clone(&'a self) -> Self {
        Self {
            signature: self.signature.clone(),
        }
    }

    fn into_either(self) -> Either<Signed<'a>, NotSigned<'a>> {
        Either::Left(self)
    }

    fn as_either_ref(&self) -> Either<&Signed<'a>, &NotSigned<'a>> {
        Either::Left(self)
    }
}
impl<'a> SignatureState<'a> for NotSigned<'a> {
    type StaticSelf = NotSigned<'static>;

    fn into_owned(self) -> Self::StaticSelf {
        NotSigned::new()
    }

    fn clone(&'a self) -> Self {
        NotSigned::new()
    }

    fn into_either(self) -> Either<Signed<'a>, NotSigned<'a>> {
        Either::Right(self)
    }

    fn as_either_ref(&self) -> Either<&Signed<'a>, &NotSigned<'a>> {
        Either::Right(self)
    }
}
impl<'a> SignatureState<'a> for MaybeSigned<'a> {
    type StaticSelf = MaybeSigned<'static>;

    fn into_owned(self) -> Self::StaticSelf {
        MaybeSigned {
            inner: self
                .inner
                .map_left(Signed::into_owned)
                .map_right(NotSigned::into_owned),
        }
    }

    fn clone(&'a self) -> Self {
        Self {
            inner: self
                .inner
                .as_ref()
                .map_left(Signed::clone)
                .map_right(NotSigned::clone),
        }
    }

    fn into_either(self) -> Either<Signed<'a>, NotSigned<'a>> {
        self.inner
    }

    fn as_either_ref(&self) -> Either<&Signed<'a>, &NotSigned<'a>> {
        self.inner.as_ref()
    }
}

impl<'a> fmt::Debug for NotSigned<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("NotSigned")
    }
}

impl<'a> fmt::Debug for MaybeSigned<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.inner {
            Either::Left(l) => l.fmt(f),
            Either::Right(r) => r.fmt(f),
        }
    }
}
