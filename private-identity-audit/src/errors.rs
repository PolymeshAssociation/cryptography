use failure::{Backtrace, Context, Fail};

use std::{fmt, result::Result};

/// Represents PIAL errors.
#[derive(Debug)]
pub struct Error {
    inner: Context<ErrorKind>,
}

impl Error {
    #[inline]
    pub fn kind(&self) -> &ErrorKind {
        self.inner.get_context()
    }
}

impl From<ErrorKind> for Error {
    #[inline]
    fn from(kind: ErrorKind) -> Error {
        Error {
            inner: Context::new(kind),
        }
    }
}

impl From<Context<ErrorKind>> for Error {
    #[inline]
    fn from(inner: Context<ErrorKind>) -> Error {
        Error { inner }
    }
}

impl Fail for Error {
    fn cause(&self) -> Option<&dyn Fail> {
        self.inner.cause()
    }

    #[inline]
    fn backtrace(&self) -> Option<&Backtrace> {
        self.inner.backtrace()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.inner, f)
    }
}

#[derive(Fail, Clone, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    /// ZKP proof failed.
    #[fail(display = "ZK Proof of {} failed", kind)]
    ZKPVerificationError { kind: String },

    /// Membership proof failed.
    #[fail(display = "Membership proof failed")]
    MembershipProofError,

    /// CDD_ID mismatched.
    #[fail(display = "CDD ID in the proof is different from the CDD ID of the chain.")]
    CDDIdMismatchError,
}

pub type Fallible<T, E = Error> = Result<T, E>;
