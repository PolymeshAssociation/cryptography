use failure::{Backtrace, Context, Fail};

use sp_std::{fmt, result::Result};

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
    /// Scope claim does not match cdd claim: Zero Knowledge Proof failed.
    #[fail(display = "Scope claim does not match cdd claim: Zero Knowledge Proof failed.")]
    ZkpError,

    /// Scope id is not wellformed: signature verification failed.
    #[fail(display = "Scope id is not wellformed: signature verification failed.")]
    SignatureError,
}

pub type Fallible<T, E = Error> = Result<T, E>;
