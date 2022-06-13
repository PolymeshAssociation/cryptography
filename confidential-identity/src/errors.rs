use sp_std::{fmt, result::Result};

#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
}

impl Error {
    #[inline]
    pub fn kind(&self) -> &ErrorKind {
        &self.kind
    }
}

impl From<ErrorKind> for Error {
    #[inline]
    fn from(kind: ErrorKind) -> Error {
        Error {
            kind,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use ErrorKind::*;
        match &self.kind {
            ZkpError => {
                write!(f, "Scope claim does not match cdd claim: Zero Knowledge Proof failed.")
            },
            SignatureError => {
                write!(f, "Scope id is not wellformed: signature verification failed.")
            },
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    /// Scope claim does not match cdd claim: Zero Knowledge Proof failed.
    ZkpError,

    /// Scope id is not wellformed: signature verification failed.
    SignatureError,
}

pub type Fallible<T, E = Error> = Result<T, E>;
