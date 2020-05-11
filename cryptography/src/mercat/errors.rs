use crate::mercat::lib::ConfidentialTxState;
use failure::{Error, Fail};

/// Represents an error in asset issuance transaction.
/// TODO: as we implement the methods, we will find more explicit types for
/// the error.
#[derive(Fail, Clone, Debug, Eq, PartialEq)]
pub enum AssetTxError {
    #[fail(display = "CHANGEME as needed")]
    ChangeMe,
}

/// Represents an error in confidential transaction.
/// TODO: as we implement the methods, we will find more explicit types for
/// the error.
#[derive(Fail, Clone, Debug, Eq, PartialEq)]
pub enum ConfidentialTxError {
    #[fail(display = "This method is not implemented yet")]
    NotImplemented,
    #[fail(display = "Received an invalid previous state: {}", state)]
    InvalidPreviousState { state: ConfidentialTxState },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
