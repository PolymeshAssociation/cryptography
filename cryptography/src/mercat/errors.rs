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
    #[fail(display = "Received an invalid previous state: {:?}", state)]
    InvalidPreviousState { state: ConfidentialTxState },
    #[fail(
        display = "Expected to receive {:?} form the sender, got {:?}",
        expected_amount, received_amount
    )]
    TransactionAmountMismatch {
        expected_amount: u32,
        received_amount: u32,
    },
    #[fail(display = "Public keys in the memo and the account are different.")]
    InputPubKeyMismatch,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
