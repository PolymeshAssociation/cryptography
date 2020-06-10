use crate::mercat::AssetTxState;
use crate::mercat::ConfidentialTxState;

use bulletproofs::ProofError;
use failure::{Backtrace, Context, Fail};

use sp_std::fmt;

/// Represents an error resulted from asset value encryption,
/// decryption, or proof generation.
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
    fn from(kind: ErrorKind) -> Error {
        Error {
            inner: Context::new(kind),
        }
    }
}

impl From<Context<ErrorKind>> for Error {
    fn from(inner: Context<ErrorKind>) -> Error {
        Error { inner: inner }
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
    /// Unable to encrypt a plain text outside of the valid range.
    #[fail(display = "Unable to encrypt a plain text outside of the valid range")]
    PlainTextRangeError,

    /// Encrypted value was not found within the valid range.
    #[fail(display = "Encrypted value was not found within the valid range")]
    CipherTextDecryptionError,

    /// A proof verification error occurred.
    #[fail(display = "A proof verification error occured")]
    VerificationError,

    /// Failed to verify a correctness proof.
    #[fail(
        display = "Failed to verify the check number {} of the correctness proof",
        check
    )]
    CorrectnessFinalResponseVerificationError { check: u16 },

    /// Failed to verify a R1 proof.
    #[fail(
        display = "Failed to verify the check number {} of the R1 proof",
        check
    )]
    R1FinalResponseVerificationError { check: u16 },

    /// The index is out of range.
    #[fail(display = "The index is out of range {}", index)]
    OOONProofIndexOutofRange { index: usize },

    /// Input vector or matrix size does not match to the expected value
    #[fail(display = "The provided matrix or vector size does not match to the expected")]
    OOONProofWrongSize,

    /// Failed to verify a one-out-of-many proof.
    #[fail(
        display = "Failed to verify the check number {} of the OOON proof",
        check
    )]
    OOONFinalResponseVerificationError { check: u16 },

    /// Failed to verify a wellformedness proof.
    #[fail(
        display = "Failed to verify the check number {} of the wellformedness proof",
        check
    )]
    WellformednessFinalResponseVerificationError { check: u16 },

    /// Failed to verify a ciphertext refreshment proof.
    #[fail(
        display = "Failed to verify the check number {} of the ciphertext refreshment proof",
        check
    )]
    CiphertextRefreshmentFinalResponseVerificationError { check: u16 },

    /// Failed to verify an encrypting the same value proof.
    #[fail(
        display = "Failed to verify the check number {} of the encrypting the same value proof",
        check
    )]
    EncryptingSameValueFinalResponseVerificationError { check: u16 },

    /// Failed to verify the membership proof.
    #[fail(
        display = "Failed to verify the check number {} of the membership proof",
        check
    )]
    MembershipProofVerificationError { check: u16 },

    /// Invalid asset type is provided.
    #[fail(display = "Invalid asset type ")]
    MembershipProofInvalidAssetError,

    /// Elements set is empty.
    #[fail(display = "The elements set passed to the membership proof cannot be empty.")]
    EmptyElementsSet,

    /// TODO: remove this once all the mercat methods are implemented.
    #[fail(display = "This method is not implemented yet")]
    NotImplemented,

    #[fail(display = "Wrong exponent parameter is passed")]
    InvalidExponentParameter,

    /// The incoming transaction state does not match the expectation.
    #[fail(display = "Received an invalid previous state: {:?}", state)]
    InvalidPreviousState { state: ConfidentialTxState },

    /// The incoming asset transaction state does not match the expectation.
    #[fail(
        display = "Received an invalid previous asset transaction state: {:?}",
        state
    )]
    InvalidPreviousAssetTransactionState { state: AssetTxState },

    /// The amount in the initial transaction does not match the amount that receiver expacted.
    #[fail(
        display = "Expected to receive {:?} form the sender, got {:?}",
        expected_amount, received_amount
    )]
    TransactionAmountMismatch {
        expected_amount: u32,
        received_amount: u32,
    },

    /// The public key in the memo of the initial transaction does not match the public key
    /// in the memo.
    #[fail(display = "Public keys in the memo and the account are different.")]
    InputPubKeyMismatch,

    /// The sender has attempted to send more that their balance.
    #[fail(
        display = "Transaction amount {} must be equal or greater than {}",
        transaction_amount, balance
    )]
    NotEnoughFund {
        balance: u32,
        transaction_amount: u32,
    },

    /// The account Id in the transaction does not match the input account info.
    #[fail(display = "The account does not match the account on the transaction")]
    AccountIdMismatch,

    /// Error while converting a transaction content to binary format.
    #[fail(display = "Error during the serialization to byte array.")]
    SerializationError,

    /// Signature verification failure.
    #[fail(display = "The signature failed to verify.")]
    SignatureValidationFailure,

    /// A range proof error occurred.
    #[fail(display = "A range proof error occured: {}", source)]
    ProvingError { source: ProofError },
}

pub type Fallible<T, E = Error> = std::result::Result<T, E>;
