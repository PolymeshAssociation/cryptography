use bulletproofs::ProofError;
use failure::{Backtrace, Context, Fail};

use sp_std::{fmt, result::Result};

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
        Error { inner: inner }
    }
}

impl From<schnorrkel::errors::SignatureError> for Error {
    #[inline]
    fn from(_inner: schnorrkel::errors::SignatureError) -> Error {
        Error::from(ErrorKind::SignatureValidationFailure)
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
    #[fail(display = "A proof verification error occurred")]
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
    OOONProofIndexOutofRange { index: u32 },

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

    /// Invalid exponent parameter was passed.
    #[fail(display = "Invalid exponent parameter was passed.")]
    InvalidExponentParameter,

    /// The amount in the initial transaction does not match the amount that receiver expected.
    #[fail(
        display = "Expected to receive {:?} from the sender, got a different amount.",
        expected_amount
    )]
    TransactionAmountMismatch { expected_amount: u32 },

    /// The public key in the memo of the initial transaction does not match the public key
    /// in the memo.
    #[fail(display = "Public keys in the memo and the account are different.")]
    InputPubKeyMismatch,

    /// The sender has attempted to send more that their balance.
    #[fail(
        display = "Transaction amount {} must be less than or equal to {}",
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
    #[fail(display = "A range proof error occurred: {:?}", source)]
    ProvingError { source: ProofError },

    /// The ticker id can be at most 12 characters long.
    #[fail(
        display = "Incorrect ticker length. The length can be at most {:?}, but got {:?}",
        want, got
    )]
    TickerIdLengthError { want: usize, got: usize },

    /// The auditors' payload does not match the compliance rules.
    #[fail(display = "The auditors' payload does not match the compliance rules.")]
    AuditorPayloadError,
}

pub type Fallible<T, E = Error> = Result<T, E>;
