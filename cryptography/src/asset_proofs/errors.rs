use bulletproofs::ProofError;
use failure::{Error, Fail};

/// Represents an error resulted from asset value encryption,
/// decryption, or proof generation.
#[derive(Fail, Clone, Debug, Eq, PartialEq)]
pub enum AssetProofError {
    /// Unable to encrypt a plain text outside of the valid range.
    #[fail(display = "Unable to encrypt a plain text outside of the valid range")]
    PlainTextRangeError,

    /// Encrypted value was not found within the valid range.
    #[fail(display = "Encrypted value was not found within the valid range")]
    CipherTextDecryptionError,

    /// A proof verification error occured.
    #[fail(display = "A proof verification error occured")]
    VerificationError,

    /// Failed to verify a correctness proof.
    #[fail(
        display = "Failed to verify the check number {} of the correctness proof",
        check
    )]
    CorrectnessFinalResponseVerificationError { check: u16 },

    /// Failed to verify an encrypting the same value proof.
    #[fail(
        display = "Failed to verify the check number {} of the encrypting the same value proof",
        check
    )]
    EncryptingSameValueFinalResponseVerificationError { check: u16 },

    /// A range proof error occured.
    #[fail(display = "A range proof error occured: {}", source)]
    ProvingError { source: ProofError },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
