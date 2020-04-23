use bulletproofs::ProofError;

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
    #[fail(display = "Failed to verify the {} of the correctness proof", str)]
    CorrectnessFinalResponseVerificationError { str: String },

    /// A range proof error occured.
    #[fail(display = "A range proof error occured")]
    ProvingError(ProofError),
}

impl From<ProofError> for AssetProofError {
    fn from(e: ProofError) -> AssetProofError {
        AssetProofError::ProvingError(e)
    }
}
