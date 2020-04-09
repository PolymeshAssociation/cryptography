use bulletproofs::ProofError;

/// Represents an error resulted from asset value encryption,
/// decryption, or proof generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AssetProofError {
    /// Unable to encrypt a plain text outside of the valid range.
    PlainTextRangeError,

    /// Encrypted value was not found within the valid range.
    CipherTextDecryptionError,

    /// A range proof error occured.
    ProvingError(ProofError),
}

impl From<ProofError> for AssetProofError {
    fn from(e: ProofError) -> AssetProofError {
        AssetProofError::ProvingError(e)
    }
}
