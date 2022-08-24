use failure::Fail;
use std::path::PathBuf;

/// Common errors for all mercat clis
#[derive(Fail, Debug)]
pub enum Error {
    /// Instruction is not valid.
    #[fail(display = "Instruction is not valid.")]
    InvalidInstructionError,

    /// The create account has been called with an empty seed.
    #[fail(display = "The input seed cannot be empty.")]
    EmptySeed,

    /// There was an error in converting the seed from base64 to byte array.
    #[fail(display = "Error in decoding the seed value: {:?}", error)]
    SeedDecodeError { error: base64::DecodeError },

    /// The length of the provided seed was not equal to 32 bytes.
    #[fail(display = "Want seed length 32, got len: {:?}", length)]
    SeedLengthError { length: usize },

    /// An error occurred while deserializing asset id list to a vector of Scalar values.
    #[fail(display = "Could not deserialize the asset id list from {:?}", path)]
    AssetIdListDeserializeError { path: String },

    /// An error occurred during the call to the mercat library.
    #[fail(display = "An error occurred in the underlying library: {:?}", error)]
    LibraryError {
        error: confidential_identity_core::asset_proofs::errors::Error,
    },

    /// No database directory path was passed.
    #[fail(display = "The database directory must be provided.")]
    EmptyDatabaseDir,

    /// An error occurred while creating an empty file.
    #[fail(display = "Failed to create the file {:?}: {:?}", path, error)]
    FileCreationError {
        error: std::io::Error,
        path: PathBuf,
    },

    /// An error occurred while reading from a file.
    #[fail(display = "Failed to read the file {:?}: {:?}", path, error)]
    FileReadError {
        error: std::io::Error,
        path: PathBuf,
    },

    /// An error occurred while deserializing an object from a file.
    #[fail(
        display = "Failed to deserialize an object, read from file {:?}: {:?}",
        path, error
    )]
    ObjectDeserializationError {
        error: serde_json::Error,
        path: PathBuf,
    },

    /// An error occurred while writing to a file.
    #[fail(display = "Failed to write to file {:?}: {:?}", path, error)]
    FileWriteError {
        error: serde_json::Error,
        path: PathBuf,
    },

    /// An error occurred while decoding an object.
    #[fail(
        display = "Failed to decode an object, read from file {:?}: {:?}",
        path, error
    )]
    ObjectLoadError { error: codec::Error, path: PathBuf },

    /// An error occurred while writing to a file.
    #[fail(display = "Failed to save data to file {:?}: {:?}", path, error)]
    ObjectSaveError {
        error: std::io::Error,
        path: PathBuf,
    },

    /// An error occurred while removing a file.
    #[fail(display = "Failed to remove file {:?}: {:?}", path, error)]
    FileRemovalError {
        error: std::io::Error,
        path: PathBuf,
    },

    /// An error occurred while reading from a file.
    #[fail(
        display = "Failed to parse the config file {:?}, because {:?}",
        path, reason
    )]
    ErrorParsingTestHarnessConfig { path: PathBuf, reason: String },

    /// An error occurred while parsing regex.
    #[fail(display = "Failed to parse the regex: {:?}", reason)]
    RegexError { reason: String },

    /// Balance great than u32
    #[fail(display = "balance does not fit u32")]
    BalanceTooBig,

    /// There can be only one top level transaction
    #[fail(display = "There can be only one top level transaction")]
    TopLevelTransaction,

    /// Could not convert a PathBuf to string
    #[fail(display = "Could not convert a PathBuf to string")]
    PathBufConversionError,

    /// Error accessing the glob pattern.
    #[fail(display = "Error accessing the glob pattern")]
    GlobPatternError,

    /// Error in decoding the object.
    #[fail(display = "Error in decoding the object.")]
    DecodeError,

    /// Could not find account id in the validators local map.
    #[fail(
        display = "Could not find account id {} in the validator's local map.",
        account_id
    )]
    AccountIdNotFound { account_id: String },

    /// Invalid transaction file
    #[fail(display = "Invalid transaction file: {}.", path)]
    InvalidTransactionFile { path: String },

    /// Transaction is not ready for validation
    #[fail(display = "Transaction is not ready for validation.")]
    TransactionIsNotReadyForValidation,

    /// Last transaction could not be found for user.
    #[fail(display = "Last transaction could not be found for user: {:?}.", user)]
    LastTransactionNotFound { user: String },

    /// Last processed tx error.
    #[fail(
        display = "Last processed tx counter in the transaction cannot be less than the last processed tx counter in the account. Want {:?} > {:?}",
        current, earliest
    )]
    MismatchInProcessedCounter {
        current: Option<u32>,
        earliest: Option<u32>,
    },

    /// Last processed tx counter should not be less than -1
    #[fail(
        display = "Last processed tx counter should not be less than -1, got {}.",
        value
    )]
    InvalidLastProcessedTxCounter { value: i32 },

    #[fail(display = "Not implemented, story: {}", story)]
    NotImplemented { story: String },
}
