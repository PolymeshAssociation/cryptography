use failure::Fail;
use std::path::PathBuf;

/// Commom errors for all mercat clis
#[derive(Fail, Debug)]
pub enum Error {
    /// The create account has been called with an empty seed.
    #[fail(display = "The input seed cannot be empty")]
    EmptySeed,

    /// There was an error in converting the seed from base64 to byte array.
    #[fail(display = "Error in decoding the seed value: {:?}", error)]
    SeedDecodeError { error: base64::DecodeError },

    /// The length of the provided seed was not equal to 32 byets.
    #[fail(display = "Want seed length 32, got len: {:?}", length)]
    SeedLengthError { length: usize },

    /// An error occured while deserializing asset id list to a vector of Scalar values.
    #[fail(display = "Could not deserialize the asset id list from {:?}", path)]
    AssetIdListDeserializeError { path: String },

    /// An error occurred during the call to the mercat library.
    #[fail(display = "An error occured in the underlying library: {:?}", error)]
    LibraryError { error: cryptography::errors::Error },

    /// No database directory path was passed.
    #[fail(display = "The database directory must be provided")]
    EmptyDatabaseDir,

    /// An error occured while creating an empty file.
    #[fail(display = "Failed to create the file {:?}: {:?}", path, error)]
    FileCreationError {
        error: std::io::Error,
        path: PathBuf,
    },

    /// An error occured while reading from a file.
    #[fail(display = "Failed to read the file {:?}: {:?}", path, error)]
    FileReadError { error: std::io::Error, path: String },

    /// An error occured while writing to a file.
    #[fail(display = "Failed to write to the file {:?}: {:?}", path, error)]
    FileWriteError {
        error: serde_json::Error,
        path: PathBuf,
    },

    /// An error occured while removing a file.
    #[fail(display = "Failed to remove the file {:?}: {:?}", path, error)]
    FileRemovalError {
        error: std::io::Error,
        path: PathBuf,
    },
}
