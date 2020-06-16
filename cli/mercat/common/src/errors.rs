use failure::Fail;
use std::path::PathBuf;

#[derive(Fail, Debug)]
pub enum Error {
    #[fail(display = "The input seed cannot be empty")]
    EmptySeed,

    #[fail(display = "Error in decoding the seed value: {:?}", error)]
    SeedDecodeError { error: base64::DecodeError },

    #[fail(display = "Want seed length 32, got len: {:?}", length)]
    SeedLengthError { length: usize },

    #[fail(display = "An error occured in the underlying library: {:?}", error)]
    LibraryError { error: cryptography::errors::Error },

    #[fail(display = "The database directory must be provided")]
    EmptyDatabaseDir,

    #[fail(display = "Failed to create the file {:?}: {:?}", path, error)]
    FileCreationError {
        error: std::io::Error,
        path: PathBuf,
    },

    #[fail(display = "Failed to write to the file {:?}: {:?}", path, error)]
    FileWriteError {
        error: serde_json::Error,
        path: PathBuf,
    },

    #[fail(display = "Failed to remove the file {:?}: {:?}", path, error)]
    FileRemovalError {
        error: std::io::Error,
        path: PathBuf,
    },
}
