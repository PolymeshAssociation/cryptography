//! A common library for utility functions.
//!

pub mod errors;

use codec::{Decode, Encode};
use cryptography::mercat::{AssetTxState, ConfidentialTxState};
use curve25519_dalek::scalar::Scalar;
use errors::Error;
use log::info;
use metrics::Recorder;
use metrics_core::Key;
use rand::{rngs::StdRng, Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use std::{
    convert::TryInto,
    fs::{create_dir_all, File},
    io::BufReader,
    path::PathBuf,
};

pub const ON_CHAIN_DIR: &str = "on-chain";
pub const OFF_CHAIN_DIR: &str = "off-chain";
pub const PUBLIC_ACCOUNT_FILE: &str = "public_account.json";
pub const VALIDATED_PUBLIC_ACCOUNT_FILE: &str = "validated_public_account.json";
pub const SECRET_ACCOUNT_FILE: &str = "secret_account.json";
pub const ASSET_ID_LIST_FILE: &str = "valid_asset_ids.json";
pub const COMMON_OBJECTS_DIR: &str = "common";
pub const INIT_STATE: &str = "initialization_started";
pub const JUSTIFY_STATE: &str = "justification_started";

#[inline]
pub fn asset_transaction_file(tx_id: u32, state: AssetTxState) -> String {
    format!("tx_{}_{}.json", tx_id, state)
}

#[derive(Debug, Serialize, Deserialize, Encode, Decode, Clone)]
pub struct Instruction {
    pub state: AssetTxState,
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

#[inline]
pub fn confidential_transaction_file(tx_id: u32, state: ConfidentialTxState) -> String {
    format!("tx_{}_{}.json", tx_id, state)
}

#[derive(Debug, Serialize, Deserialize, Encode, Decode, Clone)]
pub struct CTXInstruction {
    pub state: ConfidentialTxState,
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

#[allow(dead_code)]
static RECORDER: PrintRecorder = PrintRecorder;

#[derive(Default)]
pub struct PrintRecorder;

impl Recorder for PrintRecorder {
    fn increment_counter(&self, key: Key, value: u64) {
        info!(
            "metrics: {{ \"counter\": {{ \"name\": \"{}\", \"value\": {} }} }}",
            key, value
        );
    }

    fn update_gauge(&self, key: Key, value: i64) {
        info!(
            "gauge: {{ \"counter\": {{ \"name\": \"{}\", \"value\": {} }} }}",
            key, value
        );
    }

    fn record_histogram(&self, key: Key, value: u64) {
        info!(
            "histogram: {{ \"counter\": {{ \"name\": \"{}\", \"value\": {} }} }}",
            key, value
        );
    }
}

#[cfg(feature = "std")]
pub fn init_print_logger() {
    let recorder = PrintRecorder::default();
    metrics::set_boxed_recorder(Box::new(recorder)).unwrap()
}

#[cfg(not(feature = "std"))]
pub fn init_print_logger() {
    metrics::set_recorder(&RECORDER).unwrap()
}

/// Utility function to construct the path based user name, file name, and whether the file
/// should be stored on or off chain.
#[inline]
pub fn construct_path(db_dir: PathBuf, on_off_chain: &str, user: &str, file_name: &str) -> PathBuf {
    let mut file_path = db_dir;
    file_path.push(on_off_chain);
    file_path.push(user);
    file_path.push(file_name);
    file_path
}

/// Utility function to save a serializable data to a location inside the database directory,
/// for a particular user.
#[inline]
pub fn save_to_file<T>(
    db_dir: PathBuf,
    on_off_chain: &str,
    user: &str,
    file_name: &str,
    data: &T,
) -> Result<(), Error>
where
    T: ?Sized + serde::Serialize,
{
    let mut file_path = db_dir;
    file_path.push(on_off_chain);
    file_path.push(user);

    // file_path is now the path to the user directory. Create it if it does not exist.
    create_dir_all(file_path.clone()).map_err(|error| Error::FileCreationError {
        error,
        path: file_path.clone(),
    })?;

    file_path.push(file_name);
    let file = File::create(file_path.clone()).map_err(|error| Error::FileCreationError {
        error,
        path: file_path.clone(),
    })?;
    serde_json::to_writer_pretty(file, &data).map_err(|error| Error::FileWriteError {
        error,
        path: file_path,
    })?;

    Ok(())
}

/// Utility function to read and deserializable data from a location inside the database directory,
/// for a particular user.
#[inline]
pub fn load_from_file<T: serde::de::DeserializeOwned>(
    db_dir: PathBuf,
    on_off_chain: &str,
    user: &str,
    file_name: &str,
) -> Result<T, Error> {
    let file_path = construct_path(db_dir, on_off_chain, user, file_name);
    let file = File::open(file_path.clone()).map_err(|error| Error::FileReadError {
        error,
        path: file_path.clone(),
    })?;

    let data = BufReader::new(file);

    serde_json::from_reader(data).map_err(|error| Error::ObjectDeserializationError {
        error,
        path: file_path.clone(),
    })
}

/// Utility function to remove a file from the database directory for a particular user.
#[inline]
pub fn remove_file(
    db_dir: PathBuf,
    on_off_chain: &str,
    user: &str,
    file_name: &str,
) -> Result<(), Error> {
    let file_path = construct_path(db_dir, on_off_chain, user, file_name);
    std::fs::remove_file(file_path.clone()).map_err(|error| Error::FileRemovalError {
        error,
        path: file_path,
    })?;
    Ok(())
}

/// A data structure that various CLIs can share to serialize and deserialize asset ids.
#[derive(Serialize, Deserialize)]
pub struct AssetIdList(pub Vec<Scalar>);

/// Utility function to read the asset ids from the database directory.
#[inline]
pub fn get_asset_ids(db_dir: PathBuf) -> Result<Vec<Scalar>, Error> {
    let file_path = construct_path(db_dir, ON_CHAIN_DIR, COMMON_OBJECTS_DIR, ASSET_ID_LIST_FILE);
    let file = File::open(file_path).map_err(|error| Error::FileReadError {
        error,
        path: ASSET_ID_LIST_FILE.into(),
    })?;
    let mut de = serde_json::Deserializer::from_reader(file);

    let valid_asset_ids =
        AssetIdList::deserialize(&mut de).map_err(|_| Error::AssetIdListDeserializeError {
            path: ASSET_ID_LIST_FILE.into(),
        })?;
    Ok(valid_asset_ids.0)
}

/// Utility function to save an object that implements the Decode trait to file.
#[inline]
pub fn save_object<T: Encode>(
    db_dir: PathBuf,
    on_off_chain: &str,
    user: &str,
    file_name: &str,
    data: &T,
) -> Result<(), Error> {
    let mut file_path = db_dir;
    file_path.push(on_off_chain);
    file_path.push(user);

    // file_path is now the path to the user directory. Create it if it does not exist.
    create_dir_all(file_path.clone()).map_err(|error| Error::FileCreationError {
        error,
        path: file_path.clone(),
    })?;

    file_path.push(file_name);

    std::fs::write(file_path.clone(), data.encode()).map_err(|error| Error::ObjectSaveError {
        error,
        path: file_path,
    })?;

    Ok(())
}

/// Utility function to read an object that implements the Encode trait from file.
#[inline]
pub fn load_object<T: Decode>(
    db_dir: PathBuf,
    on_off_chain: &str,
    user: &str,
    file_name: &str,
) -> Result<T, Error> {
    let file_path = construct_path(db_dir, on_off_chain, user, file_name);

    let data = std::fs::read(file_path.clone()).map_err(|error| Error::FileReadError {
        error,
        path: file_path.clone(),
    })?;

    T::decode(&mut &data[..]).map_err(|error| Error::ObjectLoadError {
        error,
        path: file_path,
    })
}

/// Helper function to save a config file to `cfg_path`.
pub fn save_config<T>(cfg_path: Option<PathBuf>, cfg: &T)
where
    T: ?Sized + serde::Serialize,
{
    if let Some(path) = &cfg_path {
        std::fs::write(
            path,
            serde_json::to_string_pretty(cfg).unwrap_or_else(|error| {
                panic!("Failed to serialize configuration file: {}", error)
            }),
        )
        .expect(&format!(
            "Failed to write the configuration to the file {:?}.",
            path
        ));
    }
}

/// Helper function to generate a random seed using the thread RNG.
pub fn gen_seed() -> String {
    let mut rng = rand::thread_rng();
    let mut seed = [0u8; 32];
    rng.fill(&mut seed);
    base64::encode(seed)
}

/// Helper function to create an RNG from seed.
#[inline]
pub fn create_rng_from_seed(seed: Option<String>) -> Result<StdRng, Error> {
    let seed = seed.ok_or(Error::EmptySeed)?;
    let seed: &[u8] = &base64::decode(seed).map_err(|error| Error::SeedDecodeError { error })?;
    let seed = seed
        .try_into()
        .map_err(|_| Error::SeedLengthError { length: seed.len() })?;

    Ok(StdRng::from_seed(seed))
}
