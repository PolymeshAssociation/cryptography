pub mod errors;

use curve25519_dalek::scalar::Scalar;
use errors::Error;
use log::info;
use metrics::Recorder;
use metrics_core::Key;
use serde::{Deserialize, Serialize};
use std::{
    fs::{create_dir_all, File},
    path::PathBuf,
};

pub const ON_CHAIN_DIR: &str = "on-chain";
pub const OFF_CHAIN_DIR: &str = "off-chain";
pub const PUBLIC_ACCOUNT_FILE: &str = "public_account.json";
pub const SECRET_ACCOUNT_FILE: &str = "secret_account.json";
pub const ASSET_ID_LIST_FILE: &str = "valid_asset_ids.json";
pub const GLOBAL_USER_DIR: &str = "global";

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

pub fn construct_path(db_dir: PathBuf, on_off_chain: &str, user: &str, file_name: &str) -> PathBuf {
    let mut file_path = db_dir;
    file_path.push(on_off_chain);
    file_path.push(user);
    file_path.push(file_name);
    file_path
}

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

#[derive(Serialize, Deserialize)]
pub struct AssetIdList(pub Vec<Scalar>);

#[inline]
pub fn get_asset_ids(db_dir: PathBuf) -> Result<Vec<Scalar>, Error> {
    let file_path = construct_path(db_dir, ON_CHAIN_DIR, GLOBAL_USER_DIR, ASSET_ID_LIST_FILE);
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
