pub mod errors;

use cryptography::{mercat::account::convert_asset_ids, AssetId};
use curve25519_dalek::scalar::Scalar;
use errors::Error;
use log::info;
use metrics::Recorder;
use metrics_core::Key;
use std::{
    convert::TryFrom,
    fs::{create_dir_all, File},
    path::PathBuf,
};

pub const ON_CHAIN_DIR: &str = "on-chain";
pub const OFF_CHAIN_DIR: &str = "off-chain";
pub const PUBLIC_ACCOUNT_FILE: &str = "public_account.json";
pub const SECRET_ACCOUNT_FILE: &str = "secret_account.json";

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
    serde_json::to_writer(file, &data).map_err(|error| Error::FileWriteError {
        error,
        path: file_path,
    })?;

    Ok(())
}

pub fn remove_file(
    db_dir: PathBuf,
    on_off_chain: &str,
    user: &str,
    file_name: &str,
) -> Result<(), Error> {
    let mut file_path = db_dir;
    file_path.push(on_off_chain);
    file_path.push(user);
    file_path.push(file_name);
    std::fs::remove_file(file_path.clone()).map_err(|error| Error::FileRemovalError {
        error,
        path: file_path,
    })?;
    Ok(())
}

pub fn get_asset_ids() -> Vec<Scalar> {
    let valid_asset_ids = vec!["poly", "acme"]; // TODO make this configurable
    let valid_asset_ids: Vec<AssetId> = valid_asset_ids
        .into_iter()
        .map(|asset_id| AssetId::try_from(String::from(asset_id)).unwrap())
        .collect();
    convert_asset_ids(valid_asset_ids)
}
