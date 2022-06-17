use crate::{
    errors::Error, save_to_file, AssetIdList, ASSET_ID_LIST_FILE, COMMON_OBJECTS_DIR, ON_CHAIN_DIR,
};
use confidential_identity_core::asset_proofs::{asset_id_from_ticker, AssetId};
use mercat::account::convert_asset_ids;
use metrics::timing;
use std::{path::PathBuf, time::Instant};

pub fn process_asset_id_creation(db_dir: PathBuf, ticker_names: Vec<String>) -> Result<(), Error> {
    let start = Instant::now();

    let valid_asset_ids: Vec<AssetId> = ticker_names
        .into_iter()
        .map(|ticker_name| {
            asset_id_from_ticker(&ticker_name).map_err(|error| Error::LibraryError { error })
        })
        .collect::<Result<Vec<AssetId>, Error>>()?;

    let valid_asset_ids = AssetIdList(convert_asset_ids(valid_asset_ids));

    save_to_file(
        db_dir,
        ON_CHAIN_DIR,
        COMMON_OBJECTS_DIR,
        ASSET_ID_LIST_FILE,
        &valid_asset_ids,
    )?;

    timing!(
        "chain_setup.gen_and_save_asset_id_list",
        start,
        Instant::now()
    );

    Ok(())
}
