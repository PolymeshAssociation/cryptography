mod input;

use cryptography::{mercat::account::convert_asset_ids, AssetId};
use env_logger;
use input::parse_input;
use log::info;
use mercat_common::{
    errors::Error, init_print_logger, save_to_file, AssetIdList, ASSET_ID_LIST_FILE,
    COMMON_OBJECTS_DIR, ON_CHAIN_DIR,
};
use metrics::timing;
use std::{convert::TryFrom, path::PathBuf, time::Instant};

fn main() {
    info!("Starting the program.");
    env_logger::init();
    init_print_logger();

    let start = Instant::now();
    let args = parse_input().unwrap();
    timing!("global.argument_parse", start, Instant::now());

    process_asset_id_creation(args.db_dir, args.ticker_names).unwrap();
    info!("The program finished successfully.");
}

fn process_asset_id_creation(
    db_dir: Option<PathBuf>,
    ticker_names: Vec<String>,
) -> Result<(), Error> {
    let start = Instant::now();

    let valid_asset_ids: Vec<AssetId> = ticker_names
        .into_iter()
        .map(|ticker_name| {
            AssetId::try_from(ticker_name).map_err(|error| Error::LibraryError { error })
        })
        .collect::<Result<Vec<AssetId>, Error>>()?;

    let valid_asset_ids = AssetIdList(convert_asset_ids(valid_asset_ids));

    let db_dir = db_dir.ok_or(Error::EmptyDatabaseDir)?;
    save_to_file(
        db_dir,
        ON_CHAIN_DIR,
        COMMON_OBJECTS_DIR,
        ASSET_ID_LIST_FILE,
        &valid_asset_ids,
    )?;

    timing!("global.gen_and_save_asset_id_list", start, Instant::now());

    Ok(())
}
