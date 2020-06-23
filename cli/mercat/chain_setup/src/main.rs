mod input;

use env_logger;
use input::parse_input;
use log::info;
use mercat_common::{chain_setup::process_asset_id_creation, errors::Error, init_print_logger};
use metrics::timing;
use std::time::Instant;

fn main() {
    info!("Starting the program.");
    env_logger::init();
    init_print_logger();

    let start = Instant::now();
    let args = parse_input().unwrap();
    timing!("chain_setup.argument_parse", start, Instant::now());

    let db_dir = args.db_dir.ok_or(Error::EmptyDatabaseDir).unwrap();
    process_asset_id_creation(db_dir, args.ticker_names).unwrap();
    info!("The program finished successfully.");
}
