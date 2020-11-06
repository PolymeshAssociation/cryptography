//! A simple commandline application to act as a MERCAT Validator.
//! Use `mercat_validator --help` to see the usage.

mod input;
use env_logger;
use input::parse_input;
use log::info;
use mercat_common::{errors::Error, init_print_logger, validate::validate_all_pending};
use metrics::timing;
use std::time::Instant;

fn main() {
    env_logger::init();
    info!("Starting the program.");
    init_print_logger();

    let parse_arg_timer = Instant::now();
    let args = parse_input().unwrap();
    timing!("validator.argument_parse", parse_arg_timer, Instant::now());
    validate_all_pending(args.db_dir.ok_or(Error::EmptyDatabaseDir).unwrap()).unwrap();
    info!("The program finished successfully.");
}
