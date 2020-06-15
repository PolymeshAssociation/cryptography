mod input;

use env_logger;
use input::parse_input;
use log::{debug, info};
use mercat_common::init_print_logger;
//use metrics::{counter, timing};

fn main() {
    info!("Starting the program.");
    env_logger::init();
    init_print_logger();

    let cfg = parse_input().unwrap();
    debug!("{:#?}", cfg);
}
