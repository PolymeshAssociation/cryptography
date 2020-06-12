use confy;
use log::info;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use structopt::StructOpt;

/// mercat_issuer -- a confidential asset issuer.{n}
/// todo The mercat_issuer utility (optionally) creates a random claim and proves it.
#[derive(StructOpt, Debug, Serialize, Deserialize, Clone)]
pub struct AssetIssuanceInfo {
    /// The directory that will serve as the database of the on/off-chain data and will be used
    /// to save and load the data that in a real execution would be written to the on/off the
    /// blockchain. Defaults to the current directory. This directory will have two main
    /// sub-directories: `on-chain` and `off-chain`
    #[structopt(
        parse(from_os_str),
        help = "The directory to load and save the input and output files. Defaults to current directory.",
        short,
        long
    )]
    pub db_dir: PathBuf,

    // /// Get the Json formatted instruction from file.
    #[structopt(short, long, help = "The name of the user. This name must be unique.")]
    pub mediator: String,

    #[structopt(long, help = "The id of the transaction. This value must be unique.")]
    pub tx_id: u32,

    /// The name of the user. The name can be any valid string that can be used as a file name.
    /// It is the responsibility of the caller to ensure the uniqueness of the name.
    #[structopt(short, long, help = "The name of the user. This name must be unique.")]
    pub issuer: String,

    // todo: can I use an enum in the structopt?
    #[structopt(short, long, help = "The name of the user. This name must be unique.")]
    pub state: String,
}

#[derive(StructOpt, Debug, Serialize, Deserialize, Clone)]
pub struct AccountCreationInfo {
    /// The directory that will serve as the database of the on/off-chain data and will be used
    /// to save and load the data that in a real execution would be written to the on/off the
    /// blockchain. Defaults to the current directory. This directory will have two main
    /// sub-directories: `on-chain` and `off-chain`
    #[structopt(
        parse(from_os_str),
        help = "The directory to load and save the input and output files. Defaults to current directory.",
        short,
        long
    )]
    pub db_dir: PathBuf,

    // /// Get the Json formatted instruction from file.
    #[structopt(short, long, help = "The name of the user. This name must be unique.")]
    pub user: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, StructOpt)]
pub enum CLI {
    /// Create a MERCAT account memo
    ValidateIssuance(AssetIssuanceInfo),
    ValidateAccount(AccountCreationInfo),
}

pub fn parse_input() -> Result<CLI, confy::ConfyError> {
    info!("Parsing input configuration.");
    let args: CLI = CLI::from_args();

    match args {
        CLI::ValidateIssuance(cfg) => {
            // Otherwise, set the default seed and db_dir if needed
            // let db_dir = cfg.db_dir.clone().or_else(|| std::env::current_dir().ok());

            // let cfg = AssetIssuanceInfo {
            //     db_dir,
            //     user: cfg.user.clone(),
            // };

            info!(
                "Parsed the following config from the command line:\n{:#?}",
                cfg
            );

            // Save the config is the argument is passed
            // if let Some(path) = &cfg.save_config {
            //     info!("Saving the following config to {:?}:\n{:#?}", &path, &cfg);
            //     std::fs::write(
            //         path,
            //         serde_json::to_string_pretty(&cfg).unwrap_or_else(|error| {
            //             panic!("Failed to serialize configuration file: {}", error)
            //         }),
            //     )
            //     .expect(&format!(
            //         "Failed to write the configuration to the file {:?}.",
            //         path
            //     ));
            // }

            return Ok(CLI::ValidateIssuance(cfg));
        }
        CLI::ValidateAccount(cfg) => return Ok(CLI::ValidateAccount(cfg)),
    }
}
