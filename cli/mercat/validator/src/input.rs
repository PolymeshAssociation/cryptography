use confy;
use log::info;
use mercat_common::save_config;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(StructOpt, Debug, Serialize, Deserialize, Clone)]
pub struct ValidateAssetIssuanceInfo {
    /// The directory that will serve as the database of the on/off-chain data and will be used
    /// to save and load the data that in a real execution would be written to the on/off the
    /// blockchain. Defaults to the current directory. This directory will have two main
    /// sub-directories: `on-chain` and `off-chain`.
    #[structopt(
        parse(from_os_str),
        help = "The directory to load and save the input and output files. Defaults to current directory.",
        short,
        long
    )]
    pub db_dir: Option<PathBuf>,

    /// Account ID of the issuer.
    /// In the CLI, we use the ticker name as the unique account id of each party.
    #[structopt(long, help = "The issuer's account ID.")]
    pub account_id: String,

    /// The name of the mediator.
    #[structopt(short, long, help = "The mediator's name.")]
    pub mediator: String,

    /// The name of the issuer.
    #[structopt(short, long, help = "The name of the asset issuer.")]
    pub issuer: String,

    /// The transaction ID.
    /// This ID must be the same as the one used to create the transaction.
    #[structopt(long, help = "The id of the transaction.")]
    pub tx_id: u32,

    /// The state of the transaction to validate.{n}
    /// Must be one of `initialization_started` or `justification_started`.
    #[structopt(
        short,
        long,
        help = "The transaction state. Must be one of `initialization_started` or `justification_started`."
    )]
    pub state: String,

    /// An optional path to save the config used for this experiment.
    #[structopt(
        parse(from_os_str),
        long,
        help = "Path to save the input command line arguments as a config file."
    )]
    pub save_config: Option<PathBuf>,
}

#[derive(StructOpt, Debug, Serialize, Deserialize, Clone)]
pub struct AccountCreationInfo {
    /// The directory that will serve as the database of the on/off-chain data and will be used
    /// to save and load the data that in a real execution would be written to the on/off the
    /// blockchain. Defaults to the current directory. This directory will have two main
    /// sub-directories: `on-chain` and `off-chain`.
    #[structopt(
        parse(from_os_str),
        help = "The directory to load and save the input and output files. Defaults to current directory.",
        short,
        long
    )]
    pub db_dir: Option<PathBuf>,

    /// The name of the account user.
    #[structopt(short, long, help = "The name of the user.")]
    pub user: String,

    /// The ticker name for the account.
    #[structopt(short, long, help = "The ticker name for the account.")]
    pub ticker: String,

    /// An optional path to save the config used for this experiment.
    #[structopt(
        parse(from_os_str),
        long,
        help = "Path to save the input command line arguments as a config file."
    )]
    pub save_config: Option<PathBuf>,
}

#[derive(StructOpt, Debug, Serialize, Deserialize, Clone)]
pub struct ValidateTransactionInfo {
    /// The directory that will serve as the database of the on/off-chain data and will be used
    /// to save and load the data that in a real execution would be written to the on/off the
    /// blockchain. Defaults to the current directory. This directory will have two main
    /// sub-directories: `on-chain` and `off-chain`.
    #[structopt(
        parse(from_os_str),
        help = "The directory to load and save the input and output files. Defaults to current directory.",
        short,
        long
    )]
    pub db_dir: Option<PathBuf>,

    /// Account ID of the issuer.
    /// In the CLI, we use the ticker name as the unique account id of each party.
    #[structopt(long, help = "The issuer's account ID.")]
    pub account_id: String,

    /// The name of the mediator.
    #[structopt(short, long, help = "The mediator's name.")]
    pub mediator: String,

    /// The name of the sender.
    #[structopt(long, help = "The name of the sender.")]
    pub sender: String,

    /// The name of the receiver.
    #[structopt(short, long, help = "The name of the receiver.")]
    pub receiver: String,

    /// The transaction ID.
    /// This ID must be the same as the one used to create the transaction.
    #[structopt(long, help = "The id of the transaction.")]
    pub tx_id: u32,

    /// The state of the transaction to validate.{n}
    /// Must be one of `initialization_started`, `finalization_started`, or `finalization_justification_started`.
    #[structopt(
        long,
        help = "The transaction state. Must be one of `initialization_started`, `Finalization_started`, or `finalization_justification_started`."
    )]
    pub state: String,

    /// An optional path to save the config used for this experiment.
    #[structopt(
        parse(from_os_str),
        long,
        help = "Path to save the input command line arguments as a config file."
    )]
    pub save_config: Option<PathBuf>,
}

#[derive(Clone, Debug, Serialize, Deserialize, StructOpt)]
pub enum CLI {
    /// Validate an asset issuance transaction.
    ValidateIssuance(ValidateAssetIssuanceInfo),

    /// Validate an account creation transaction.
    ValidateAccount(AccountCreationInfo),

    /// Validate an initialized transaction.
    ValidateTransaction(ValidateTransactionInfo),
}

pub fn parse_input() -> Result<CLI, confy::ConfyError> {
    info!("Parsing input configuration.");
    let args: CLI = CLI::from_args();

    match args {
        CLI::ValidateIssuance(cfg) => {
            // Set the default db_dir if needed.
            let db_dir = cfg.db_dir.clone().or_else(|| std::env::current_dir().ok());

            let cfg = ValidateAssetIssuanceInfo {
                db_dir,
                account_id: cfg.account_id,
                mediator: cfg.mediator,
                issuer: cfg.issuer,
                tx_id: cfg.tx_id,
                state: cfg.state,
                save_config: cfg.save_config,
            };

            info!(
                "Parsed the following config from the command line:\n{:#?}",
                cfg.clone()
            );

            // Save the config if the argument is passed.
            save_config(cfg.save_config.clone(), &cfg);

            return Ok(CLI::ValidateIssuance(cfg));
        }

        CLI::ValidateAccount(cfg) => return Ok(CLI::ValidateAccount(cfg)),

        CLI::ValidateTransaction(cfg) => {
            // Set the default db_dir if needed.
            let db_dir = cfg.db_dir.clone().or_else(|| std::env::current_dir().ok());

            let cfg = ValidateTransactionInfo {
                db_dir,
                account_id: cfg.account_id,
                mediator: cfg.mediator,
                sender: cfg.sender,
                receiver: cfg.receiver,
                tx_id: cfg.tx_id,
                state: cfg.state,
                save_config: cfg.save_config,
            };

            info!(
                "Parsed the following config from the command line:\n{:#?}",
                cfg.clone()
            );

            // Save the config if the argument is passed.
            save_config(cfg.save_config.clone(), &cfg);

            return Ok(CLI::ValidateTransaction(cfg));
        }
    }
}
