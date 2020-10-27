use log::info;
use mercat_common::gen_seed;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(Clone, Debug, Serialize, Deserialize, StructOpt)]
pub struct CreateUserAccountInfo {
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

    /// The name of the user. The name can be any valid string that can be used as a file name.
    /// It is the responsibility of the caller to ensure the uniqueness of the name.
    #[structopt(short, long, help = "The name of the user. This name must be unique.")]
    pub user: String,

    /// An asset ticker name which is a string of at most 12 characters.
    /// In these test CLIs, the unique account id is created from the pair of username and ticker.
    #[structopt(
        short,
        long,
        help = "The asset ticker name. String of at most 12 characters."
    )]
    pub ticker: String,

    /// An optional seed, to feed to the RNG, that can be passed to reproduce a previous run of this CLI.
    /// The seed can be found inside the logs.
    #[structopt(
        long,
        help = "Base64 encoding of an initial seed for the RNG. If not provided, the seed will be chosen at random."
    )]
    pub seed: Option<String>,

    /// Space separated list of ticker names.
    #[structopt(short, long, help = "Space separated list of a ticker names.")]
    pub valid_ticker_names: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, StructOpt)]
pub struct CreateMediatorAccountInfo {
    /// The name of the mediator.
    /// It is the responsibility of the caller to ensure this name is unique.
    /// If it is not unique the artifacts will be overwritten.
    #[structopt(
        short,
        long,
        help = "The name of the mediator. This name must be unique."
    )]
    pub user: String,

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

    /// An optional seed, to feed to the RNG, that can be passed to reproduce a previous run of this CLI.
    /// The seed can be found inside the logs.
    #[structopt(
        short,
        long,
        help = "Base64 encoding of an initial seed for the RNG. If not provided, the seed will be chosen at random."
    )]
    pub seed: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, StructOpt)]
pub struct IssueAssetInfo {
    /// Account ID of the issuer will be generated from the username and ticker name pair.
    #[structopt(
        long,
        help = "The ticker name that will be used to generate the unique account id of the user."
    )]
    pub account_id_from_ticker: String,

    /// An optional seed, to feed to the RNG, that can be passed to reproduce a previous run of this CLI.
    /// The seed can be found inside the logs.
    #[structopt(
        long,
        help = "Base64 encoding of an initial seed for the RNG. If not provided, the seed will be chosen at random."
    )]
    pub seed: Option<String>,

    /// Amount to issue.
    #[structopt(short, long, help = "The amount of assets to issue.")]
    pub amount: u32,

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

    /// The issuer's name. An account must have already been created for this user.
    #[structopt(short, long, help = "The name of the issuer.")]
    pub issuer: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, StructOpt)]
pub struct CreateTransactionInfo {
    /// Account ID of the issuer will be generated from the username and ticker name pair.
    #[structopt(
        long,
        help = "The ticker name that will be used to generate the unique account id of the user."
    )]
    pub account_id_from_ticker: String,

    /// An optional seed, to feed to the RNG, that can be passed to reproduce a previous run of this CLI.
    /// The seed can be found inside the logs.
    #[structopt(
        long,
        help = "Base64 encoding of an initial seed for the RNG. If not provided, the seed will be chosen at random."
    )]
    pub seed: Option<String>,

    /// Amount to transfer.
    #[structopt(short, long, help = "The amount of assets to transfer.")]
    pub amount: u32,

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

    /// The sender's name. An account must have already been created for this user.
    #[structopt(long, help = "The sender's name.")]
    pub sender: String,

    /// The receiver's base64 public account.
    #[structopt(
        short,
        long,
        help = "The receiver's base64 public account (encrypted asset id, followed by encryption public key)."
    )]
    pub receiver: Vec<String>,

    /// The mediator's base64 public encryption key.
    #[structopt(short, long, help = "The mediator's base64 public encryption key.")]
    pub mediator: String,

    /// The sender's base64 pending balance.
    #[structopt(short, long, help = "The sender's base64 pending balance.")]
    pub pending_balance: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, StructOpt)]
pub struct FinalizeTransactionInfo {
    /// Account ID of the receiver will be generated from the username and ticker name pair.
    #[structopt(
        long,
        help = "The ticker name that will be used to generate the unique account id of the user."
    )]
    pub account_id_from_ticker: String,

    /// An optional seed, to feed to the RNG, that can be passed to reproduce a previous run of this CLI.
    /// The seed can be found inside the logs.
    #[structopt(
        long,
        help = "Base64 encoding of an initial seed for the RNG. If not provided, the seed will be chosen at random."
    )]
    pub seed: Option<String>,

    /// The expected amount to receive.
    #[structopt(short, long, help = "The expected amount to receive.")]
    pub amount: u32,

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

    /// The receiver's name. An account must have already been created for this user.
    #[structopt(short, long, help = "The sender's name.")]
    pub receiver: String,

    /// The initial transaction as base64 encoded string.
    #[structopt(
        short,
        long,
        help = "The initial transaction as base64 encoded string."
    )]
    pub init_tx: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, StructOpt)]
pub struct JustifyTransferInfo {
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

    /// Asset id that is transferred.
    /// An asset ticker name which is a string of at most 12 characters.
    #[structopt(
        short,
        long,
        help = "The asset ticker name. String of at most 12 characters."
    )]
    pub ticker: String,

    /// The sender's base64 public account (encrypted asset id, followed by encryption public key).
    #[structopt(
        long,
        help = "The sender's base64 public account (encrypted asset id, followed by encryption public key)."
    )]
    pub sender: Vec<String>,

    /// The sender's base64 balance.
    #[structopt(long, help = "The sender's base64 balance.")]
    pub sender_balance: String,

    /// The receiver's base64 public account (encrypted asset id, followed by encryption public key).
    #[structopt(
        long,
        help = "The receiver's base64 public account (encrypted asset id, followed by encryption public key)."
    )]
    pub receiver: Vec<String>,

    /// The name of the mediator.
    #[structopt(short, long, help = "The name of the mediator.")]
    pub mediator: String,

    /// An optional seed, to feed to the RNG, that can be passed to reproduce a previous run of this CLI.
    /// The seed can be found inside the logs.
    #[structopt(
        short,
        long,
        help = "Base64 encoding of an initial seed for the RNG. If not provided, the seed will be chosen at random."
    )]
    pub seed: Option<String>,

    /// Finalized tx as base64.
    #[structopt(short, long, help = "Finalized tx as base64.")]
    pub finalized_tx: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, StructOpt)]
pub struct DecryptAccountInfo {
    /// The name of the user. The name can be any valid string that can be used as a file name.
    #[structopt(short, long, help = "The name of the user. This name must be unique.")]
    pub user: String,

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

    /// An asset ticker name which is a string of at most 12 characters.
    /// In these test CLIs, the unique account id is created from the pair of username and ticker.
    #[structopt(
        short,
        long,
        help = "The asset ticker name. String of at most 12 characters."
    )]
    pub ticker: String,

    /// An encrypted value as base64.
    #[structopt(short, long, help = "An encrypted value as base64.")]
    pub encrypted_value: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, StructOpt)]
pub enum CLI {
    CreateUserAccount(CreateUserAccountInfo),
    CreateMediatorAccount(CreateMediatorAccountInfo),
    Mint(IssueAssetInfo),
    CreateTransaction(CreateTransactionInfo),
    FinalizeTransaction(FinalizeTransactionInfo),
    JustifyTransaction(JustifyTransferInfo),
    Decrypt(DecryptAccountInfo),
}

pub fn parse_input() -> CLI {
    info!("Parsing input configuration.");
    let args: CLI = CLI::from_args();

    match args {
        CLI::CreateUserAccount(cfg) => {
            let seed: Option<String> = cfg.seed.clone().or_else(|| Some(gen_seed()));
            info!("Seed: {:?}", seed.clone().unwrap()); // unwrap won't panic

            let cfg = CreateUserAccountInfo {
                seed,
                user: cfg.user,
                db_dir: cfg.db_dir,
                ticker: cfg.ticker,
                valid_ticker_names: cfg.valid_ticker_names,
            };

            info!(
                "Parsed the following config from the command line:\n{:#?}",
                cfg.clone()
            );

            return CLI::CreateUserAccount(cfg);
        }

        CLI::CreateMediatorAccount(cfg) => {
            // Set the default seed and db_dir if needed.
            let db_dir = cfg.db_dir.clone().or_else(|| std::env::current_dir().ok());

            let seed: Option<String> = cfg.seed.clone().or_else(|| Some(gen_seed()));
            info!("Seed: {:?}", seed.clone().unwrap());

            let cfg = CreateMediatorAccountInfo {
                seed,
                db_dir,
                user: cfg.user.clone(),
            };

            info!(
                "Parsed the following config from the command line:\n{:#?}",
                cfg
            );

            return CLI::CreateMediatorAccount(cfg);
        }

        CLI::Mint(cfg) => {
            let db_dir = cfg.db_dir.clone().or_else(|| std::env::current_dir().ok());

            let seed: Option<String> = cfg.seed.clone().or_else(|| Some(gen_seed()));
            info!("Seed: {:?}", seed.clone().unwrap()); // unwrap won't panic

            let cfg = IssueAssetInfo {
                account_id_from_ticker: cfg.account_id_from_ticker,
                seed,
                amount: cfg.amount,
                db_dir,
                issuer: cfg.issuer,
            };

            info!(
                "Parsed the following config from the command line:\n{:#?}",
                cfg
            );

            return CLI::Mint(cfg);
        }
        CLI::CreateTransaction(cfg) => {
            let db_dir = cfg.db_dir.clone().or_else(|| std::env::current_dir().ok());

            let seed: Option<String> = cfg.seed.clone().or_else(|| Some(gen_seed()));
            info!("Seed: {:?}", seed.clone().unwrap());

            let cfg = CreateTransactionInfo {
                account_id_from_ticker: cfg.account_id_from_ticker,
                seed,
                amount: cfg.amount,
                db_dir,
                sender: cfg.sender,
                receiver: cfg.receiver,
                mediator: cfg.mediator,
                pending_balance: cfg.pending_balance,
            };

            info!(
                "Parsed the following config from the command line:\n{:#?}",
                cfg.clone()
            );

            return CLI::CreateTransaction(cfg);
        }
        CLI::FinalizeTransaction(cfg) => {
            let db_dir = cfg.db_dir.clone().or_else(|| std::env::current_dir().ok());

            let seed: Option<String> = cfg.seed.clone().or_else(|| Some(gen_seed()));
            info!("Seed: {:?}", seed.clone().unwrap());

            let cfg = FinalizeTransactionInfo {
                account_id_from_ticker: cfg.account_id_from_ticker,
                seed,
                amount: cfg.amount,
                db_dir,
                receiver: cfg.receiver,
                init_tx: cfg.init_tx,
            };

            info!(
                "Parsed the following config from the command line:\n{:#?}",
                cfg.clone()
            );

            return CLI::FinalizeTransaction(cfg);
        }
        CLI::JustifyTransaction(cfg) => {
            // Set the default seed and db_dir if needed.
            let db_dir = cfg.db_dir.clone().or_else(|| std::env::current_dir().ok());

            let seed: Option<String> = cfg.seed.clone().or_else(|| Some(gen_seed()));
            info!("Seed: {:?}", seed.clone().unwrap());
            let cfg = JustifyTransferInfo {
                db_dir,
                ticker: cfg.ticker,
                sender: cfg.sender,
                sender_balance: cfg.sender_balance,
                receiver: cfg.receiver,
                mediator: cfg.mediator,
                seed,
                finalized_tx: cfg.finalized_tx,
            };

            info!(
                "Parsed the following config from the command line:\n{:#?}",
                cfg.clone()
            );

            return CLI::JustifyTransaction(cfg);
        }
        CLI::Decrypt(cfg) => {
            let db_dir = cfg.db_dir.clone().or_else(|| std::env::current_dir().ok());

            let cfg = DecryptAccountInfo {
                ticker: cfg.ticker,
                db_dir,
                user: cfg.user.clone(),
                encrypted_value: cfg.encrypted_value,
            };

            info!(
                "Parsed the following config from the command line:\n{:#?}",
                cfg.clone()
            );

            return CLI::Decrypt(cfg);
        }
    }
}
