use confy;
use log::info;
use mercat_common::{gen_seed, save_config};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(Clone, Debug, Serialize, Deserialize, StructOpt)]
pub struct CreateAccountInfo {
    /// The name of the user. The name can be any valid string that can be used as a file name.
    /// It is the responsibility of the caller to ensure the uniqueness of the name.
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

    /// Account id. It is the responsibility of the caller to ensure the uniqueness of the id.
    /// The CLI will not throw any errors if a duplicate id is passed.
    #[structopt(
        short,
        long,
        help = "The id of the account. This value must be unique."
    )]
    pub account_id: u32,

    /// Asset id. An asset ticker name which is a string of at most 12 characters.
    #[structopt(
        short,
        long,
        help = "The asset ticker id. String of at most 12 characters."
    )]
    pub ticker_id: String,

    /// An optional seed, to feed to the RNG, that can be passed to reproduce a previous run of this CLI.
    /// The seed can be found inside the logs.
    #[structopt(
        long,
        help = "Base64 encoding of an initial seed for the RNG. If not provided, the seed will be chosen at random."
    )]
    pub seed: Option<String>,

    /// An optional path to save the config used for this experiment.
    #[structopt(
        parse(from_os_str),
        long,
        help = "Path to save the input command line arguments as a config file."
    )]
    pub save_config: Option<PathBuf>,
}

#[derive(Clone, Debug, Serialize, Deserialize, StructOpt)]
pub struct IssueAssetInfo {
    /// Account ID of the issuer.
    /// The CLI will not throw any errors if a duplicate id is passed.
    #[structopt(long, help = "The account ID.")]
    pub account_id: u32,

    /// A transaction ID for the asset issuance transaction.
    /// The CLI will not throw any errors if a duplicate id is passed.
    /// It will silently overwrite the transaction.
    #[structopt(long, help = "The transaction ID.")]
    pub tx_id: u32,

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

    /// The transaction mediator's name. Used to retrieve mediator's public keys.
    /// Use `mercat-mediator` CLI to create the credentials needed for this role.
    #[structopt(short, long, help = "The name of the mediator.")]
    pub mediator: String,

    /// An optional path to save the config used for this experiment.
    #[structopt(
        parse(from_os_str),
        long,
        help = "Path to save the input command line arguments as a config file."
    )]
    pub save_config: Option<PathBuf>,
}

#[derive(Clone, Debug, Serialize, Deserialize, StructOpt)]
pub struct CreateTransactionInfo {
    /// Account ID of the sender.
    /// The CLI will not throw any errors if a duplicate id is passed.
    #[structopt(long, help = "The sender's account ID.")]
    pub account_id: u32,

    /// A transaction ID for the transaction.
    /// The CLI will not throw any errors if a duplicate id is passed.
    /// It will silently overwrite the transaction.
    #[structopt(long, help = "The transaction ID.")]
    pub tx_id: u32,

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

    /// The receiver's name. An account must have already been created for this user.
    #[structopt(short, long, help = "The sender's name.")]
    pub receiver: String,

    /// The transaction mediator's name. Used to retrieve mediator's public keys.
    /// Use `mercat-mediator` CLI to create the credentials needed for this role.
    #[structopt(short, long, help = "The mediator's name.")]
    pub mediator: String,

    /// An optional path to save the config used for this experiment.
    #[structopt(
        parse(from_os_str),
        long,
        help = "Path to save the input command line arguments as a config file."
    )]
    pub save_config: Option<PathBuf>,
}

#[derive(Clone, Debug, Serialize, Deserialize, StructOpt)]
pub struct FinalizeTransactionInfo {
    /// The transaction ID for the transaction.
    /// The CLI will not throw any errors if a duplicate id is passed.
    /// It will silently overwrite the transaction.
    #[structopt(long, help = "The transaction ID.")]
    pub tx_id: u32,

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

    // todo if we put the tx on chain, we won't need sender here.
    /// The sender's name. An account must have already been created for this user.
    #[structopt(long, help = "The sender's name.")]
    pub sender: String,

    /// The receiver's name. An account must have already been created for this user.
    #[structopt(short, long, help = "The sender's name.")]
    pub receiver: String,

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
    /// Create a MERCAT account using command line arguments.
    Create(CreateAccountInfo),

    /// Create a MERCAT account from a config file.
    CreateFrom {
        /// The path to the config file. This is a positional argument.
        config: PathBuf,
    },

    /// Remove a previously generated MERCAT account.
    Cleanup {
        /// The name of the user whose account will be removed.
        #[structopt(short, long, help = "The name of the user.")]
        user: String,

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
        db_dir: Option<PathBuf>,
    },

    /// Issue an asset to a MERCAT account.
    Issue(IssueAssetInfo),

    /// Create a MERCAT transaction.
    CreateTransaction(CreateTransactionInfo),

    /// Finalize a MERCAT transaction.
    FinalizeTransaction(FinalizeTransactionInfo),
}

pub fn parse_input() -> Result<CLI, confy::ConfyError> {
    info!("Parsing input configuration.");
    let args: CLI = CLI::from_args();

    match args {
        CLI::Create(cfg) => {
            let db_dir = cfg.db_dir.clone().or_else(|| std::env::current_dir().ok());

            let seed: Option<String> = cfg.seed.clone().or_else(|| Some(gen_seed()));
            info!("Seed: {:?}", seed.clone().unwrap()); // unwrap won't panic

            let cfg = CreateAccountInfo {
                save_config: cfg.save_config.clone(),
                seed,
                account_id: cfg.account_id,
                ticker_id: cfg.ticker_id,
                db_dir,
                user: cfg.user.clone(),
            };

            info!(
                "Parsed the following config from the command line:\n{:#?}",
                cfg.clone()
            );

            // Save the config if the argument is passed.
            save_config(cfg.save_config.clone(), &cfg);

            return Ok(CLI::Create(cfg));
        }

        CLI::CreateFrom { config } => {
            let json_file_content = std::fs::read_to_string(&config).expect(&format!(
                "Failed to read the account config from file: {:?}.",
                config
            ));

            let cfg = serde_json::from_str(&json_file_content).unwrap_or_else(|error| {
                panic!("Failed to deserialize the account config: {}", error)
            });

            info!("Read the following config from {:?}:\n{:#?}", &config, &cfg);
            return Ok(CLI::Create(cfg));
        }

        CLI::Cleanup { user, db_dir } => {
            // Set the default directory for db_dir
            let db_dir = db_dir.clone().or_else(|| std::env::current_dir().ok());
            let args = CLI::Cleanup {
                user: user.clone(),
                db_dir,
            };
            info!(
                "Parsed the following config from the command line:\n{:#?}",
                args
            );
            return Ok(args);
        }

        CLI::Issue(cfg) => {
            let db_dir = cfg.db_dir.clone().or_else(|| std::env::current_dir().ok());

            let seed: Option<String> = cfg.seed.clone().or_else(|| Some(gen_seed()));
            info!("Seed: {:?}", seed.clone().unwrap()); // unwrap won't panic

            let cfg = IssueAssetInfo {
                account_id: cfg.account_id,
                tx_id: cfg.tx_id,
                seed,
                amount: cfg.amount,
                db_dir,
                issuer: cfg.issuer,
                mediator: cfg.mediator,
                save_config: cfg.save_config.clone(),
            };

            info!(
                "Parsed the following config from the command line:\n{:#?}",
                cfg.clone()
            );

            // Save the config if the argument is passed.
            save_config(cfg.save_config.clone(), &cfg);

            return Ok(CLI::Issue(cfg));
        }

        CLI::CreateTransaction(cfg) => {
            let db_dir = cfg.db_dir.clone().or_else(|| std::env::current_dir().ok());

            let seed: Option<String> = cfg.seed.clone().or_else(|| Some(gen_seed()));
            info!("Seed: {:?}", seed.clone().unwrap());

            let cfg = CreateTransactionInfo {
                account_id: cfg.account_id,
                tx_id: cfg.tx_id,
                seed,
                amount: cfg.amount,
                db_dir,
                sender: cfg.sender,
                receiver: cfg.receiver,
                mediator: cfg.mediator,
                save_config: cfg.save_config.clone(),
            };

            info!(
                "Parsed the following config from the command line:\n{:#?}",
                cfg.clone()
            );

            // Save the config if the argument is passed.
            save_config(cfg.save_config.clone(), &cfg);

            return Ok(CLI::CreateTransaction(cfg));
        }

        CLI::FinalizeTransaction(cfg) => {
            let db_dir = cfg.db_dir.clone().or_else(|| std::env::current_dir().ok());

            let seed: Option<String> = cfg.seed.clone().or_else(|| Some(gen_seed()));
            info!("Seed: {:?}", seed.clone().unwrap());

            let cfg = FinalizeTransactionInfo {
                tx_id: cfg.tx_id,
                seed,
                amount: cfg.amount,
                db_dir,
                sender: cfg.sender,
                receiver: cfg.receiver,
                save_config: cfg.save_config.clone(),
            };

            info!(
                "Parsed the following config from the command line:\n{:#?}",
                cfg.clone()
            );

            // Save the config if the argument is passed.
            save_config(cfg.save_config.clone(), &cfg);

            return Ok(CLI::FinalizeTransaction(cfg));
        }
    }
}
