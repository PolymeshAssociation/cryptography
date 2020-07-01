use crate::{
    chain_setup::process_asset_id_creation,
    create_account::process_create_account,
    create_rng_from_seed,
    errors::Error,
    gen_seed, gen_seed_from,
    issue_asset::process_issue_asset,
    justify::{justify_asset_issuance, justify_asset_transaction, process_create_mediator},
    load_object,
    transfer::{process_create_tx, process_finalize_tx},
    validate::{validate_account, validate_asset_issuance, validate_transaction},
    COMMON_OBJECTS_DIR, OFF_CHAIN_DIR, ON_CHAIN_DIR, PUBLIC_ACCOUNT_FILE, SECRET_ACCOUNT_FILE,
};
use cryptography::mercat::{Account, PubAccount, SecAccount};
use linked_hash_map::LinkedHashMap;
use log::info;
use rand::Rng;
use rand::{rngs::StdRng, SeedableRng};
use rand::{CryptoRng, RngCore};
use regex::Regex;
use std::path::PathBuf;
use std::{
    collections::HashSet,
    convert::{From, TryFrom},
    fs, io,
    time::Instant,
};
use yaml_rust::{Yaml, YamlLoader};

// --------------------------------------------------------------------------------------------------
// -                                       data types                                                -
// ---------------------------------------------------------------------------------------------------

/// The signature fo the function for a generic step in a transaction. This function performs
/// the action (e.g., initializing a transaction, finalizing a transaction, or creating an account),
/// and returns the corresponding CLI command that can be run to reproduce this step manually.
type StepFunc = Box<dyn Fn() -> String + 'static>;

/// Represents the three types of mercat transactions.
#[derive(Debug)]
pub enum Transaction {
    /// Transfer a balance from Alice to Bob, with some mediator and validator.
    Transfer(Transfer),
    /// Create an account for Alice for a ticker, with balance of zero.
    Create(Create),
    /// Issue tokens for an account (effectively funding an account).
    Issue(Issue),
}

/// A generic party, can be sender, receiver, or mediator.
#[derive(Debug)]
pub struct Party {
    pub name: String,
    pub cheater: bool,
}

impl TryFrom<&str> for Party {
    type Error = Error;
    fn try_from(segment: &str) -> Result<Self, Error> {
        // Example: alice or alice(cheat)
        let re = Regex::new(r"([a-zA-Z0-9]+)(\(cheat\))?").map_err(|_| Error::RegexError {
            reason: String::from("Failed to compile the Transfer regex"),
        })?;
        let caps = re.captures(segment).ok_or(Error::RegexError {
            reason: format!("Pattern did not match {}", segment),
        })?;
        let name = String::from(caps.get(1).unwrap().as_str());
        let cheater = caps.get(2).is_some();
        Ok(Self { name, cheater })
    }
}

// todo remove all unwraps

/// Data type of the transaction of transferring balance.
#[derive(Debug)]
pub struct Transfer {
    pub tx_id: u32,
    pub sender: Party,
    pub receiver: Party,
    pub receiver_approves: bool,
    pub mediator: Party,
    pub mediator_approves: bool,
    pub amount: u32,
    pub ticker: String,
}

impl TryFrom<(u32, String)> for Transfer {
    type Error = Error;
    fn try_from(pair: (u32, String)) -> Result<Self, Error> {
        let (tx_id, segment) = pair;
        // Example: Bob(cheat) 40 ACME Carol approve Marry reject
        let re = Regex::new(
            r"^([a-zA-Z0-9()]+) ([0-9]+) ([a-zA-Z0-9]+) ([a-zA-Z0-9()]+) (approve|reject) ([a-zA-Z0-9()]+) (approve|reject)$",
        )
        .map_err(|_| Error::RegexError {
            reason: String::from("Failed to compile the Transfer regex"),
        })?;
        let caps = re.captures(&segment).ok_or(Error::RegexError {
            reason: format!("Pattern did not match {}", segment),
        })?;
        Ok(Self {
            tx_id,
            sender: Party::try_from(caps.get(1).unwrap().as_str())?,
            receiver: Party::try_from(caps.get(4).unwrap().as_str())?,
            receiver_approves: caps.get(5).unwrap().as_str() == "approve",
            mediator: Party::try_from(caps.get(6).unwrap().as_str())?,
            mediator_approves: caps.get(7).unwrap().as_str() == "approve",
            amount: caps.get(2).unwrap().as_str().parse::<u32>().unwrap(),
            ticker: String::from(caps.get(3).unwrap().as_str()),
        })
    }
}

/// Data type of the transaction of creating empty account.
#[derive(Debug)]
pub struct Create {
    pub tx_id: u32,
    pub account_id: u32,
    pub owner: Party,
    pub ticker: Option<String>,
}

/// Data type of the transaction of funding an account by issuer.
#[derive(Debug)]
pub struct Issue {
    pub tx_id: u32,
    pub issuer: Party,
    pub mediator: Party,
    pub mediator_approves: bool,
    pub ticker: String,
    pub amount: u32,
}

impl TryFrom<(u32, String)> for Issue {
    type Error = Error;
    fn try_from(pair: (u32, String)) -> Result<Self, Error> {
        let (tx_id, segment) = pair;
        // Example: Bob(cheat) 40 ACME Carol approve Marry reject
        let re = Regex::new(
            r"^([a-zA-Z0-9()]+) ([0-9]+) ([a-zA-Z0-9]+) ([a-zA-Z0-9()]+) (approve|reject)$",
        )
        .map_err(|_| Error::RegexError {
            reason: String::from("Failed to compile the Issue regex"),
        })?;
        let caps = re.captures(&segment).ok_or(Error::RegexError {
            reason: format!("Pattern did not match {}", segment),
        })?;
        Ok(Self {
            tx_id,
            issuer: Party::try_from(caps.get(1).unwrap().as_str())?,
            mediator: Party::try_from(caps.get(4).unwrap().as_str())?,
            mediator_approves: caps.get(5).unwrap().as_str() == "approve",
            ticker: String::from(caps.get(3).unwrap().as_str()),
            amount: caps.get(2).unwrap().as_str().parse::<u32>().unwrap(),
        })
    }
}
/// Human readable form of a mercat account.
#[derive(PartialEq, Eq, Hash, Debug)]
pub struct InputAccount {
    owner: String,
    ticker: Option<String>,
    balance: u32,
}

/// Represents the various combinations of the transactions.
#[derive(Debug)]
pub enum TransactionMode {
    /// The transactions are run `repeat` number of times, and in each iteration, the
    /// steps of one transaction are done before the steps of the next transaction.
    Sequence {
        repeat: u32,
        steps: Vec<TransactionMode>,
    },
    /// The transactions are run `repeat` number of times, and in each iteration, the
    /// steps of the transactions are interleaved randomly.
    Concurrent {
        repeat: u32,
        steps: Vec<TransactionMode>,
    },
    Transaction(Transaction),
}

/// Represents a testcase that is read from the config file.
pub struct TestCase {
    /// Human readable description of the testcase. Will be printed to the log.
    title: String,
    /// The list of valid ticker names. This names will be converted to asset ids for meract.
    ticker_names: Vec<String>,
    ///// The initial list of accounts for each party.
    //// todo remove this
    //accounts: Vec<Account>,
    /// The transactions of this testcase.
    transactions: TransactionMode,
    /// The expected value of the accounts at the end of the scenario.
    accounts_outcome: HashSet<InputAccount>,
    /// Maximum allowable time in Milliseconds
    timing_limit: u128,
    /// the directory that will act as the chain datastore.
    chain_db_dir: PathBuf,
}

// --------------------------------------------------------------------------------------------------
// -                                  data type methods                                             -
// --------------------------------------------------------------------------------------------------

impl Transaction {
    fn order<T: RngCore + CryptoRng>(&self, rng: &mut T, chain_db_dir: PathBuf) -> Vec<StepFunc> {
        match self {
            Transaction::Issue(fund) => fund.order(rng, chain_db_dir.clone()),
            Transaction::Transfer(transfer) => transfer.order(rng, chain_db_dir.clone()),
            Transaction::Create(create) => create.order(rng, chain_db_dir),
        }
    }
}

impl Transfer {
    pub fn send<T: RngCore + CryptoRng>(&self, rng: &mut T, chain_db_dir: PathBuf) -> StepFunc {
        let seed = gen_seed_from(rng);
        let value = format!(
            "mercat-account create-transaction --account-id {} --amount {} --sender {} --receiver {} --mediator {} --tx-id {} --seed {} {}",
            self.ticker,
            self.amount,
            self.sender.name,
            self.receiver.name,
            self.mediator.name,
            self.tx_id,
            seed,
            cheater_flag(self.sender.cheater)
        );
        let ticker = self.ticker.clone();
        let sender = self.sender.name.clone();
        let receiver = self.receiver.name.clone();
        let mediator = self.mediator.name.clone();
        let amount = self.amount;
        let tx_id = self.tx_id;
        return Box::new(move || {
            process_create_tx(
                seed.clone(),
                chain_db_dir.clone(),
                sender.clone(),
                receiver.clone(),
                mediator.clone(),
                ticker.clone(),
                amount,
                tx_id,
            )
            .unwrap();
            value.clone()
        });
    }

    pub fn receive<T: RngCore + CryptoRng>(&self, rng: &mut T, chain_db_dir: PathBuf) -> StepFunc {
        let seed = gen_seed_from(rng);
        let value = format!(
            "mercat-account finalize-transaction --account-id {} --amount {} --sender {} --receiver {} --tx-id {} --seed {} {}",
            self.ticker,
            self.amount,
            self.sender.name,
            self.receiver.name,
            self.tx_id,
            seed,
            cheater_flag(self.sender.cheater)
        );
        let ticker = self.ticker.clone();
        let sender = self.sender.name.clone();
        let receiver = self.receiver.name.clone();
        let amount = self.amount;
        let tx_id = self.tx_id;
        return Box::new(move || {
            process_finalize_tx(
                seed.clone(),
                chain_db_dir.clone(),
                sender.clone(),
                receiver.clone(),
                ticker.clone(),
                amount,
                tx_id,
            )
            .unwrap();
            value.clone()
        });
    }

    pub fn mediate(&self, chain_db_dir: PathBuf) -> StepFunc {
        let value = format!(
            "mercat-mediator justify-transaction --sender {} --mediator {} --ticker {} --tx-id {} {}",
            self.sender.name,
            self.mediator.name,
            self.ticker,
            self.tx_id,
            cheater_flag(self.sender.cheater)
        );
        let ticker = self.ticker.clone();
        let sender = self.sender.name.clone();
        let mediator = self.mediator.name.clone();
        let tx_id = self.tx_id;
        let reject = !self.mediator_approves;
        return Box::new(move || {
            justify_asset_transaction(
                chain_db_dir.clone(),
                sender.clone(),
                mediator.clone(),
                ticker.clone(),
                tx_id,
                reject,
            )
            .unwrap();
            value.clone()
        });
    }

    pub fn validate(&self, chain_db_dir: PathBuf) -> StepFunc {
        let value = format!(
            "mercat-validator validate-transaction --sender {} --receiver {} --mediator {} --state {} --tx-id {}",
            self.sender.name,
            self.receiver.name,
            self.mediator.name,
            "state: todo",
            self.tx_id,
        );
        let sender = self.sender.name.clone();
        let receiver = self.receiver.name.clone();
        let mediator = self.mediator.name.clone();
        let tx_id = self.tx_id;
        return Box::new(move || {
            validate_transaction(
                chain_db_dir.clone(),
                sender.clone(),
                receiver.clone(),
                mediator.clone(),
                String::from("state: todo"),
                tx_id,
            )
            .unwrap();
            value.clone()
        });
    }

    pub fn order<T: RngCore + CryptoRng>(
        &self,
        rng: &mut T,
        chain_db_dir: PathBuf,
    ) -> Vec<StepFunc> {
        vec![
            self.send(rng, chain_db_dir.clone()),
            self.receive(rng, chain_db_dir.clone()),
            self.mediate(chain_db_dir.clone()),
            self.validate(chain_db_dir),
        ]
    }
}

impl Create {
    pub fn create_account<T: RngCore + CryptoRng>(
        &self,
        rng: &mut T,
        chain_db_dir: PathBuf,
    ) -> StepFunc {
        let seed = gen_seed_from(rng);
        if let Some(ticker) = self.ticker.clone() {
            // create a normal account
            let value = format!(
                "mercat-account create --account-id {} --ticker {} --user {} --seed {} {}",
                self.account_id,
                ticker,
                self.owner.name,
                seed,
                cheater_flag(self.owner.cheater)
            );
            let ticker = ticker.clone();
            let account_id = self.account_id;
            let owner = self.owner.name.clone();
            return Box::new(move || {
                process_create_account(
                    Some(seed.clone()),
                    chain_db_dir.clone(),
                    ticker.clone(),
                    account_id,
                    owner.clone(),
                )
                .unwrap();
                value.clone()
            });
        } else {
            // create a mediator account
            let value = format!(
                "mercat-mediator create --user {} --seed {} {}",
                self.owner.name,
                seed,
                cheater_flag(self.owner.cheater)
            );
            let owner = self.owner.name.clone();
            return Box::new(move || {
                process_create_mediator(seed.clone(), chain_db_dir.clone(), owner.clone()).unwrap();
                value.clone()
            });
        }
    }
    // todo : add db_dir to all the commands

    pub fn validate(&self, chain_db_dir: PathBuf) -> StepFunc {
        if let Some(_) = self.ticker.clone() {
            // validate a normal account
            let value = format!(
                "mercat-validator validate-account --user {}",
                self.owner.name,
            );
            let owner = self.owner.name.clone();
            return Box::new(move || {
                validate_account(chain_db_dir.clone(), owner.clone()).unwrap();
                value.clone()
            });
        } else {
            // validate mediator account
            return Box::new(move || {
                String::from("todo: need a validator for mediator account creation")
            });
        }
    }

    pub fn order<T: RngCore + CryptoRng>(
        &self,
        rng: &mut T,
        chain_db_dir: PathBuf,
    ) -> Vec<StepFunc> {
        vec![
            self.create_account(rng, chain_db_dir.clone()),
            self.validate(chain_db_dir),
        ]
    }
}

impl Issue {
    pub fn issue<T: RngCore + CryptoRng>(&self, rng: &mut T, chain_db_dir: PathBuf) -> StepFunc {
        let seed = gen_seed_from(rng);
        let value = format!(
            "mercat-account issue --account-id {} --amount {} --issuer {} --mediator {} --tx-id {} --seed {} {}",
            self.ticker,
            self.amount,
            self.issuer.name,
            self.mediator.name,
            self.tx_id,
            seed,
            cheater_flag(self.issuer.cheater)
        );
        let ticker = self.ticker.clone();
        let issuer = self.issuer.name.clone();
        let mediator = self.mediator.name.clone();
        let amount = self.amount;
        let tx_id = self.tx_id;
        return Box::new(move || {
            process_issue_asset(
                seed.clone(),
                chain_db_dir.clone(),
                issuer.clone(),
                mediator.clone(),
                ticker.clone(),
                amount,
                tx_id,
            )
            .unwrap();
            value.clone()
        });
    }

    pub fn mediate(&self, chain_db_dir: PathBuf) -> StepFunc {
        let value = format!(
            "mercat-mediator justify-issuance --account-id {} --issuer {} --mediator {} --tx-id {} {}",
            self.ticker,
            self.issuer.name,
            self.mediator.name,
            self.tx_id,
            cheater_flag(self.issuer.cheater)
        );
        let issuer = self.issuer.name.clone();
        let mediator = self.mediator.name.clone();
        let ticker = self.ticker.clone();
        let tx_id = self.tx_id;
        let reject = !self.mediator_approves;
        return Box::new(move || {
            justify_asset_issuance(
                chain_db_dir.clone(),
                issuer.clone(),
                mediator.clone(),
                ticker.clone(),
                tx_id,
                reject,
            )
            .unwrap();
            value.clone()
        });
    }

    pub fn validate(&self, chain_db_dir: PathBuf) -> StepFunc {
        // validate a normal account
        let value = format!(
            "mercat-validator validate-issuance --issuer {} --mediator {} --state {} --tx-id {}",
            self.issuer.name, self.mediator.name, "state: todo", self.tx_id,
        );
        let issuer = self.issuer.name.clone();
        let mediator = self.mediator.name.clone();
        let tx_id = self.tx_id;
        return Box::new(move || {
            validate_asset_issuance(
                chain_db_dir.clone(),
                issuer.clone(),
                mediator.clone(),
                String::from("state: todo"),
                tx_id,
            )
            .unwrap();
            value.clone()
        });
    }

    pub fn order<T: RngCore + CryptoRng>(
        &self,
        rng: &mut T,
        chain_db_dir: PathBuf,
    ) -> Vec<StepFunc> {
        vec![
            self.issue(rng, chain_db_dir.clone()),
            self.mediate(chain_db_dir.clone()),
            self.validate(chain_db_dir),
        ]
    }
}

impl TransactionMode {
    fn sequence<T: RngCore + CryptoRng>(
        &self,
        rng: &mut T,
        chain_db_dir: PathBuf,
    ) -> Vec<StepFunc> {
        match self {
            TransactionMode::Transaction(transaction) => transaction.order(rng, chain_db_dir),
            TransactionMode::Sequence { repeat, steps } => {
                let mut seq: Vec<StepFunc> = vec![];
                for _ in 0..*repeat {
                    for transaction in steps {
                        seq.extend(transaction.sequence(rng, chain_db_dir.clone()));
                    }
                }
                seq
            }
            TransactionMode::Concurrent { repeat, steps } => {
                let mut seqs: Vec<Vec<StepFunc>> = vec![];
                for _ in 0..*repeat {
                    for transaction in steps {
                        seqs.push(transaction.sequence(rng, chain_db_dir.clone()));
                    }
                }

                let mut seed = [0u8; 32];
                rng.fill(&mut seed);
                info!(
                    "Using seed {:?} for interleaving the transactions.",
                    base64::encode(seed)
                );

                let mut rng = StdRng::from_seed(seed);
                let mut seq: Vec<StepFunc> = vec![];

                while seqs.len() != 0 {
                    let next = rng.gen_range(0, seqs.len());
                    if seqs[next].len() == 0 {
                        seqs.remove(next);
                        continue;
                    }
                    seq.push(seqs[next].remove(0));
                }
                seq
            }
        }
    }
}

impl TestCase {
    fn run(&self) -> Result<HashSet<InputAccount>, Error> {
        let seed = gen_seed();
        info!("Using seed {}, for testcase: {}.", seed, self.title);
        let mut rng = create_rng_from_seed(Some(seed))?;

        self.chain_setup()?;
        let start = Instant::now();
        for transaction in self
            .transactions
            .sequence(&mut rng, self.chain_db_dir.clone())
        {
            info!("Running {}", transaction());
        }
        let duration = Instant::now() - start;
        if duration.as_millis() > self.timing_limit {
            return Err(Error::TimeLimitExceeded {
                want: self.timing_limit,
                got: duration.as_millis(),
            });
        }
        self.resulting_accounts()
    }

    fn chain_setup(&self) -> Result<(), Error> {
        process_asset_id_creation(self.chain_db_dir.clone(), self.ticker_names.clone())
    }

    /// Reads the contents of all the accounts from the on-chain directory and decrypts
    /// the balance with the secret account from the off-chain directory.
    fn resulting_accounts(&self) -> Result<HashSet<InputAccount>, Error> {
        let mut accounts: HashSet<InputAccount> = HashSet::new();
        let mut path = self.chain_db_dir.clone();
        path.push(ON_CHAIN_DIR);

        for dir in all_dirs_in_dir(path)? {
            if let Some(user) = dir.file_name().and_then(|user| user.to_str()) {
                if user != COMMON_OBJECTS_DIR {
                    for ticker in self.ticker_names.clone() {
                        let pub_file_name = format!("{}_{}", ticker, PUBLIC_ACCOUNT_FILE);
                        let sec_file_name = format!("{}_{}", ticker, SECRET_ACCOUNT_FILE);

                        let mut path = dir.clone();
                        path.push(pub_file_name.clone());
                        if !path.exists() {
                            continue;
                        }
                        let pub_account: PubAccount = load_object(
                            self.chain_db_dir.clone(),
                            ON_CHAIN_DIR,
                            user,
                            &pub_file_name,
                        )?;
                        let sec_account: SecAccount = load_object(
                            self.chain_db_dir.clone(),
                            OFF_CHAIN_DIR,
                            user,
                            &sec_file_name,
                        )?;
                        let account = Account {
                            pblc: pub_account,
                            scrt: sec_account,
                        };
                        let balance = account.decrypt_balance().unwrap();
                        accounts.insert(InputAccount {
                            owner: String::from(user),
                            ticker: Some(ticker),
                            balance,
                        });
                    }
                }
            }
        }
        Ok(accounts)
    }
}

// ------------------------------------------------------------------------------------------
// -                                  Utility functions                                     -
// ------------------------------------------------------------------------------------------
fn cheater_flag(is_cheater: bool) -> String {
    if is_cheater {
        String::from("--cheater")
    } else {
        String::from("")
    }
}

fn all_files_in_dir(dir: PathBuf) -> io::Result<Vec<PathBuf>> {
    let mut files = vec![];
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() {
            files.push(path);
        }
    }
    Ok(files)
}

fn all_dirs_in_dir(dir: PathBuf) -> Result<Vec<PathBuf>, Error> {
    let mut files = vec![];
    for entry in fs::read_dir(dir.clone()).map_err(|error| Error::FileReadError {
        error,
        path: dir.clone(),
    })? {
        let entry = entry.map_err(|error| Error::FileReadError {
            error,
            path: dir.clone(),
        })?;
        let path = entry.path();
        if path.is_dir() {
            files.push(path);
        }
    }
    Ok(files)
}
fn make_empty_accounts(accounts: &Vec<InputAccount>) -> Result<(u32, TransactionMode), Error> {
    let mut account_id = 0;
    let mut transaction_counter = 0;
    let mut seq: Vec<TransactionMode> = vec![];
    for account in accounts {
        let mut rng = rand::thread_rng();
        let mut seed = [0u8; 32];
        rng.fill(&mut seed);
        seq.push(TransactionMode::Transaction(Transaction::Create(Create {
            tx_id: transaction_counter,
            account_id: account_id,
            owner: Party {
                name: account.owner.clone(),
                cheater: false, // TODO: test harness does not support cheating for account creation yet.
            },
            ticker: account.ticker.clone(),
        })));
        account_id += 1;
        transaction_counter += 1;
    }
    Ok((
        transaction_counter,
        TransactionMode::Sequence {
            repeat: 1,
            steps: seq,
        },
    ))
}

fn to_string(value: &Yaml, path: PathBuf, attribute: &str) -> Result<String, Error> {
    Ok(value
        .as_str()
        .ok_or(Error::ErrorParsingTestHarnessConfig {
            path: path,
            reason: format!("Failed to read {}", attribute),
        })?
        .to_string())
}

fn to_hash<'a>(
    value: &'a Yaml,
    path: PathBuf,
    attribute: &str,
) -> Result<&'a LinkedHashMap<Yaml, Yaml>, Error> {
    if let Yaml::Hash(hash) = value {
        Ok(hash)
    } else {
        Err(Error::ErrorParsingTestHarnessConfig {
            path,
            reason: format!("Failed to parse {} as hash", attribute),
        })
    }
}

fn to_array<'a>(value: &'a Yaml, path: PathBuf, attribute: &str) -> Result<&'a Vec<Yaml>, Error> {
    if let Yaml::Array(array) = value {
        Ok(array)
    } else {
        Err(Error::ErrorParsingTestHarnessConfig {
            path,
            reason: format!("Failed to parse {} as array", attribute),
        })
    }
}

fn parse_transactions(
    value: &Yaml,
    path: PathBuf,
    attribute: &str,
    transaction_id: u32,
) -> Result<(u32, Vec<TransactionMode>), Error> {
    let mut transaction_list: Vec<TransactionMode> = vec![];
    let mut transaction_id = transaction_id;
    let transactions = to_array(value, path.clone(), attribute)?;
    for transaction in transactions.into_iter() {
        match &transaction {
            Yaml::Hash(transaction) => {
                for (key, value) in transaction {
                    let key = to_string(key, path.clone(), "sequence-or-concurrent")?;
                    let (new_transaction_id, steps) = parse_transactions(
                        value,
                        path.clone(),
                        "sequence-or-concurrent",
                        transaction_id,
                    )?;
                    transaction_id = new_transaction_id;
                    if key == "sequence" {
                        // TODO add repeat to the config. Create new story for it.
                        transaction_list.push(TransactionMode::Sequence { repeat: 1, steps });
                    } else if key == "concurrent" {
                        transaction_list.push(TransactionMode::Concurrent { repeat: 1, steps });
                    } else {
                        return Err(Error::ErrorParsingTestHarnessConfig {
                            path: path.clone(),
                            reason: format!("key: {} is invalid", key),
                        });
                    }
                }
            }
            Yaml::String(transaction) => {
                if let Some(issue) = Issue::try_from((transaction_id, transaction.to_string()))
                    .map_err(|_| Error::ErrorParsingTestHarnessConfig {
                        path: path.clone(),
                        reason: String::from("issuance"),
                    })
                    .ok()
                {
                    transaction_id += 1;
                    transaction_list.push(TransactionMode::Transaction(Transaction::Issue(issue)));
                } else if let Some(transfer) =
                    Transfer::try_from((transaction_id, transaction.to_string()))
                        .map_err(|_| Error::ErrorParsingTestHarnessConfig {
                            path: path.clone(),
                            reason: String::from("transfer"),
                        })
                        .ok()
                {
                    transaction_id += 1;
                    transaction_list.push(TransactionMode::Transaction(Transaction::Transfer(
                        transfer,
                    )));
                } else {
                    return Err(Error::ErrorParsingTestHarnessConfig {
                        path: path.clone(),
                        reason: format!(
                            "Transaction {} does not match neither issuance or transfer format",
                            transaction
                        ),
                    });
                }
            }
            _ => {
                return Err(Error::ErrorParsingTestHarnessConfig {
                    path: path.clone(),
                        reason: format!("Expected 'sequence', 'concurrent', or a transaction description. Got {:#?}", transaction),
                });
            }
        }
    }

    Ok((transaction_id, transaction_list))
}

fn parse_config(path: PathBuf, chain_db_dir: PathBuf) -> Result<TestCase, Error> {
    let config = fs::read_to_string(path.clone()).map_err(|error| Error::FileReadError {
        error,
        path: path.clone(),
    })?;
    let config = YamlLoader::load_from_str(&config).unwrap();
    let config = &config[0];

    let title: String = to_string(&config["title"], path.clone(), "title")?;
    let mut ticker_names: Vec<String> = vec![];
    if let Yaml::Array(tickers_yaml) = &config["tickers"] {
        for ticker in tickers_yaml {
            ticker_names.push(to_string(&ticker, path.clone(), "ticker")?)
        }
    }

    let mut all_accounts: Vec<InputAccount> = vec![];
    let accounts = to_array(&config["accounts"], path.clone(), "accounts")?;
    for user in accounts {
        let user = to_hash(&user, path.clone(), "accounts.user")?;
        for (user, tickers) in user {
            let user = to_string(&user, path.clone(), "accounts.user")?;
            let tickers = to_array(&tickers, path.clone(), "accounts.tickers")?;
            for ticker in tickers {
                let ticker = to_string(
                    &ticker,
                    path.clone(),
                    &format!("accounts.{}.ticker", user.clone()),
                )?;
                all_accounts.push(InputAccount {
                    balance: 0,
                    owner: user.clone(),
                    ticker: Some(ticker),
                });
            }
        }
    }

    let accounts = to_array(&config["mediators"], path.clone(), "mediators")?;
    for user in accounts {
        let user = to_string(&user, path.clone(), "mediator.user")?;
        all_accounts.push(InputAccount {
            balance: 0,
            owner: user.clone(),
            ticker: None,
        });
    }

    let mut accounts_outcome: HashSet<InputAccount> = HashSet::new();
    let outcomes = to_array(&config["outcome"], path.clone(), "outcome")?;
    let mut timing_limit: u128 = 0;
    for outcome in outcomes {
        let outcome_type = to_hash(&outcome, path.clone(), "outcome.key")?;
        for (key, value) in outcome_type {
            let key = to_string(key, path.clone(), "outcome.key")?;
            if key == "time-limit" {
                if let Some(expected_time_limit) = value.as_i64() {
                    timing_limit = expected_time_limit as u128;
                }
            } else {
                let accounts_for_user =
                    to_array(&value, path.clone(), &format!("outcome.{}.ticker", key))?;
                let owner = key.clone();
                for accounts in accounts_for_user {
                    let accounts =
                        to_hash(&accounts, path.clone(), &format!("outcome.{}.ticker", key))?;
                    for (ticker, amount) in accounts {
                        let ticker = to_string(
                            &ticker,
                            path.clone(),
                            &format!("outcome.{}.ticker", owner.clone()),
                        )?;
                        let balance =
                            amount
                                .as_i64()
                                .ok_or(Error::ErrorParsingTestHarnessConfig {
                                    path: path.clone(),
                                    reason: format!(
                                        "failed to convert expect amount for outcome.{}.{}",
                                        owner.clone(),
                                        ticker.clone()
                                    ),
                                })?;
                        let balance = u32::try_from(balance).map_err(|_| Error::BalanceTooBig)?;
                        accounts_outcome.insert(InputAccount {
                            owner: owner.clone(),
                            ticker: Some(ticker.clone()),
                            balance,
                        });
                    }
                }
            }
        }
    }

    let (next_transaction_id, create_account_transactions) = make_empty_accounts(&all_accounts)?;

    // TODO declared mutable since later I want to consume a single element of it
    let (_, mut transactions) = parse_transactions(
        &config["transactions"],
        path.clone(),
        "transactions",
        next_transaction_id,
    )?;

    if transactions.len() != 1 {
        return Err(Error::TopLevelTransaction);
    }
    let transactions = TransactionMode::Sequence {
        repeat: 1,
        steps: vec![create_account_transactions, transactions.remove(0)],
    };
    Ok(TestCase {
        title,
        ticker_names,
        transactions,
        accounts_outcome,
        timing_limit,
        chain_db_dir,
    })
}

fn accounts_are_equal(want: &HashSet<InputAccount>, got: &HashSet<InputAccount>) -> bool {
    let intersection: HashSet<_> = want.intersection(&got).collect();
    intersection.len() == want.len() && want.len() == got.len()
}

// This is called from the test and benchmark. Allowing it be unused to silence compiler warnings.
#[allow(unused)]
fn run_from(mode: &str) {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("scenarios/unittest");
    path.push(mode);

    let mut chain_db_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    chain_db_dir.push("chain_dir/unittest");
    chain_db_dir.push(mode);

    let configs = all_files_in_dir(path).unwrap();
    for config in configs {
        let mut separate_chain_db_dir = chain_db_dir.clone();
        separate_chain_db_dir.push(config.file_name().unwrap());
        let testcase = &parse_config(config, separate_chain_db_dir).unwrap();
        info!("Running test case: {}.", testcase.title);
        let want = &testcase.accounts_outcome;
        let got = &testcase.run().unwrap();
        assert!(
            accounts_are_equal(want, got),
            format!("want: {:?}, got: {:?}", want, got)
        );
    }
}

// ------------------------------------------------------------------------------------------------
// -                                            Tests                                             -
// ------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use env_logger;
    use wasm_bindgen_test::*;

    #[test]
    fn test_on_slow_pc() {
        env_logger::init();
        run_from("pc");
    }

    #[test]
    fn test_on_fast_node() {
        run_from("node");
    }

    #[wasm_bindgen_test]
    fn test_on_wasm() {
        run_from("wasm");
    }
}
