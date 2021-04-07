use crate::{
    account_create::process_create_account,
    account_issue::process_issue_asset_with_tx_name,
    account_transfer::{process_create_tx_with_tx_name, process_finalize_tx},
    audit::{process_audit, process_create_auditor},
    chain_setup::process_asset_id_creation,
    create_rng_from_seed, debug_decrypt_account_balance,
    errors::Error,
    gen_seed, gen_seed_from,
    justify::{justify_asset_transfer_transaction, process_create_mediator},
    load_object_from, user_public_account_file,
    validate::validate_all_pending,
    AuditResult, COMMON_OBJECTS_DIR, ON_CHAIN_DIR,
};
use linked_hash_map::LinkedHashMap;
use log::{error, info, warn};
use rand::Rng;
use rand::{rngs::StdRng, SeedableRng};
use rand::{CryptoRng, RngCore};
use regex::Regex;
use std::{
    collections::HashSet,
    convert::{From, TryFrom},
    fs,
};
use std::{convert::TryInto, path::PathBuf};
use yaml_rust::{Yaml, YamlLoader};

// --------------------------------------------------------------------------------------------------
// -                                       data types                                                -
// ---------------------------------------------------------------------------------------------------

/// The signature of the function for a generic step in a transaction. This function performs
/// the action (e.g., initializing a transaction, finalizing a transaction, or creating an account),
/// and returns the corresponding CLI command that can be run to reproduce this step manually.
type StepFunc = Box<dyn Fn() -> Result<String, Error>>;

/// Represents the three types of mercat transactions.
#[derive(Debug)]
pub enum Transaction {
    /// Transfer a balance from Alice to Bob, with some mediator and validator.
    Transfer(Transfer),
    /// Create an account for Alice for a ticker, with balance of zero.
    Create(Create),
    /// Issue tokens for an account (effectively funding an account).
    Issue(Issue),
    /// Validate all pending transactions up to this point.
    Validate(Validate),
    /// Audit the specified transaction.
    Audit(Audit),
}

/// Distinguishes between the three types of users in the system.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PartyKind {
    Normal,
    Mediator,
    Auditor,
}

/// A generic party, can be sender, receiver, or mediator.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Party {
    pub name: String,
    pub cheater: bool,
    pub kind: PartyKind,
}

impl TryFrom<(&str, PartyKind)> for Party {
    type Error = Error;
    fn try_from(pair: (&str, PartyKind)) -> Result<Self, Error> {
        let (segment, kind) = pair;
        // Example: alice or alice(cheat)
        let re = Regex::new(r"([a-zA-Z0-9]+)(\(cheat\))?").map_err(|_| Error::RegexError {
            reason: String::from("Failed to compile the Transfer regex"),
        })?;
        let caps = re.captures(segment).ok_or(Error::RegexError {
            reason: format!("Pattern did not match {}", segment),
        })?;
        let name = caps[1].to_string().to_lowercase();
        let cheater = caps.get(2).is_some();
        Ok(Self {
            name,
            cheater,
            kind,
        })
    }
}

/// Data type of the transaction of transferring balance.
#[derive(Debug, PartialEq)]
pub struct Transfer {
    pub tx_id: u32,
    pub sender: Party,
    pub receiver: Party,
    pub receiver_approves: bool,
    pub mediator: Party,
    pub mediator_approves: bool,
    pub amount: u32,
    pub ticker: String,
    pub auditors: Vec<Party>,
    pub tx_name: Option<String>,
}

impl TryFrom<(u32, String)> for Transfer {
    type Error = Error;
    fn try_from(pair: (u32, String)) -> Result<Self, Error> {
        let (tx_id, segment) = pair;
        // Example: transfer Bob(cheat) 40 ACME Carol approve Marry reject auditors Ava,Aubrey tx_name BobToAlice
        let re = Regex::new(
            r"^transfer ([a-zA-Z0-9()]+) ([0-9]+) ([a-zA-Z0-9]+) ([a-zA-Z0-9()]+) (approve|reject) ([a-zA-Z0-9()]+) (approve|reject)( auditors)?( [a-zA-Z0-9,]+)?( tx_name)?( [a-zA-Z0-9-_]+)?$",
        )
        .map_err(|_| Error::RegexError {
            reason: String::from("Failed to compile the Transfer regex"),
        })?;
        let caps = re.captures(&segment).ok_or(Error::RegexError {
            reason: format!("Pattern did not match {}", segment),
        })?;
        let ticker = caps[3].to_string().to_uppercase();
        let auditors = if caps.get(9) == None {
            vec![]
        } else {
            caps[9]
                .to_string()
                .to_lowercase()
                .split(",")
                .map(|name| Party::try_from((name, PartyKind::Auditor)))
                .collect::<Result<_, _>>()?
        };
        let tx_name = if caps.get(11) == None {
            None
        } else {
            Some(caps[11].trim().to_string())
        };
        Ok(Self {
            tx_id,
            sender: Party::try_from((&caps[1], PartyKind::Normal))?,
            receiver: Party::try_from((&caps[4], PartyKind::Normal))?,
            receiver_approves: caps[5].to_string() == "approve",
            mediator: Party::try_from((&caps[6], PartyKind::Mediator))?,
            mediator_approves: caps[7].to_string() == "approve",
            amount: caps[2]
                .to_string()
                .parse::<u32>()
                .map_err(|_| Error::RegexError {
                    reason: String::from("failed to convert amount to u32."),
                })?,
            ticker,
            auditors,
            tx_name,
        })
    }
}

/// Data type of the transaction of creating empty account.
#[derive(Debug)]
pub struct Create {
    pub tx_id: u32,
    pub owner: Party,
    pub owner_id: Option<u32>,
    pub ticker: Option<String>,
}

/// Data type of the transaction of funding an account by issuer.
#[derive(Debug, PartialEq)]
pub struct Issue {
    pub tx_id: u32,
    pub issuer: Party,
    pub ticker: String,
    pub amount: u32,
    pub auditors: Vec<Party>,
    pub tx_name: Option<String>,
}

impl TryFrom<(u32, String)> for Issue {
    type Error = Error;
    fn try_from(pair: (u32, String)) -> Result<Self, Error> {
        let (tx_id, segment) = pair;
        // Example: issue Bob(cheat) 40 ACME
        // Example: issue Bob(cheat) 40 ACME auditors Ava,Aubrey tx_name BobIssue
        let re = Regex::new(
            r"^issue ([a-zA-Z0-9()]+) ([0-9]+) ([a-zA-Z0-9]+)( auditors)?( [a-zA-Z0-9,]+)?( tx_name)?( [a-zA-Z0-9-_]+)?$",
        )
        .map_err(|_| Error::RegexError {
            reason: String::from("Failed to compile the Issue regex"),
        })?;
        let caps = re.captures(&segment).ok_or(Error::RegexError {
            reason: format!("Pattern did not match {}", segment),
        })?;
        let ticker = caps[3].to_string().to_uppercase();
        let auditors = if caps.get(5) == None {
            vec![]
        } else {
            caps[5]
                .to_string()
                .to_lowercase()
                .split(",")
                .map(|name| Party::try_from((name, PartyKind::Auditor)))
                .collect::<Result<_, _>>()?
        };
        let tx_name = if caps.get(7) == None {
            None
        } else {
            Some(caps[7].trim().to_string())
        };
        Ok(Self {
            tx_id,
            issuer: Party::try_from((&caps[1], PartyKind::Normal))?,
            ticker,
            amount: caps[2]
                .to_string()
                .parse::<u32>()
                .map_err(|_| Error::RegexError {
                    reason: String::from("failed to convert amount to u32."),
                })?,
            auditors,
            tx_name,
        })
    }
}

/// Data type for validating transactions
#[derive(Debug)]
pub struct Validate {}

impl TryFrom<String> for Validate {
    type Error = Error;
    fn try_from(segment: String) -> Result<Self, Error> {
        // Example: validate
        if segment != "validate" {
            return Err(Error::RegexError {
                reason: format!("Expected 'validate', got {}", segment),
            });
        }
        Ok(Self {})
    }
}

/// A generic party, can be sender, receiver, or mediator.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Audit {
    pub tx_id: u32,
    pub tx_name: String,
    pub auditor: Party,
}

impl TryFrom<(u32, String)> for Audit {
    type Error = Error;
    fn try_from(pair: (u32, String)) -> Result<Self, Error> {
        // Example: audit AliceIssue Ava
        let (tx_id, segment) = pair;
        let re = Regex::new(r"audit ([a-zA-Z0-9-_]+) ([a-zA-Z0-9]+)").map_err(|_| {
            Error::RegexError {
                reason: String::from("Failed to compile the Transfer regex"),
            }
        })?;
        let caps = re.captures(&segment).ok_or(Error::RegexError {
            reason: format!("Pattern did not match {}", segment),
        })?;
        let tx_name = caps[1].to_string();
        let auditor = Party::try_from((&caps[2], PartyKind::Auditor))?;
        Ok(Self {
            tx_id,
            tx_name,
            auditor,
        })
    }
}

/// Human readable form of a mercat account.
#[derive(PartialEq, Eq, Hash, Debug)]
pub struct InputAccount {
    owner: Party,
    ticker: String,
    balance: u32,
}

/// The expected result of an audit.
#[derive(PartialEq, Eq, Hash, Debug)]
pub struct AuditExpectation {
    auditor: Party,
    tx_name: String,
    tx_status: AuditResult,
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
    Empty,
}

/// Represents a testcase that is read from the config file.
pub struct TestCase {
    /// Human readable description of the testcase. Will be printed to the log.
    title: String,

    /// The list of valid ticker names. These names will be converted to asset ids for meract.
    ticker_names: Vec<String>,

    /// The transactions of this testcase.
    transactions: TransactionMode,

    /// The expected value of the accounts at the end of the scenario.
    accounts_outcome: HashSet<InputAccount>,

    /// The expected state of auditted transactions.
    audit_outcome: HashSet<AuditExpectation>,

    /// The directory that will act as the chain datastore.
    chain_db_dir: PathBuf,
}

// --------------------------------------------------------------------------------------------------
// -                                  data type methods                                             -
// --------------------------------------------------------------------------------------------------

impl Transaction {
    fn operations_order<T: RngCore + CryptoRng>(
        &self,
        rng: &mut T,
        chain_db_dir: PathBuf,
    ) -> Vec<StepFunc> {
        match self {
            Transaction::Audit(audit) => audit.operations_order(chain_db_dir),
            Transaction::Validate(validate) => validate.operations_order(chain_db_dir),
            Transaction::Issue(fund) => fund.operations_order(rng, chain_db_dir),
            Transaction::Transfer(transfer) => transfer.operations_order(rng, chain_db_dir),
            Transaction::Create(create) => create.operations_order(rng, chain_db_dir),
        }
    }
}

impl Transfer {
    pub fn send<T: RngCore + CryptoRng>(&self, rng: &mut T, chain_db_dir: PathBuf) -> StepFunc {
        let seed = gen_seed_from(rng);
        let value = format!(
            "tx-{}: $ mercat-account create-transaction --account-id-from-ticker {} --amount {} --sender {} --receiver {} \
            --mediator {} --tx-id {} --seed {} --db-dir {} {}",
            self.tx_id,
            self.ticker,
            self.amount,
            self.sender.name,
            self.receiver.name,
            self.mediator.name,
            self.tx_id,
            seed,
            path_to_string(&chain_db_dir),
            cheater_flag(self.sender.cheater)
        );
        let ticker = self.ticker.clone();
        let sender = self.sender.name.clone();
        let receiver = self.receiver.name.clone();
        let mediator = self.mediator.name.clone();
        let amount = self.amount;
        let tx_id = self.tx_id;
        let tx_name = self.tx_name.clone();
        let cheat = self.sender.cheater;
        let auditors: Vec<String> = self
            .auditors
            .clone()
            .into_iter()
            .map(|auditor| auditor.name)
            .collect();

        Box::new(move || {
            info!("Running: {}", value.clone());
            process_create_tx_with_tx_name(
                seed.clone(),
                chain_db_dir.clone(),
                sender.clone(),
                receiver.clone(),
                mediator.clone(),
                &auditors,
                ticker.clone(),
                amount,
                false, // Do not print the transaction data to stdout.
                tx_id,
                cheat,
                tx_name.clone(),
            )?;
            Ok(value.clone())
        })
    }

    pub fn receive<T: RngCore + CryptoRng>(&self, rng: &mut T, chain_db_dir: PathBuf) -> StepFunc {
        let seed = gen_seed_from(rng);
        let value = format!(
            "tx-{}: $ mercat-account finalize-transaction --account-id-from-ticker {} --amount {} --sender {} --receiver {} --tx-id {} \
            --seed {} --db-dir {} {}",
            self.tx_id,
            self.ticker,
            self.amount,
            self.sender.name,
            self.receiver.name,
            self.tx_id,
            seed,
            path_to_string(&chain_db_dir),
            cheater_flag(self.receiver.cheater)
        );
        let ticker = self.ticker.clone();
        let sender = self.sender.name.clone();
        let receiver = self.receiver.name.clone();
        let amount = self.amount;
        let tx_id = self.tx_id;
        let cheat = self.receiver.cheater;

        Box::new(move || {
            info!("Running: {}", value.clone());
            process_finalize_tx(
                seed.clone(),
                chain_db_dir.clone(),
                sender.clone(),
                receiver.clone(),
                ticker.clone(),
                amount,
                false, // Do not print the transaction data to stdout.
                tx_id,
                cheat,
            )?;
            Ok(value.clone())
        })
    }

    pub fn mediate<T: RngCore + CryptoRng>(&self, rng: &mut T, chain_db_dir: PathBuf) -> StepFunc {
        let seed = gen_seed_from(rng);
        let value = format!(
            "tx-{}: $ mercat-mediator justify-transaction --sender {} --receiver {} --mediator {} --ticker {} --tx-id {} --seed {} --db-dir {} {}",
            self.tx_id,
            self.sender.name,
            self.receiver.name,
            self.mediator.name,
            self.ticker,
            self.tx_id,
            seed,
            path_to_string(&chain_db_dir),
            cheater_flag(self.mediator.cheater)
        );
        let ticker = self.ticker.clone();
        let sender = self.sender.name.clone();
        let receiver = self.receiver.name.clone();
        let mediator = self.mediator.name.clone();
        let tx_id = self.tx_id;
        let reject = !self.mediator_approves;
        let cheat = self.mediator.cheater;
        let auditors: Vec<String> = self
            .auditors
            .clone()
            .into_iter()
            .map(|auditor| auditor.name)
            .collect();

        Box::new(move || {
            info!("Running: {}", value.clone());
            justify_asset_transfer_transaction(
                chain_db_dir.clone(),
                sender.clone(),
                receiver.clone(),
                mediator.clone(),
                &auditors,
                ticker.clone(),
                seed.clone(),
                false, // Do not print the transaction data to stdout.
                tx_id,
                reject,
                cheat,
            )?;
            Ok(value.clone())
        })
    }

    pub fn operations_order<T: RngCore + CryptoRng>(
        &self,
        rng: &mut T,
        chain_db_dir: PathBuf,
    ) -> Vec<StepFunc> {
        vec![
            self.send(rng, chain_db_dir.clone()),
            self.receive(rng, chain_db_dir.clone()),
            self.mediate(rng, chain_db_dir),
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
        match self.owner.kind {
            PartyKind::Normal => {
                if let Some(ticker) = self.ticker.clone() {
                    let value = format!(
                "tx-{}: $ mercat-account create --ticker {} --user {} --seed {} --db-dir {} --tx-id {} {}",
                self.tx_id,
                ticker,
                self.owner.name,
                seed,
                path_to_string(&chain_db_dir),
                self.tx_id,
                cheater_flag(self.owner.cheater)
            );
                    let owner = self.owner.name.clone();
                    let cheat = self.owner.cheater;
                    let tx_id = self.tx_id;

                    Box::new(move || {
                        info!("Running: {}", value.clone());
                        process_create_account(
                            Some(seed.clone()),
                            chain_db_dir.clone(),
                            ticker.clone(),
                            owner.clone(),
                            false, // Do not print the transaction data to stdout.
                            tx_id,
                            cheat,
                        )?;
                        Ok(value.clone())
                    })
                } else {
                    panic!("Tech debt: the function should return error when ticker is not set for normal users.");
                }
            }
            PartyKind::Mediator => {
                let value = format!(
                    "tx-{}: $ mercat-mediator create --user {} --seed {} --db-dir {} {}",
                    self.tx_id,
                    self.owner.name,
                    seed,
                    path_to_string(&chain_db_dir),
                    cheater_flag(self.owner.cheater)
                );
                let owner = self.owner.name.clone();

                Box::new(move || {
                    info!("Running: {}", value.clone());
                    process_create_mediator(seed.clone(), chain_db_dir.clone(), owner.clone())?;
                    Ok(value.clone())
                })
            }
            PartyKind::Auditor => {
                if let Some(owner_id) = self.owner_id {
                    let value = format!(
                        "tx-{}: $ mercat-auditor create --user {} --id {} --seed {} --db-dir {} {}",
                        self.tx_id,
                        self.owner.name,
                        owner_id,
                        seed,
                        path_to_string(&chain_db_dir),
                        cheater_flag(self.owner.cheater)
                    );
                    let owner = self.owner.name.clone();

                    Box::new(move || {
                        info!("Running: {}", value.clone());
                        process_create_auditor(
                            seed.clone(),
                            chain_db_dir.clone(),
                            owner.clone(),
                            owner_id,
                        )?;
                        Ok(value.clone())
                    })
                } else {
                    panic!("Tech debt: the function should return error when the owner id is not set for normal users.");
                }
            }
        }
    }

    pub fn operations_order<T: RngCore + CryptoRng>(
        &self,
        rng: &mut T,
        chain_db_dir: PathBuf,
    ) -> Vec<StepFunc> {
        vec![self.create_account(rng, chain_db_dir)]
    }
}

impl Issue {
    pub fn issue<T: RngCore + CryptoRng>(&self, rng: &mut T, chain_db_dir: PathBuf) -> StepFunc {
        let seed = gen_seed_from(rng);
        let value = format!(
            "tx-{}: $ mercat-account issue --account-id-from-ticker {} --amount {} --issuer {} --tx-id {} --seed {} --db-dir {} {}",
            self.tx_id,
            self.ticker,
            self.amount,
            self.issuer.name,
            self.tx_id,
            seed,
            path_to_string(&chain_db_dir),
            cheater_flag(self.issuer.cheater)
        );
        let ticker = self.ticker.clone();
        let issuer = self.issuer.name.clone();
        let amount = self.amount;
        let tx_id = self.tx_id;
        let tx_name = self.tx_name.clone();
        let cheat = self.issuer.cheater;
        let auditors: Vec<String> = self
            .auditors
            .clone()
            .into_iter()
            .map(|auditor| auditor.name)
            .collect();

        Box::new(move || {
            info!("Running: {}", value.clone());
            process_issue_asset_with_tx_name(
                seed.clone(),
                chain_db_dir.clone(),
                issuer.clone(),
                &auditors,
                ticker.clone(),
                amount,
                false, // Do not print the transaction data to stdout.
                tx_id,
                tx_name.clone(),
                cheat,
            )?;
            Ok(value.clone())
        })
    }

    pub fn operations_order<T: RngCore + CryptoRng>(
        &self,
        rng: &mut T,
        chain_db_dir: PathBuf,
    ) -> Vec<StepFunc> {
        vec![self.issue(rng, chain_db_dir)]
    }
}

impl Validate {
    pub fn validate(&self, chain_db_dir: PathBuf) -> StepFunc {
        // validate a normal account
        let value = format!(
            "tx-NA: $ mercat-validator validate --db-dir {}",
            path_to_string(&chain_db_dir),
        );

        Box::new(move || {
            info!("Running: {}", value.clone());
            validate_all_pending(chain_db_dir.clone())?;
            Ok(value.clone())
        })
    }

    pub fn operations_order(&self, chain_db_dir: PathBuf) -> Vec<StepFunc> {
        vec![self.validate(chain_db_dir)]
    }
}

impl Audit {
    pub fn audit(&self, chain_db_dir: PathBuf) -> StepFunc {
        // validate a transaction
        let value = format!(
            "tx-NA: $ mercat-auditor audit TODO --db-dir {}",
            path_to_string(&chain_db_dir),
        );

        let auditor = self.auditor.name.clone();
        let tx_name = self.tx_name.clone();

        Box::new(move || {
            info!("Running: {}", value.clone());
            process_audit(auditor.clone(), tx_name.clone(), chain_db_dir.clone())?;
            Ok(value.clone())
        })
    }

    pub fn operations_order(&self, chain_db_dir: PathBuf) -> Vec<StepFunc> {
        vec![self.audit(chain_db_dir)]
    }
}

impl TransactionMode {
    fn sequence<T: RngCore + CryptoRng>(
        &self,
        rng: &mut T,
        chain_db_dir: PathBuf,
    ) -> Vec<StepFunc> {
        match self {
            TransactionMode::Transaction(transaction) => {
                transaction.operations_order(rng, chain_db_dir)
            }
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

                while !seqs.is_empty() {
                    let next = rng.gen_range(0, seqs.len());
                    if seqs[next].is_empty() {
                        seqs.remove(next);
                        continue;
                    }
                    seq.push(seqs[next].remove(0));
                }
                seq
            }
            TransactionMode::Empty => vec![],
        }
    }
}

impl TestCase {
    fn run(&self) -> Result<(HashSet<InputAccount>, HashSet<AuditExpectation>), Error> {
        let seed = gen_seed();
        info!("Using seed {}, for testcase: {}.", seed, self.title);
        let mut rng = create_rng_from_seed(Some(seed))?;

        self.chain_setup()?;
        info!(
            "tx-N/A: $ mercat-chain-setup --ticker-names {} --db-dir {}",
            self.ticker_names.join(" "),
            path_to_string(&self.chain_db_dir.clone()),
        );

        for transaction in self
            .transactions
            .sequence(&mut rng, self.chain_db_dir.clone())
        {
            match transaction() {
                Err(error) => {
                    error!("Error in transaction: {:#?}", error);
                    error!("Ignoring the error and continuing with the rest of the transactions.");
                }
                Ok(_) => info!("Success!"),
            }
        }

        Ok((self.resulting_accounts()?, self.audit_results()?))
    }

    fn chain_setup(&self) -> Result<(), Error> {
        process_asset_id_creation(self.chain_db_dir.clone(), self.ticker_names.clone())
    }

    /// Reads the contents of all the accounts from the on-chain directory and decrypts
    /// the balance with the secret account from the off-chain directory.
    fn resulting_accounts(&self) -> Result<HashSet<InputAccount>, Error> {
        let mut accounts: HashSet<InputAccount> = HashSet::new();
        //let mut audit_results: HashSet<AuditExpectation> = HashSet::new();
        let mut path = self.chain_db_dir.clone();
        path.push(ON_CHAIN_DIR);

        for dir in all_dirs_in_dir(path)? {
            if let Some(user) = dir.file_name().and_then(|user| user.to_str()) {
                if user != COMMON_OBJECTS_DIR {
                    for ticker in self.ticker_names.clone() {
                        let pub_file_name = user_public_account_file(&ticker);

                        let mut path = dir.clone();
                        path.push(pub_file_name.clone());
                        if !path.exists() {
                            continue;
                        }
                        let balance = debug_decrypt_account_balance(
                            String::from(user),
                            ticker.clone(),
                            self.chain_db_dir.clone(),
                        )?;
                        accounts.insert(InputAccount {
                            owner: Party::try_from((user, PartyKind::Normal))?,
                            ticker,
                            balance,
                        });
                    }
                }
            }
        }
        Ok(accounts)
    }

    fn audit_results(&self) -> Result<HashSet<AuditExpectation>, Error> {
        let mut audit_results: HashSet<AuditExpectation> = HashSet::new();
        let mut path = self.chain_db_dir.clone();
        path.push(ON_CHAIN_DIR);

        for dir in all_dirs_in_dir(path.clone())? {
            if let Some(user) = dir.file_name().and_then(|user| user.to_str()) {
                if user != COMMON_OBJECTS_DIR {
                    // Read all the files and try to deserialize them to (String, AuditResult).
                    // If they get converted successfully, add them to the HashSet of
                    // AuditExpectation.

                    let mut file_path = path.clone();
                    file_path.push(user);
                    for file in all_files_in_dir(file_path)? {
                        let tx: Result<String, _> = load_object_from(file.clone());
                        if let Ok(serialized) = tx {
                            if let Ok((tx_name, tx_status)) = serde_json::from_str(&serialized) {
                                println!(
                                    "---------> Found file {:?} with content: {:?} {:?}",
                                    &file, &tx_name, &tx_status
                                );
                                audit_results.insert(AuditExpectation {
                                    auditor: Party::try_from((user, PartyKind::Auditor))?,
                                    tx_name,
                                    tx_status,
                                });
                            }
                        }
                    }
                }
            }
        }
        Ok(audit_results)
    }
}

// ------------------------------------------------------------------------------------------
// -                                  Utility functions                                     -
// ------------------------------------------------------------------------------------------
fn cheater_flag(is_cheater: bool) -> String {
    if is_cheater {
        String::from("--cheat")
    } else {
        String::from("")
    }
}

fn all_files_in_dir(dir: PathBuf) -> Result<Vec<PathBuf>, Error> {
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

fn make_empty_normal_accounts(
    accounts: &[InputAccount],
) -> Result<(u32, Vec<TransactionMode>), Error> {
    let mut transaction_counter = 0;
    let mut seq: Vec<TransactionMode> = vec![];
    for account in accounts {
        seq.push(TransactionMode::Transaction(Transaction::Create(Create {
            tx_id: transaction_counter,
            owner: account.owner.clone(),
            ticker: Some(account.ticker.clone()),
            owner_id: None,
        })));
        transaction_counter += 1;
    }
    Ok((
        transaction_counter,
        seq
        //TransactionMode::Sequence {
        //    repeat: 1,
        //    steps: seq,
        //},
    ))
}

fn make_empty_non_normal_accounts(
    accounts: &[(Party, Option<u32>)],
    starting_id: u32,
) -> Result<(u32, Vec<TransactionMode>), Error> {
    let mut transaction_counter = starting_id;
    let mut seq: Vec<TransactionMode> = vec![];
    for account in accounts {
        let (party, owner_id) = account;
        seq.push(TransactionMode::Transaction(Transaction::Create(Create {
            tx_id: transaction_counter,
            owner: party.clone(),
            ticker: None,
            owner_id: *owner_id,
        })));
        transaction_counter += 1;
    }
    Ok((
        transaction_counter,
        seq
        //TransactionMode::Sequence {
        //    repeat: 1,
        //    steps: seq,
        //},
    ))
}

fn to_string(value: &Yaml, path: PathBuf, attribute: &str) -> Result<String, Error> {
    Ok(value
        .as_str()
        .ok_or(Error::ErrorParsingTestHarnessConfig {
            path,
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
    if value == &Yaml::BadValue {
        transaction_list.push(TransactionMode::Empty);
        return Ok((transaction_id, transaction_list));
    }
    let transactions = to_array(value, path.clone(), attribute)?;
    for transaction in transactions.iter() {
        // In the yaml file, either the transaction starts with a keyword of sequence or concurrent,
        // or it is simply a string. If it is a string, then it either represents an asset issuance or a transfer.
        match &transaction {
            // Check if the sequence or concurrent keys are found
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
                        // TODO: CRYP-122: Add repeat to the config.
                        transaction_list.push(TransactionMode::Sequence { repeat: 1, steps });
                    } else if key == "concurrent" {
                        transaction_list.push(TransactionMode::Concurrent { repeat: 1, steps });
                    } else {
                        return Err(Error::ErrorParsingTestHarnessConfig {
                            path,
                            reason: format!("key: {} is invalid", key),
                        });
                    }
                }
            }
            // check if a string is found
            Yaml::String(transaction) => {
                if let Ok(issue) = Issue::try_from((transaction_id, transaction.to_string()))
                    .map_err(|_| Error::ErrorParsingTestHarnessConfig {
                        path: path.clone(),
                        reason: String::from("issuance"),
                    })
                {
                    transaction_id += 1;
                    transaction_list.push(TransactionMode::Transaction(Transaction::Issue(issue)));
                } else if let Ok(transfer) =
                    Transfer::try_from((transaction_id, transaction.to_string())).map_err(|_| {
                        Error::ErrorParsingTestHarnessConfig {
                            path: path.clone(),
                            reason: String::from("transfer"),
                        }
                    })
                {
                    transaction_id += 1;
                    transaction_list.push(TransactionMode::Transaction(Transaction::Transfer(
                        transfer,
                    )));
                } else if let Ok(validate) =
                    Validate::try_from(transaction.to_string()).map_err(|_| {
                        Error::ErrorParsingTestHarnessConfig {
                            path: path.clone(),
                            reason: String::from("validate"),
                        }
                    })
                {
                    // validate does not need a transaction id
                    transaction_list.push(TransactionMode::Transaction(Transaction::Validate(
                        validate,
                    )));
                } else if let Ok(audit) = Audit::try_from((transaction_id, transaction.to_string()))
                    .map_err(|_| Error::ErrorParsingTestHarnessConfig {
                        path: path.clone(),
                        reason: String::from("audit"),
                    })
                {
                    // audit does not need a transaction id
                    transaction_list.push(TransactionMode::Transaction(Transaction::Audit(audit)));
                } else {
                    return Err(Error::ErrorParsingTestHarnessConfig {
                        path,
                        reason: format!(
                            "Transaction {} does not match issuance, or transfer format",
                            transaction
                        ),
                    });
                }
            }
            _ => {
                return Err(Error::ErrorParsingTestHarnessConfig {
                    path,
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
    let config =
        YamlLoader::load_from_str(&config).map_err(|_| Error::ErrorParsingTestHarnessConfig {
            path: path.clone(),
            reason: String::from("YmlLoader scan error"),
        })?;
    let config = &config[0];

    let title: String = to_string(&config["title"], path.clone(), "title")?;
    let mut ticker_names: Vec<String> = vec![];
    if let Yaml::Array(tickers_yaml) = &config["tickers"] {
        for ticker in tickers_yaml {
            ticker_names.push(to_string(&ticker, path.clone(), "ticker")?)
        }
    }

    let mut all_normal_accounts: Vec<InputAccount> = vec![];
    let mut all_non_normal_accounts: Vec<(Party, Option<u32>)> = vec![];
    let accounts = to_array(&config["accounts"], path.clone(), "accounts")?;
    for user in accounts {
        let user = to_hash(&user, path.clone(), "accounts.user")?;
        for (user, tickers) in user {
            let user: &str = &to_string(&user, path.clone(), "accounts.user")?;
            let user = Party::try_from((user, PartyKind::Normal))?;
            let tickers = to_array(&tickers, path.clone(), "accounts.tickers")?;
            for ticker in tickers {
                let ticker = to_string(
                    &ticker,
                    path.clone(),
                    &format!("accounts.{}.ticker", user.name),
                )?;
                let ticker = ticker.to_uppercase();
                all_normal_accounts.push(InputAccount {
                    balance: 0,
                    owner: user.clone(),
                    ticker,
                });
            }
        }
    }

    if config["mediators"] != Yaml::BadValue {
        let accounts = to_array(&config["mediators"], path.clone(), "mediators")?;
        for user in accounts {
            let user = to_string(&user, path.clone(), "mediator.user")?;
            let user = user.to_lowercase();
            all_non_normal_accounts
                .push((Party::try_from((user.as_str(), PartyKind::Mediator))?, None));
        }
    }

    if config["auditors"] != Yaml::BadValue {
        let accounts = to_array(&config["auditors"], path.clone(), "auditors")?;
        for (id, user) in accounts.iter().enumerate() {
            let user = to_string(&user, path.clone(), "auditor.user")?;
            let user = user.to_lowercase();
            all_non_normal_accounts.push((
                Party::try_from((user.as_str(), PartyKind::Auditor))?,
                id.try_into().ok(),
            ));
        }
    }

    let mut accounts_outcome: HashSet<InputAccount> = HashSet::new();
    let outcomes = to_array(&config["outcome"], path.clone(), "outcome")?;
    for outcome in outcomes {
        let outcome_type = to_hash(&outcome, path.clone(), "outcome.key")?;
        for (key, value) in outcome_type {
            let key = to_string(key, path.clone(), "outcome.key")?;
            let accounts_for_user =
                to_array(&value, path.clone(), &format!("outcome.{}.ticker", key))?;
            let owner = key.clone();
            for accounts in accounts_for_user {
                let accounts =
                    to_hash(&accounts, path.clone(), &format!("outcome.{}.ticker", key))?;
                for (ticker, amount) in accounts {
                    let ticker =
                        to_string(&ticker, path.clone(), &format!("outcome.{}.ticker", owner))?;
                    let balance = amount
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
                    if ticker != "NONE" {
                        accounts_outcome.insert(InputAccount {
                            owner: Party::try_from((owner.as_str(), PartyKind::Normal))?,
                            ticker: ticker.clone(),
                            balance,
                        });
                    }
                }
            }
        }
    }

    let mut audit_outcome: HashSet<AuditExpectation> = HashSet::new();
    if config["audit_outcome"] != Yaml::BadValue {
        let outcomes = to_array(&config["audit_outcome"], path.clone(), "audit_outcome")?;
        for outcome in outcomes {
            let outcome_type = to_hash(&outcome, path.clone(), "audit_outcome.key")?;
            for (auditor, value) in outcome_type {
                let auditor = to_string(auditor, path.clone(), "audit_outcome.key")?;
                let auditted_transactions = to_array(
                    &value,
                    path.clone(),
                    &format!("audit_outcome.{}.transaction_names", auditor),
                )?;
                for transaction in auditted_transactions {
                    let transaction = to_hash(
                        &transaction,
                        path.clone(),
                        &format!("audit_outcome.{}.transaction_hashes", auditor),
                    )?;
                    for (tx_name, tx_status) in transaction {
                        let tx_name = to_string(
                            &tx_name,
                            path.clone(),
                            &format!("audit_outcome.{}.tx_name", auditor),
                        )?;
                        let tx_status = to_string(
                            &tx_status,
                            path.clone(),
                            &format!("audit_outcome.{}.tx_status", auditor),
                        )?;

                        audit_outcome.insert(AuditExpectation {
                            auditor: Party::try_from((auditor.as_str(), PartyKind::Auditor))?,
                            tx_name,
                            tx_status: AuditResult::try_from(tx_status)?,
                        });
                    }
                }
            }
        }
    }

    let (next_transaction_id, create_normal_account_transactions) =
        make_empty_normal_accounts(&all_normal_accounts)?;

    let (next_transaction_id, create_non_normal_account_transactions) =
        make_empty_non_normal_accounts(&all_non_normal_accounts, next_transaction_id)?;

    let create_account_transactions = TransactionMode::Sequence {
        repeat: 1,
        steps: create_normal_account_transactions
            .into_iter()
            .chain(create_non_normal_account_transactions.into_iter())
            .collect(),
    };

    // Declared mutable since later I want to consume a single element of it.
    let (_, mut transactions_list) = parse_transactions(
        &config["transactions"],
        path,
        "transactions",
        next_transaction_id,
    )?;

    let mut transactions = TransactionMode::Empty;
    if transactions_list.len() > 1 {
        return Err(Error::TopLevelTransaction);
    }
    if transactions_list.len() == 1 {
        transactions = TransactionMode::Sequence {
            repeat: 1,
            steps: vec![create_account_transactions, transactions_list.remove(0)],
        };
    }
    Ok(TestCase {
        title,
        ticker_names,
        transactions,
        accounts_outcome,
        audit_outcome,
        chain_db_dir,
    })
}

#[allow(unused)]
fn sets_are_equal<T: std::cmp::Eq + std::hash::Hash>(want: &HashSet<T>, got: &HashSet<T>) -> bool {
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

    // Do not fail if the top level directory does not exist
    if let Ok(configs) = all_files_in_dir(path) {
        for config in configs {
            let file_name = config.file_name().unwrap();
            let file_name = file_name.to_str().unwrap();
            if file_name.starts_with('_') {
                // skip the test case
                warn!("Skipping test case: {}", file_name);
                continue;
            }

            let mut separate_chain_db_dir = chain_db_dir.clone();
            separate_chain_db_dir.push(file_name);
            let testcase = &parse_config(config, separate_chain_db_dir).unwrap();
            info!("----------------------------------------------------------------------------------");
            info!("- Running test case: {}.", testcase.title);
            info!("----------------------------------------------------------------------------------");
            let want_accounts = &testcase.accounts_outcome;
            let want_audit_results = &testcase.audit_outcome;
            let got = testcase.run();
            match got {
                Err(error) => {
                    panic!(
                        "Test was expected to succeed, but failed with {:#?}.",
                        error
                    );
                }
                Ok((got_accounts, got_audit_results)) => {
                    assert!(
                        sets_are_equal::<InputAccount>(want_accounts, &got_accounts),
                        "Test failed due to account value mismatch.\nWant: {:#?}, got: {:#?}",
                        want_accounts,
                        got_accounts
                    );
                    assert!(
                        sets_are_equal::<AuditExpectation>(want_audit_results, &got_audit_results),
                        "Test failed due to audit results mismatch.\nWant: {:#?}, got: {:#?}",
                        want_audit_results,
                        got_audit_results
                    );
                }
            }
        }
    }
}

// ------------------------------------------------------------------------------------------------
// -                                            Tests                                             -
// ------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::init_print_logger;

    use log::debug;
    use std::sync::Once;
    use wasm_bindgen_test::*;

    static INIT: Once = Once::new();

    pub fn initialize() {
        INIT.call_once(|| {
            env_logger::init();
            init_print_logger();
        });
    }

    fn cleanup_previous_run(mode: &str) {
        let mut chain_db_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        chain_db_dir.push("chain_dir/unittest");
        chain_db_dir.push(mode);
        let res = std::fs::remove_dir_all(chain_db_dir);
        debug!("Ignoring the status of removing chain dir: {:?}", res);
    }

    #[test]
    fn test_on_slow_pc() {
        initialize();
        cleanup_previous_run("pc");
        run_from("pc");
    }

    #[test]
    fn test_on_fast_node() {
        initialize();
        cleanup_previous_run("node");
        run_from("node");
    }

    #[wasm_bindgen_test]
    fn test_on_wasm() {
        cleanup_previous_run("wasm");
        run_from("wasm");
    }

    #[test]
    fn test_parse_issue() {
        let issue = Issue::try_from((1, "invalid".to_string()));
        assert!(issue.is_err());

        assert_eq!(
            Issue::try_from((1, "issue Bob 40 ACME".to_string())).unwrap(),
            Issue {
                tx_id: 1,
                issuer: Party {
                    name: "bob".to_string(),
                    cheater: false,
                    kind: PartyKind::Normal,
                },
                ticker: "ACME".to_string(),
                amount: 40,
                auditors: vec![],
                tx_name: None,
            }
        );
        assert_eq!(
            Issue::try_from((2, "issue Bob(cheat) 40 ACME".to_string())).unwrap(),
            Issue {
                tx_id: 2,
                issuer: Party {
                    name: "bob".to_string(),
                    cheater: true,
                    kind: PartyKind::Normal,
                },
                ticker: "ACME".to_string(),
                amount: 40,
                auditors: vec![],
                tx_name: None,
            }
        );

        assert_eq!(
            Issue::try_from((
                3,
                "issue Bob(cheat) 40 ACME auditors Ava,Aubrey tx_name BobIssue".to_string(),
            ))
            .unwrap(),
            Issue {
                tx_id: 3,
                issuer: Party {
                    name: "bob".to_string(),
                    cheater: true,
                    kind: PartyKind::Normal,
                },
                ticker: "ACME".to_string(),
                amount: 40,
                auditors: vec![
                    Party {
                        name: "ava".to_string(),
                        cheater: false,
                        kind: PartyKind::Auditor,
                    },
                    Party {
                        name: "aubrey".to_string(),
                        cheater: false,
                        kind: PartyKind::Auditor,
                    }
                ],
                tx_name: Some("BobIssue".to_string()),
            }
        );
    }

    #[test]
    fn test_parse_transfer() {
        assert!(Transfer::try_from((1, "invalid".to_string())).is_err());
        assert_eq!(
            Transfer::try_from((
                2,
                "transfer Bob(cheat) 40 ACME Carol approve Marry reject".to_string()
            ))
            .unwrap(),
            Transfer {
                tx_id: 2,
                sender: Party {
                    name: "bob".to_string(),
                    cheater: true,
                    kind: PartyKind::Normal,
                },
                receiver: Party {
                    name: "carol".to_string(),
                    cheater: false,
                    kind: PartyKind::Normal,
                },
                receiver_approves: true,
                mediator: Party {
                    name: "marry".to_string(),
                    cheater: false,
                    kind: PartyKind::Mediator,
                },
                mediator_approves: false,
                amount: 40,
                ticker: "ACME".to_string(),
                auditors: vec![],
                tx_name: None,
            }
        );

        assert_eq!(
            Transfer::try_from((
                3,
                "transfer Bob(cheat) 40 ACME Carol approve Marry reject auditors Ava,Aubrey tx_name BobToAlice".to_string()
            ))
            .unwrap(),
            Transfer {
                tx_id: 3,
                sender: Party {
                    name: "bob".to_string(),
                    cheater: true,
                    kind: PartyKind::Normal,
                },
                receiver: Party {
                    name: "carol".to_string(),
                    cheater: false,
                    kind: PartyKind::Normal,
                },
                receiver_approves: true,
                mediator: Party {
                    name: "marry".to_string(),
                    cheater: false,
                    kind: PartyKind::Mediator,
                },
                mediator_approves: false,
                amount: 40,
                ticker: "ACME".to_string(),
                auditors: vec![
                    Party {
                        name: "ava".to_string(),
                        cheater: false,
                        kind: PartyKind::Auditor,
                    },
                    Party {
                        name: "aubrey".to_string(),
                        cheater: false,
                        kind: PartyKind::Auditor,
                    }
                ],
                tx_name: Some("BobToAlice".to_string()),
            }
        );
    }
    #[test]
    fn test_parse_audit() {
        assert!(Transfer::try_from((1, "invalid".to_string())).is_err());
        assert_eq!(
            Audit::try_from((2, "audit AliceIssue Ava".to_string())).unwrap(),
            Audit {
                tx_id: 2,
                tx_name: "AliceIssue".to_string(),
                auditor: Party {
                    name: "ava".to_string(),
                    cheater: false,
                    kind: PartyKind::Auditor,
                },
            }
        );
    }
}

fn path_to_string(path: &PathBuf) -> String {
    if let Some(path) = path.to_str() {
        String::from(path)
    } else {
        String::from(env!("CARGO_MANIFEST_DIR"))
    }
}
