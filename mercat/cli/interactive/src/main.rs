//! A simple command-line application to act as a Wallet. Can be used to interact with the Polymesh chain.
//! Use `mercat_interactive --help` to see the usage.

mod input;

use codec::{Decode, Encode};
use confidential_identity_core::asset_proofs::ElgamalSecretKey;
use curve25519_dalek::scalar::Scalar;

use input::{parse_input, CLI};
use log::info;
use mercat::{
    account::AccountCreator,
    transaction::{CtxMediator, CtxReceiver, CtxSender},
    Account, AccountCreatorInitializer, EncryptedAmount, EncryptionKeys, EncryptionPubKey,
    FinalizedTransferTx, InitializedTransferTx, MediatorAccount, PubAccount, SecAccount,
    TransferTransactionMediator, TransferTransactionReceiver, TransferTransactionSender,
};
use mercat_common::{
    account_issue::process_issue_asset, create_rng_from_seed, debug_decrypt_base64_account_balance,
    errors::Error, init_print_logger, justify::process_create_mediator, load_object, save_object,
    user_public_account_file, user_secret_account_file, OrderedPubAccount, OFF_CHAIN_DIR,
    ON_CHAIN_DIR, SECRET_ACCOUNT_FILE,
};
use rand::{CryptoRng, RngCore};
use std::path::PathBuf;

const TX_ID: u32 = 1;

enum Op {
    Add,
    Subtract,
}

fn main() {
    env_logger::init();
    info!("Starting the program.");
    init_print_logger();

    let args = parse_input();

    match args {
        CLI::CreateUserAccount(cfg) => {
            let db_dir = cfg.db_dir.ok_or(Error::EmptyDatabaseDir).unwrap();
            process_create_account(cfg.seed, db_dir, cfg.user, cfg.ticker).unwrap()
        }
        CLI::CreateMediatorAccount(cfg) => process_create_mediator(
            cfg.seed.ok_or(Error::EmptySeed).unwrap(),
            cfg.db_dir.ok_or(Error::EmptyDatabaseDir).unwrap(),
            cfg.user,
        )
        .map(drop)
        .unwrap(),
        CLI::Mint(cfg) => process_issue_asset(
            cfg.seed.ok_or(Error::EmptySeed).unwrap(),
            cfg.db_dir.ok_or(Error::EmptyDatabaseDir).unwrap(),
            cfg.issuer,
            cfg.account_id_from_ticker,
            cfg.amount,
            true,
            TX_ID,
            false,
        )
        .map(drop)
        .unwrap(),
        CLI::CreateTransaction(cfg) => process_create_tx(
            cfg.seed.ok_or(Error::EmptySeed).unwrap(),
            cfg.db_dir.ok_or(Error::EmptyDatabaseDir).unwrap(),
            cfg.sender,
            cfg.receiver,
            cfg.mediator,
            cfg.account_id_from_ticker,
            cfg.amount,
            cfg.pending_balance,
        )
        .unwrap(),
        CLI::FinalizeTransaction(cfg) => process_finalize_tx(
            cfg.db_dir.ok_or(Error::EmptyDatabaseDir).unwrap(),
            cfg.receiver,
            cfg.account_id_from_ticker,
            cfg.amount,
            cfg.init_tx,
        )
        .unwrap(),
        CLI::JustifyTransaction(cfg) => justify_asset_transfer_transaction(
            cfg.seed.ok_or(Error::EmptySeed).unwrap(),
            cfg.db_dir.ok_or(Error::EmptyDatabaseDir).unwrap(),
            cfg.sender,
            cfg.sender_balance,
            cfg.receiver,
            cfg.mediator,
            cfg.init_tx,
            cfg.finalized_tx,
        )
        .unwrap(),
        CLI::Decrypt(cfg) => info!(
            "Account balance: {}",
            debug_decrypt_base64_account_balance(
                cfg.user,
                cfg.encrypted_value,
                cfg.ticker,
                cfg.db_dir.ok_or(Error::EmptyDatabaseDir).unwrap()
            )
            .unwrap()
        ),
        CLI::Add(cfg) => info!("Result: {}", add_subtract(Op::Add, cfg.first, cfg.second,)),
        CLI::Subtract(cfg) => info!(
            "Result: {}",
            add_subtract(Op::Subtract, cfg.first, cfg.second,)
        ),
    };
    info!("The program finished successfully.");
}

fn process_create_account(
    seed: Option<String>,
    db_dir: PathBuf,
    user: String,
    ticker: String,
) -> Result<(), Error> {
    let mut rng = create_rng_from_seed(seed)?;

    // Create the account.
    let secret_account = create_secret_account(&mut rng)?;

    let account_tx = AccountCreator
        .create(&secret_account, &mut rng)
        .map_err(|error| Error::LibraryError { error })?;

    // Save the artifacts to file.
    save_object(
        db_dir.clone(),
        OFF_CHAIN_DIR,
        &user,
        &user_secret_account_file(&ticker),
        &secret_account,
    )?;

    info!(
        "CLI log: tx-{}:\n\nAccount Transaction as base64:\n{}\n",
        TX_ID,
        base64::encode(account_tx.encode())
    );

    let ordered_account = OrderedPubAccount {
        pub_account: account_tx.pub_account,
        last_processed_tx_counter: Some(TX_ID),
    };
    save_object(
        db_dir,
        ON_CHAIN_DIR,
        &user,
        &user_public_account_file(&ticker),
        &ordered_account,
    )?;

    Ok(())
}

fn create_secret_account<R: RngCore + CryptoRng>(rng: &mut R) -> Result<SecAccount, Error> {
    let elg_secret = ElgamalSecretKey::new(Scalar::random(rng));
    let elg_pub = elg_secret.get_public_key();
    let enc_keys = EncryptionKeys {
        public: elg_pub,
        secret: elg_secret,
    };

    Ok(SecAccount { enc_keys })
}

pub fn process_create_tx(
    seed: String,
    db_dir: PathBuf,
    sender: String,
    receiver: String,
    mediator: String,
    ticker: String,
    amount: u32,
    pending_enc_balance: String,
) -> Result<(), Error> {
    let mut rng = create_rng_from_seed(Some(seed))?;

    let sender_ordered_pub_account: OrderedPubAccount = load_object(
        db_dir.clone(),
        ON_CHAIN_DIR,
        &sender,
        &user_public_account_file(&ticker),
    )?;
    let sender_account = Account {
        secret: load_object(
            db_dir,
            OFF_CHAIN_DIR,
            &sender,
            &user_secret_account_file(&ticker),
        )?,
        public: sender_ordered_pub_account.pub_account,
    };

    // Calculate the pending
    let mut data: &[u8] = &base64::decode(pending_enc_balance).unwrap();
    let pending_enc_balance = EncryptedAmount::decode(&mut data).unwrap(); // For now the same as initial balance
    let pending_balance = sender_account.secret.enc_keys.secret.decrypt(&pending_enc_balance)
        .map_err(|error| Error::LibraryError { error })?;

    let mut data1: &[u8] = &base64::decode(&receiver).unwrap();
    let receiver_pub_account = PubAccount {
        owner_enc_pub_key: EncryptionPubKey::decode(&mut data1).unwrap(),
    };

    let mut data: &[u8] = &base64::decode(mediator).unwrap();
    let mediator_account = EncryptionPubKey::decode(&mut data).unwrap();

    // Initialize the transaction.
    let ctx_sender = CtxSender {};
    let pending_account = Account {
        secret: sender_account.secret,
        public: PubAccount {
            owner_enc_pub_key: sender_account.public.owner_enc_pub_key,
        },
    };
    let asset_tx = ctx_sender
        .create_transaction(
            &pending_account,
            &pending_enc_balance,
            pending_balance,
            &receiver_pub_account,
            &mediator_account,
            &[],
            amount,
            &mut rng,
        )
        .map_err(|error| Error::LibraryError { error })?;

    info!(
        "CLI log: Initialized Transaction as base64:\n{}\n",
        base64::encode(asset_tx.encode())
    );

    Ok(())
}

pub fn process_finalize_tx(
    db_dir: PathBuf,
    receiver: String,
    ticker: String,
    amount: u32,
    init_tx: String,
) -> Result<(), Error> {
    let receiver_ordered_pub_account: OrderedPubAccount = load_object(
        db_dir.clone(),
        ON_CHAIN_DIR,
        &receiver,
        &user_public_account_file(&ticker),
    )?;

    let receiver_account = Account {
        secret: load_object(
            db_dir,
            OFF_CHAIN_DIR,
            &receiver,
            &user_secret_account_file(&ticker),
        )?,
        public: receiver_ordered_pub_account.pub_account,
    };

    let mut data: &[u8] = &base64::decode(&init_tx).unwrap();
    let tx = InitializedTransferTx::decode(&mut data).unwrap();

    // Finalize the transaction.
    let receiver = CtxReceiver {};
    let asset_tx = receiver
        .finalize_transaction(&tx, receiver_account, amount)
        .map_err(|error| Error::LibraryError { error })?;

    // Save the artifacts to file.
    info!(
        "CLI log: Finalized Transaction as base64:\n{}\n",
        base64::encode(asset_tx.encode())
    );

    Ok(())
}

pub fn justify_asset_transfer_transaction(
    seed: String,
    db_dir: PathBuf,
    sender: String,
    sender_balance: String,
    receiver: String,
    mediator: String,
    init_tx: String,
    finalized_tx: String,
) -> Result<(), Error> {
    // Load the transaction, mediator's credentials, and issuer's public account.
    let mut rng = create_rng_from_seed(Some(seed))?;

    let mut data: &[u8] = &base64::decode(&init_tx).unwrap();
    let init_tx = InitializedTransferTx::decode(&mut data).unwrap();
    let mut data: &[u8] = &base64::decode(&finalized_tx).unwrap();
    let finalized_tx = FinalizedTransferTx::decode(&mut data).unwrap();

    let mediator_account: MediatorAccount =
        load_object(db_dir, OFF_CHAIN_DIR, &mediator, SECRET_ACCOUNT_FILE)?;

    let mut data1: &[u8] = &base64::decode(&sender).unwrap();
    let sender_pub_account = PubAccount {
        owner_enc_pub_key: EncryptionPubKey::decode(&mut data1).unwrap(),
    };

    let mut data: &[u8] = &base64::decode(&sender_balance).unwrap();
    let sender_balance = EncryptedAmount::decode(&mut data).unwrap();

    let mut data1: &[u8] = &base64::decode(&receiver).unwrap();
    let receiver_pub_account = PubAccount {
        owner_enc_pub_key: EncryptionPubKey::decode(&mut data1).unwrap(),
    };

    // Justification.

    let justified_tx = CtxMediator {}
        .justify_transaction(
            &init_tx,
            &finalized_tx,
            &mediator_account.encryption_key,
            &sender_pub_account,
            &sender_balance,
            &receiver_pub_account,
            &[],
            &mut rng,
        )
        .map_err(|error| Error::LibraryError { error })?;

    info!(
        "CLI log: Justified Transaction as base64:\n{}\n",
        base64::encode(justified_tx.encode())
    );

    Ok(())
}

fn add_subtract(op: Op, first: String, second: String) -> String {
    let mut data: &[u8] = &base64::decode(first).unwrap();
    let first = EncryptedAmount::decode(&mut data).unwrap();
    let mut data: &[u8] = &base64::decode(second).unwrap();
    let second = EncryptedAmount::decode(&mut data).unwrap();

    match op {
        Op::Add => base64::encode((first + second).encode()),
        Op::Subtract => base64::encode((first - second).encode()),
    }
}
