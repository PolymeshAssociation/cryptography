//! A simple commandline application to act as a MERCAT mediator.
//! Use `mercat_mediator --help` to see the usage.
//!

mod input;
use codec::{Decode, Encode};
use cryptography::{
    asset_proofs::ElgamalSecretKey,
    mercat::{
        asset::AssetTxIssueMediator, AccountMemo, AssetTransactionMediator, AssetTxState,
        EncryptionKeys, MediatorAccount, PubAccount, PubAssetTxData, TxSubstate,
    },
};
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use schnorrkel::{ExpansionMode, MiniSecretKey};

use mercat_common::{
    construct_path, create_rng_from_seed, errors::Error, init_print_logger, load_object,
    save_object, transaction_file, Instruction, OFF_CHAIN_DIR, ON_CHAIN_DIR, PUBLIC_ACCOUNT_FILE,
    SECRET_ACCOUNT_FILE,
};

use env_logger;
use input::{parse_input, CreateMediatorAccountInfo, CLI};
use log::info;
use metrics::timing;
use std::time::Instant;

fn generate_mediator_keys<R: RngCore + CryptoRng>(rng: &mut R) -> (AccountMemo, MediatorAccount) {
    let mediator_elg_secret_key = ElgamalSecretKey::new(Scalar::random(rng));
    let mediator_enc_key = EncryptionKeys {
        pblc: mediator_elg_secret_key.get_public_key().into(),
        scrt: mediator_elg_secret_key.into(),
    };

    let mediator_signing_pair =
        MiniSecretKey::generate_with(rng).expand_to_keypair(ExpansionMode::Ed25519);

    (
        AccountMemo::new(mediator_enc_key.pblc, mediator_signing_pair.public),
        MediatorAccount {
            encryption_key: mediator_enc_key,
            signing_key: mediator_signing_pair,
        },
    )
}

fn process_create_mediator(cfg: CreateMediatorAccountInfo) -> Result<(), Error> {
    // Setup the rng
    let mut rng = create_rng_from_seed(cfg.seed)?;

    let db_dir = cfg.db_dir.ok_or(Error::EmptyDatabaseDir)?;

    // Generate keys for the mediator.
    let (public_account, private_account) = generate_mediator_keys(&mut rng);

    save_object(
        db_dir.clone(),
        ON_CHAIN_DIR,
        &cfg.user,
        PUBLIC_ACCOUNT_FILE,
        &public_account,
    )?;

    save_object(
        db_dir,
        OFF_CHAIN_DIR,
        &cfg.user,
        SECRET_ACCOUNT_FILE,
        &private_account,
    )?;

    Ok(())
}

// todo get rid of all unwraps... timing
fn justify_asset_issuance(cfg: input::IssueAssetInfo) -> Result<(), Error> {
    // Load the transaction, mediator's credentials, and issuer's public account.
    let db_dir = cfg.clone().db_dir.ok_or(Error::EmptyDatabaseDir)?;

    let instruction: Instruction = load_object(
        db_dir.clone(),
        ON_CHAIN_DIR,
        &cfg.issuer,
        &transaction_file(
            cfg.tx_id,
            AssetTxState::Initialization(TxSubstate::Validated),
        ),
    )?;

    let asset_tx = PubAssetTxData::decode(&mut &instruction.data[..]).map_err(|error| {
        Error::ObjectLoadError {
            error,
            path: construct_path(
                db_dir.clone(),
                ON_CHAIN_DIR,
                &cfg.issuer,
                PUBLIC_ACCOUNT_FILE,
            ),
        }
    })?;

    let mediator_account: MediatorAccount = load_object(
        db_dir.clone(),
        OFF_CHAIN_DIR,
        &cfg.mediator,
        SECRET_ACCOUNT_FILE,
    )?;

    let issuer_account: PubAccount = load_object(
        db_dir.clone(),
        ON_CHAIN_DIR,
        &cfg.issuer.clone(),
        PUBLIC_ACCOUNT_FILE,
    )?;

    // Justification
    let mediator = AssetTxIssueMediator {};
    let (justified_tx, updated_issuer_account) = mediator
        .justify_and_process(
            asset_tx,
            &issuer_account,
            instruction.state,
            &mediator_account.encryption_key,
            &mediator_account.signing_key,
        )
        .map_err(|error| Error::LibraryError { error })?;

    assert_eq!(
        justified_tx.content.state,
        AssetTxState::Justification(TxSubstate::Started)
    );

    // Save the updated_issuer_account, and the justified transaction.
    let next_instruction = Instruction {
        data: justified_tx.encode().to_vec(),
        state: justified_tx.content.state,
    };

    save_object(
        db_dir.clone(),
        ON_CHAIN_DIR,
        &cfg.issuer,
        PUBLIC_ACCOUNT_FILE,
        &updated_issuer_account,
    )?;

    save_object(
        db_dir,
        ON_CHAIN_DIR,
        &cfg.issuer,
        &transaction_file(cfg.tx_id, justified_tx.content.state),
        &next_instruction,
    )?;

    Ok(())
}

fn main() {
    info!("Starting the program.");
    env_logger::init();
    init_print_logger();

    let parse_arg_timer = Instant::now();
    let args = parse_input().unwrap();
    timing!("mediator.argument_parse", parse_arg_timer, Instant::now());

    match args {
        CLI::Create(cfg) => process_create_mediator(cfg).unwrap(),
        CLI::JustifyIssuance(cfg) => justify_asset_issuance(cfg).unwrap(),
    };

    info!("The program finished successfully.");
}
