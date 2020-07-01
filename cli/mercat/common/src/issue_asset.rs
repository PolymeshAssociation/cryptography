use crate::{
    asset_transaction_file, calc_account_id, create_rng_from_seed, errors::Error, load_object,
    save_object, Instruction, OFF_CHAIN_DIR, ON_CHAIN_DIR, PUBLIC_ACCOUNT_FILE,
    SECRET_ACCOUNT_FILE,
};
use codec::Encode;
use cryptography::mercat::{asset::CtxIssuer, AccountMemo, AssetTransactionIssuer, SecAccount};
use metrics::timing;
use std::{path::PathBuf, time::Instant};

pub fn process_issue_asset(
    seed: String,
    db_dir: PathBuf,
    issuer: String,
    mediator: String,
    ticker: String,
    amount: u32,
    tx_id: u32,
) -> Result<(), Error> {
    let mut rng = create_rng_from_seed(Some(seed))?;
    let load_from_file_timer = Instant::now();

    let issuer_account: SecAccount = load_object(
        db_dir.clone(),
        OFF_CHAIN_DIR,
        &issuer,
        &format!("{}_{}", ticker, SECRET_ACCOUNT_FILE),
    )?;

    let mediator_account: AccountMemo = load_object(
        db_dir.clone(),
        ON_CHAIN_DIR,
        &mediator,
        &format!("{}_{}", ticker, PUBLIC_ACCOUNT_FILE),
    )?;

    timing!(
        "account.issue_asset.load_from_file",
        load_from_file_timer,
        Instant::now()
    );

    // Initialize the asset issuance process.
    let issuance_init_timer = Instant::now();
    let ctx_issuer = CtxIssuer {};
    let (asset_tx, state) = ctx_issuer
        .initialize(
            calc_account_id(issuer.clone(), ticker),
            &issuer_account,
            &mediator_account.owner_enc_pub_key,
            amount,
            &mut rng,
        )
        .map_err(|error| Error::LibraryError { error })?;

    timing!(
        "account.issue_asset.init",
        issuance_init_timer,
        Instant::now()
    );

    // Save the artifacts to file.
    let save_to_file_timer = Instant::now();
    let instruction = Instruction {
        state,
        data: asset_tx.encode().to_vec(),
    };

    save_object(
        db_dir,
        ON_CHAIN_DIR,
        &issuer,
        &asset_transaction_file(tx_id, state),
        &instruction,
    )?;

    timing!(
        "account.issue_asset.save_to_file",
        save_to_file_timer,
        Instant::now()
    );

    Ok(())
}
