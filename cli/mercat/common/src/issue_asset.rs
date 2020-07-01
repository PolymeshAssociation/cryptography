use crate::{
    asset_transaction_file, errors::Error, load_object, save_object, Instruction, OFF_CHAIN_DIR,
    ON_CHAIN_DIR, PUBLIC_ACCOUNT_FILE, SECRET_ACCOUNT_FILE,
};
use codec::Encode;
use cryptography::mercat::{asset::CtxIssuer, AccountMemo, AssetTransactionIssuer, SecAccount};
use metrics::timing;
use rand::{CryptoRng, RngCore};
use std::{path::PathBuf, time::Instant};

pub fn process_issue_asset<T: RngCore + CryptoRng>(
    rng: &mut T,
    db_dir: PathBuf,
    issuer: String,
    mediator: String,
    account_id: u32,
    amount: u32,
    tx_id: u32,
) -> Result<(), Error> {
    let load_from_file_timer = Instant::now();

    let issuer_account: SecAccount =
        load_object(db_dir.clone(), OFF_CHAIN_DIR, &issuer, SECRET_ACCOUNT_FILE)?;

    let mediator_account: AccountMemo =
        load_object(db_dir.clone(), ON_CHAIN_DIR, &mediator, PUBLIC_ACCOUNT_FILE)?;

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
            account_id,
            &issuer_account,
            &mediator_account.owner_enc_pub_key,
            amount,
            rng,
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
