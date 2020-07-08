use crate::{
    asset_transaction_file, calc_account_id, create_rng_from_seed, errors::Error, load_object,
    save_object, Instruction, OFF_CHAIN_DIR, ON_CHAIN_DIR, PUBLIC_ACCOUNT_FILE,
    SECRET_ACCOUNT_FILE,
};
use codec::Encode;
use cryptography::{
    asset_id_from_ticker,
    asset_proofs::CommitmentWitness,
    mercat::{
        asset::AssetIssuer, AccountMemo, AssetTransactionIssuer, AssetTxState, SecAccount,
        TxSubstate,
    },
};
use curve25519_dalek::scalar::Scalar;
use lazy_static::lazy_static;
use log::info;
use metrics::timing;
use rand::Rng;
use schnorrkel::{context::SigningContext, signing_context};
use std::{path::PathBuf, time::Instant};

lazy_static! {
    static ref SIG_CTXT: SigningContext = signing_context(b"mercat/asset");
}

pub fn process_issue_asset(
    seed: String,
    db_dir: PathBuf,
    issuer: String,
    mediator: String,
    ticker: String,
    amount: u32,
    tx_id: u32,
    cheat: bool,
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
        &PUBLIC_ACCOUNT_FILE,
    )?;

    timing!(
        "account.issue_asset.load_from_file",
        load_from_file_timer,
        Instant::now()
    );

    let mut amount = amount;
    // To simplify the cheating selection process, we randomly choose a cheating strategy,
    // instead of requiring the caller to know of all the different cheating strategies.
    let cheating_strategy: u32 = rng.gen_range(1, 2); // TODO: CRYP-111: see below

    // The first cheating strategies make changes to the input, while the 2nd one
    // changes the output.
    if cheat && cheating_strategy == 0 {
        // TODO: CRYP-111: At the moment, this cheating is not detected since the mediator's
        //       off-chain knowledge is not reflected in the MERACT calls. As a result, the
        //       the mediator has no way of knowing whether the provided amount is what it
        //       should be or not.
        info!(
            "CLI log: tx-{}: Cheating by changing the agreed upon amount. Correct amount: {}",
            tx_id, amount
        );
        amount += 1
    }

    // Initialize the asset issuance process.
    let issuance_init_timer = Instant::now();
    let ctx_issuer = AssetIssuer {};
    let mut asset_tx = ctx_issuer
        .initialize_asset_transaction(
            calc_account_id(issuer.clone(), ticker.clone()),
            &issuer_account,
            &mediator_account.owner_enc_pub_key,
            amount,
            &mut rng,
        )
        .map_err(|error| Error::LibraryError { error })?;

    if cheat && cheating_strategy == 1 {
        info!("CLI log: tx-{}: Cheating by overwriting the asset id of the account. Correct ticker: {} and asset id: {:?}",
                      tx_id, ticker, issuer_account.asset_id_witness.value());
        let cheat_asset_id =
            asset_id_from_ticker("CHEAT").map_err(|error| Error::LibraryError { error })?;
        let cheat_asset_id_witness =
            CommitmentWitness::new(cheat_asset_id.clone().into(), Scalar::random(&mut rng));
        let cheat_enc_asset_id = issuer_account
            .clone()
            .enc_keys
            .pblc
            .encrypt(&cheat_asset_id_witness);

        asset_tx.content.enc_asset_id = cheat_enc_asset_id;
        let message = asset_tx.content.encode();
        asset_tx.sig = issuer_account
            .clone()
            .sign_keys
            .sign(SIG_CTXT.bytes(&message));
    }
    timing!(
        "account.issue_asset.init",
        issuance_init_timer,
        Instant::now()
    );

    // Save the artifacts to file.
    let state = AssetTxState::Initialization(TxSubstate::Started);
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
