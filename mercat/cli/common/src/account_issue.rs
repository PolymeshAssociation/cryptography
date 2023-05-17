use crate::{
    asset_transaction_file, create_rng_from_seed, errors::Error, last_ordering_state, load_object,
    save_object, user_public_account_file, user_secret_account_file, InitializedAssetTx,
    OrderedAssetInstruction, OrderedPubAccount, OrderingState, COMMON_OBJECTS_DIR, OFF_CHAIN_DIR,
    ON_CHAIN_DIR,
};
use codec::Encode;
use confidential_identity_core::asset_proofs::{asset_id_from_ticker, Balance, CommitmentWitness};
use curve25519_dalek::scalar::Scalar;
use log::info;
use mercat::{asset::AssetIssuer, Account, AssetTransactionIssuer, AssetTxState, TxSubstate};
use metrics::timing;
use rand::Rng;
use std::{path::PathBuf, time::Instant};

pub fn process_issue_asset(
    seed: String,
    db_dir: PathBuf,
    issuer: String,
    ticker: String,
    amount: Balance,
    stdout: bool,
    tx_id: u32,
    cheat: bool,
) -> Result<InitializedAssetTx, Error> {
    let mut rng = create_rng_from_seed(Some(seed))?;

    let load_from_file_timer = Instant::now();
    let issuer_ordered_pub_account: OrderedPubAccount = load_object(
        db_dir.clone(),
        ON_CHAIN_DIR,
        &issuer,
        &user_public_account_file(&ticker),
    )?;
    let issuer_account = Account {
        public: issuer_ordered_pub_account.pub_account,
        secret: load_object(
            db_dir.clone(),
            OFF_CHAIN_DIR,
            &issuer,
            &user_secret_account_file(&ticker),
        )?,
    };

    timing!(
        "account.issue_asset.load_from_file",
        load_from_file_timer,
        Instant::now(),
        "tx_id" => tx_id.to_string()
    );

    // Calculate the pending
    let calc_pending_state_timer = Instant::now();
    let ordering_state = last_ordering_state(
        issuer.clone(),
        issuer_ordered_pub_account.last_processed_tx_counter,
        tx_id,
        db_dir.clone(),
    )?;
    let next_pending_tx_counter = ordering_state.last_pending_tx_counter + 1;

    timing!(
        "account.finalize_tx.calc_pending_state",
        calc_pending_state_timer,
        Instant::now(),
        "tx_id" => tx_id.to_string()
    );

    let mut amount = amount;
    // To simplify the cheating selection process, we randomly choose a cheating strategy,
    // instead of requiring the caller to know of all the different cheating strategies.
    let cheating_strategy: u32 = rng.gen_range(1..2); // TODO: CRYP-111: see below

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
    let ctx_issuer = AssetIssuer;
    let mut asset_tx = ctx_issuer
        .initialize_asset_transaction(&issuer_account, &[], amount, &mut rng)
        .map_err(|error| Error::LibraryError { error })?;

    let ordering_state = OrderingState {
        last_processed_tx_counter: issuer_ordered_pub_account.last_processed_tx_counter,
        last_pending_tx_counter: next_pending_tx_counter,
        tx_id,
    };

    if cheat && cheating_strategy == 1 {
        info!("CLI log: tx-{}: Cheating by overwriting the encrypted issued amount. Correct ticker: {} and encrypted amount: {:?}",
                      tx_id, ticker, &asset_tx.memo.enc_issued_amount);
        let cheat_asset_id =
            asset_id_from_ticker("CHEAT").map_err(|error| Error::LibraryError { error })?;
        let cheat_asset_id_witness =
            CommitmentWitness::new(cheat_asset_id.into(), Scalar::random(&mut rng));
        let cheat_enc_asset_id = issuer_account
            .secret
            .enc_keys
            .public
            .encrypt(&cheat_asset_id_witness);

        asset_tx.memo.enc_issued_amount = cheat_enc_asset_id;
    }
    timing!(
        "account.issue_asset.init",
        issuance_init_timer,
        Instant::now()
    );

    // Save the artifacts to file.
    let state = AssetTxState::Initialization(TxSubstate::Started);
    let save_to_file_timer = Instant::now();
    let instruction = OrderedAssetInstruction {
        state,
        ordering_state,
        data: asset_tx.encode().to_vec(),
        amount,
    };

    save_object(
        db_dir,
        ON_CHAIN_DIR,
        COMMON_OBJECTS_DIR,
        &asset_transaction_file(tx_id, &issuer, state),
        &instruction,
    )?;

    if stdout {
        info!(
            "CLI log: tx-{}: Transaction as hex:\n{}\n",
            tx_id,
            hex::encode(asset_tx.encode())
        );
    }

    timing!(
        "account.issue_asset.save_to_file",
        save_to_file_timer,
        Instant::now(),
        "tx_id" => tx_id.to_string()
    );

    Ok(asset_tx)
}
