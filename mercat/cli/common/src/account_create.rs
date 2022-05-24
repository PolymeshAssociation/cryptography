use crate::{
    account_create_transaction_file, create_rng_from_seed, errors::Error, get_asset_ids,
    non_empty_account_id, save_object, update_account_map, user_secret_account_file,
    OrderedPubAccountTx, OrderingState, PrintableAccountId, COMMON_OBJECTS_DIR, OFF_CHAIN_DIR,
    ON_CHAIN_DIR,
};
use codec::Encode;
use cryptography_core::asset_proofs::{asset_id_from_ticker, CommitmentWitness, ElgamalSecretKey};
use curve25519_dalek::scalar::Scalar;
use log::{error, info};
use mercat::{account::AccountCreator, AccountCreatorInitializer, EncryptionKeys, SecAccount};
use metrics::timing;
use rand::{CryptoRng, Rng, RngCore};
use std::{path::PathBuf, time::Instant};

pub fn process_create_account(
    seed: Option<String>,
    db_dir: PathBuf,
    ticker: String,
    user: String,
    stdout: bool,
    tx_id: u32,
    cheat: bool,
) -> Result<(), Error> {
    // Setup the rng.
    let mut rng = create_rng_from_seed(seed)?;

    // Create the account.
    let secret_account = create_secret_account(&mut rng, ticker.clone())?;
    let valid_asset_ids = get_asset_ids(db_dir.clone())?;

    let create_account_timer = Instant::now();
    let account_creator = AccountCreator;
    let mut account_tx = account_creator
        .create(&secret_account, &valid_asset_ids, &mut rng)
        .map_err(|error| Error::LibraryError { error })?;
    timing!("account.call_library", create_account_timer, Instant::now(), "tx_id" => tx_id.to_string());
    if cheat {
        // To simplify the cheating selection process, we randomly choose a cheating strategy,
        // instead of requiring the caller to know of all the different cheating strategies.
        let n: u32 = rng.gen_range(0..2);
        match n {
            0 => {
                info!("CLI log: tx-{}: Cheating by overwriting the asset id of the account. Correct ticker: {} and asset id: {:?}",
                      tx_id, ticker, secret_account.asset_id_witness.value());
                let cheat_asset_id =
                    asset_id_from_ticker("CHEAT").map_err(|error| Error::LibraryError { error })?;
                let cheat_asset_id_witness =
                    CommitmentWitness::new(cheat_asset_id.into(), Scalar::random(&mut rng));
                let cheat_enc_asset_id = secret_account
                    .enc_keys
                    .public
                    .encrypt(&cheat_asset_id_witness);
                account_tx.pub_account.enc_asset_id = cheat_enc_asset_id;
            }
            1 => {
                info!("CLI log: tx-{}: Cheating by overwriting the account id. Correct account id: {}",
                      tx_id, PrintableAccountId(account_tx.pub_account.enc_asset_id.encode()));
                account_tx.pub_account.enc_asset_id += non_empty_account_id();
            }
            _ => error!("CLI log: tx-{}: This should never happen!", tx_id),
        }
    }

    // Save the artifacts to file.
    let save_to_file_timer = Instant::now();
    save_object(
        db_dir.clone(),
        OFF_CHAIN_DIR,
        &user,
        &user_secret_account_file(&ticker),
        &secret_account,
    )?;

    let account_id = account_tx.pub_account.enc_asset_id;

    let instruction = OrderedPubAccountTx {
        account_tx,
        ordering_state: OrderingState::new(tx_id),
    };
    save_object(
        db_dir.clone(),
        ON_CHAIN_DIR,
        COMMON_OBJECTS_DIR,
        &account_create_transaction_file(tx_id, &user, &ticker),
        &instruction,
    )?;

    if stdout {
        info!(
            "CLI log: tx-{}: Transaction as base64:\n{}\n",
            tx_id,
            base64::encode(instruction.account_tx.encode())
        );
    }

    update_account_map(db_dir, user, ticker, account_id, tx_id)?;

    timing!("account.save_output", save_to_file_timer, Instant::now(), "tx_id" => tx_id.to_string());

    Ok(())
}

fn create_secret_account<R: RngCore + CryptoRng>(
    rng: &mut R,
    ticker_id: String,
) -> Result<SecAccount, Error> {
    let elg_secret = ElgamalSecretKey::new(Scalar::random(rng));
    let elg_pub = elg_secret.get_public_key();
    let enc_keys = EncryptionKeys {
        public: elg_pub,
        secret: elg_secret,
    };

    let asset_id =
        asset_id_from_ticker(&ticker_id).map_err(|error| Error::LibraryError { error })?;
    let asset_id_witness = CommitmentWitness::new(asset_id.into(), Scalar::random(rng));

    Ok(SecAccount {
        enc_keys,
        asset_id_witness,
    })
}
