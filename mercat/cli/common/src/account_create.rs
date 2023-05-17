use crate::{
    account_create_transaction_file, create_rng_from_seed, errors::Error, save_object,
    update_account_map, user_secret_account_file, OrderedPubAccountTx, OrderingState,
    COMMON_OBJECTS_DIR, OFF_CHAIN_DIR, ON_CHAIN_DIR,
};
use codec::Encode;
use confidential_identity_core::asset_proofs::ElgamalSecretKey;
use curve25519_dalek::scalar::Scalar;
use log::info;
use mercat::{account::AccountCreator, AccountCreatorInitializer, EncryptionKeys, SecAccount};
use metrics::timing;
use rand::{CryptoRng, RngCore};
use std::{path::PathBuf, time::Instant};

pub fn process_create_account(
    seed: Option<String>,
    db_dir: PathBuf,
    ticker: String,
    user: String,
    stdout: bool,
    tx_id: u32,
) -> Result<(), Error> {
    // Setup the rng.
    let mut rng = create_rng_from_seed(seed)?;

    // Create the account.
    let secret_account = create_secret_account(&mut rng)?;

    let create_account_timer = Instant::now();
    let account_creator = AccountCreator;
    let account_tx = account_creator
        .create(&secret_account, &mut rng)
        .map_err(|error| Error::LibraryError { error })?;
    timing!("account.call_library", create_account_timer, Instant::now(), "tx_id" => tx_id.to_string());

    // Save the artifacts to file.
    let save_to_file_timer = Instant::now();
    save_object(
        db_dir.clone(),
        OFF_CHAIN_DIR,
        &user,
        &user_secret_account_file(&ticker),
        &secret_account,
    )?;

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
            "CLI log: tx-{}: Transaction as hex:\n{}\n",
            tx_id,
            hex::encode(instruction.account_tx.encode())
        );
    }

    update_account_map(db_dir, user, &secret_account.enc_keys.public, ticker, tx_id)?;

    timing!("account.save_output", save_to_file_timer, Instant::now(), "tx_id" => tx_id.to_string());

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
