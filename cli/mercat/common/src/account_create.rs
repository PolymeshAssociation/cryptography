use crate::{
    calc_account_id, create_rng_from_seed, errors::Error, get_asset_ids, save_object,
    OFF_CHAIN_DIR, ON_CHAIN_DIR, PUBLIC_ACCOUNT_FILE, SECRET_ACCOUNT_FILE,
};
use codec::Encode;
use cryptography::{
    asset_id_from_ticker,
    asset_proofs::{CommitmentWitness, ElgamalSecretKey},
    mercat::{
        account::AccountCreator, AccountCreatorInitializer, EncryptedAssetId, EncryptionKeys,
        SecAccount,
    },
};
use curve25519_dalek::scalar::Scalar;
use lazy_static::lazy_static;
use log::{error, info};
use metrics::timing;
use rand::{CryptoRng, Rng, RngCore};
use schnorrkel::{context::SigningContext, signing_context};
use schnorrkel::{ExpansionMode, MiniSecretKey};
use std::{path::PathBuf, time::Instant};

lazy_static! {
    static ref SIG_CTXT: SigningContext = signing_context(b"mercat/account");
}

pub fn process_create_account(
    seed: Option<String>,
    db_dir: PathBuf,
    ticker: String,
    user: String,
    cheat: bool,
    tx_id: u32,
) -> Result<(), Error> {
    // Setup the rng
    let mut rng = create_rng_from_seed(seed)?;

    // Create the account
    let secret_account = create_secret_account(&mut rng, ticker.clone())?;
    let valid_asset_ids = get_asset_ids(db_dir.clone())?;
    let account_id = calc_account_id(user.clone(), ticker.clone());

    let create_account_timer = Instant::now();
    let account_creator = AccountCreator {};
    let mut account = account_creator
        .create(
            secret_account.clone(),
            &valid_asset_ids,
            account_id,
            &mut rng,
        )
        .map_err(|error| Error::LibraryError { error })?;
    timing!("account.call_library", create_account_timer, Instant::now());
    if cheat {
        // To simplify the cheating selection process, we randomly choose a cheating strategy,
        // instead of requiring the caller to know of all the different cheating strategies.
        let n: u32 = rng.gen_range(0, 2);
        match n {
            0 => {
                info!("CLI log: tx-{}: Cheating by overwriting the asset id of the account. Correct ticker: {} and asset id: {:?}",
                      tx_id, ticker, account.scrt.asset_id_witness.value());
                let cheat_asset_id =
                    asset_id_from_ticker("CHEAT").map_err(|error| Error::LibraryError { error })?;
                let cheat_asset_id_witness =
                    CommitmentWitness::new(cheat_asset_id.clone().into(), Scalar::random(&mut rng));
                let cheat_enc_asset_id = secret_account
                    .clone()
                    .enc_keys
                    .pblc
                    .encrypt(&cheat_asset_id_witness);
                // the encrypted asset id and update the signature
                account.pblc.content.enc_asset_id = EncryptedAssetId::from(cheat_enc_asset_id);
                let message = account.pblc.content.encode();
                account.pblc.initial_sig = secret_account
                    .clone()
                    .sign_keys
                    .sign(SIG_CTXT.bytes(&message));
            }
            1 => {
                info!("CLI log: tx-{}: Cheating by overwriting the account id but not the signature. Correct account id: {}",
                      tx_id, account.pblc.content.id);
                account.pblc.content.id += 1;
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
        &format!("{}_{}", ticker, SECRET_ACCOUNT_FILE),
        &account.scrt,
    )?;

    save_object(
        db_dir,
        ON_CHAIN_DIR,
        &user,
        &format!("{}_{}", ticker, PUBLIC_ACCOUNT_FILE),
        &account.pblc,
    )?;

    timing!("account.save_output", save_to_file_timer, Instant::now());

    Ok(())
}

fn create_secret_account<R: RngCore + CryptoRng>(
    rng: &mut R,
    ticker_id: String,
) -> Result<SecAccount, Error> {
    let elg_secret = ElgamalSecretKey::new(Scalar::random(rng));
    let elg_pub = elg_secret.get_public_key();
    let enc_keys = EncryptionKeys {
        pblc: elg_pub.into(),
        scrt: elg_secret.into(),
    };

    let asset_id =
        asset_id_from_ticker(&ticker_id).map_err(|error| Error::LibraryError { error })?;
    let asset_id_witness = CommitmentWitness::new(asset_id.clone().into(), Scalar::random(rng));

    let sign_keys = MiniSecretKey::generate_with(rng).expand_to_keypair(ExpansionMode::Ed25519);

    Ok(SecAccount {
        enc_keys,
        sign_keys,
        asset_id_witness,
    })
}
