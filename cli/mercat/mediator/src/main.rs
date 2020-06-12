//! A simple commandline application to act as a confidential asset issuer.
//! Use `mercat_issuer --help` to see the usage.
//!

mod input;
use codec::{Decode, Encode};
use cryptography::{
    asset_proofs::ElgamalSecretKey,
    mercat::{
        asset::AssetTxIssueMediator, //, AssetTxIssueValidator, CtxIssuer},
        AccountMemo,
        AssetTransactionMediator,
        AssetTxState,
        EncryptionKeys,
        MediatorAccount,
        PubAccount,
        PubAssetTxData,
        TxSubstate,
    },
    // AssetId, Balance,
};
use curve25519_dalek::scalar::Scalar;
use rand::rngs::StdRng;
use rand::SeedableRng;
use rand_core::{CryptoRng, RngCore};
use schnorrkel::{ExpansionMode, MiniSecretKey}; //, SecretKey};
                                                // use serde::{Deserialize, Serialize};
                                                // use structopt::StructOpt;

use mercat_common::{
    errors::Error,
    // get_asset_ids,
    init_print_logger,
    load_object,
    // save_account_memo,
    // save_mediator_account, // save_sec_account, save_to_file, Instruction,
    save_object,
    transaction_file, //load_account_memo, load_mediator_account,
    Instruction,
    OFF_CHAIN_DIR,
    ON_CHAIN_DIR,
    PUBLIC_ACCOUNT_FILE,
    SECRET_ACCOUNT_FILE,
};

use env_logger;
use input::{parse_input, AccountMemoInfo, CLI};
use log::info;
use std::convert::TryInto;
/*
fn generate_account(mut rng: &mut StdRng) -> (SecAccount, PubAccount) {
    let issuer_elg_secret_key = ElgamalSecretKey::new(Scalar::random(&mut rng));
    let issuer_enc_key = EncryptionKeys {
        pblc: issuer_elg_secret_key.get_public_key().into(),
        scrt: issuer_elg_secret_key.into(),
    };
    let sign_keys = schnorrkel::Keypair::generate_with(&mut rng);
    let asset_id = AssetId::from(1);

    let issuer_secret_account = SecAccount {
        enc_keys: issuer_enc_key.clone(),
        sign_keys: sign_keys.clone(),
        asset_id: asset_id.clone(),
        asset_id_witness: CommitmentWitness::from((asset_id.clone().into(), rng)),
    };

    let pub_account_enc_asset_id = EncryptedAssetId::from(
        issuer_enc_key
            .pblc
            .key
            .encrypt(&issuer_secret_account.asset_id_witness),
    );

    let issuer_public_account = generate_pub_account(
        pub_account_enc_asset_id,
        AccountMemo::new(issuer_enc_key.pblc, sign_keys.public.into()),
    );

    (issuer_secret_account, issuer_public_account)
}

fn generate_pub_account(enc_asset_id: EncryptedAssetId, owner_memo: AccountMemo) -> PubAccount {
    PubAccount {
        content: PubAccountContent {
            id: 1,
            enc_asset_id: enc_asset_id, // pub_account_enc_asset_id,
            // Set the initial encrypted balance to 0.
            enc_balance: EncryptedAmount::default(),
            asset_wellformedness_proof: WellformednessProof::default(),
            asset_membership_proof: MembershipProof::default(),
            initial_balance_correctness_proof: CorrectnessProof::default(),
            memo: owner_memo, //AccountMemo::new(issuer_enc_key.pblc, sign_keys.public.into()),
        },
        initial_sig: Signature::from_bytes(&[128u8; 64]).expect("Invalid Schnorrkel signature"),
    }
}
*/
fn generate_mediator_keys<R: RngCore + CryptoRng>(rng: &mut R) -> (AccountMemo, MediatorAccount) {
    let mediator_elg_secret_key = ElgamalSecretKey::new(Scalar::random(rng));
    let mediator_enc_key = EncryptionKeys {
        pblc: mediator_elg_secret_key.get_public_key().into(),
        scrt: mediator_elg_secret_key.into(),
    };

    // let mut private_key_bytes = [0u8; 32];
    // rng.fill_bytes(&mut private_key_bytes);
    // let mediator_signing_pair = MiniSecretKey::from_bytes(&private_key_bytes)
    //     .expect("Invalid seed")
    //     .expand_to_keypair(ExpansionMode::Ed25519);

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

fn process_create_mediator(cfg: AccountMemoInfo) -> Result<(), Error> {
    // Setup the rng
    let seed = cfg.seed.ok_or(Error::EmptySeed)?;
    let seed: &[u8] = &base64::decode(seed).map_err(|e| Error::SeedDecodeError { error: e })?;
    let seed = seed
        .try_into()
        .map_err(|_| Error::SeedLengthError { length: seed.len() })?;
    let mut rng = StdRng::from_seed(seed);

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

fn justify_asset_issuance(cfg: input::AssetIssuanceArgs) -> Result<(), Error> {
    let db_dir = cfg.db_dir.ok_or(Error::EmptyDatabaseDir)?;

    let instruction: Instruction = load_object(
        db_dir.clone(),
        ON_CHAIN_DIR,
        &cfg.issuer,
        &transaction_file(
            cfg.tx_id,
            AssetTxState::Initialization(TxSubstate::Validated),
        ),
    )
    .unwrap_or_else(|error| panic!("Failed to deserialize the instruction: {}", error));

    let mediator_account: MediatorAccount = load_object(
        db_dir.clone(),
        OFF_CHAIN_DIR,
        &cfg.mediator,
        SECRET_ACCOUNT_FILE,
    )
    .unwrap_or_else(|error| panic!("Failed to deserialize the instruction: {}", error));

    let issuer_account: PubAccount = load_object(
        db_dir.clone(),
        ON_CHAIN_DIR,
        &cfg.issuer,
        PUBLIC_ACCOUNT_FILE,
    )
    .unwrap_or_else(|error| panic!("Failed to deserialize the instruction: {}", error));

    let asset_tx = PubAssetTxData::decode(&mut &instruction.data[..]).unwrap();

    // ----------------------- Justification
    let mediator = AssetTxIssueMediator {};
    let (justified_tx, updated_issuer_account) = mediator
        .justify_and_process(
            asset_tx,
            &issuer_account,
            instruction.state,
            &mediator_account.encryption_key,
            &mediator_account.signing_key,
        )
        .unwrap();
    assert_eq!(
        justified_tx.content.state,
        AssetTxState::Justification(TxSubstate::Started)
    );
    // todo save updated_issuer_account
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

    // let parse_arg_timer = Instant::now();
    let args = parse_input().unwrap();
    // timing!("account.argument_parse", parse_arg_timer, Instant::now());

    match args {
        CLI::Create(cfg) => process_create_mediator(cfg).unwrap(),
        CLI::JustifyIssuance(cfg) => justify_asset_issuance(cfg).unwrap(),
    };

    info!("The program finished successfully.");
    /*
        // todo take these in:
        // init: seed (1 for issuer, 1 for mediator), amount, issuer's key (secret and public), mediator's public key.
        //       account_id
        // println!("u chose: {:?}", args.amount);
        // match  args.amount {
        //     Some(a) => println!("you chose: {:?}", a)
        // }
        // let (cdd_claim, scope_claim) = if args.rand {
        //     let mut rng = StdRng::from_seed([42u8; 32]);
        //     let (rand_cdd_claim, rand_scope_claim) = random_claim(&mut rng);
        // }
        // ----------------------- Setup
        let mut rng = StdRng::from_seed([10u8; 32]);
        let issued_amount: Balance = args.amount.into();
        let account_id: u32 = 1234;

        let (issuer_secret_account, issuer_public_account) = generate_account(&mut rng);
        // save the issuer to file
        if let Some(key) = args.issuer_key {
            // std::fs::write(key, serde_json::to_string(&issuer_public_account).unwrap())
            std::fs::write(key, issuer_public_account.to_bytes().unwrap())
                .expect("Failed to write the issuer_public_account to file.");
            println!("Successfully wrote the issuer_public_account.");
        }

        // Generate keys for the mediator.
        let (mediator_enc_key, mediator_signing_pair) = generate_mediator_keys(&mut rng);
        // todo: Parnian: next take only the public part of the keypairs and save them to file.
        if let Some(key) = args.mediator_key {
            // std::fs::write(
            //     key.clone(),
            //     serde_json::to_string(&AccountMemo::new(
            //         mediator_enc_key.pblc,
            //         mediator_signing_pair.public,
            //     ))
            //     .unwrap(),
            // )
            // .expect("Failed to write the mediator_keys to file.");

            std::fs::write(
                key,
                AccountMemo::new(mediator_enc_key.pblc, mediator_signing_pair.public)
                    .to_bytes()
                    .unwrap(),
            )
            .expect("Failed to write the mediator_keys to file.");

            // read it back
            // let mediator_account_str = std::fs::read_to_string(key).expect("Failed to read the instruction from file.");
            // let mediator_account_str = AccountMemo::new(
            //     mediator_enc_key.pblc,
            //     mediator_signing_pair.public,
            // ).to_bytes().unwrap();
            // println!("mediator_account_str: {:?}", mediator_account_str);
            // let mediator_account: AccountMemo = AccountMemo::from_bytes(&mediator_account_str).unwrap();
            // serde_json::from_str(&mediator_account_str).unwrap_or_else(|error| {
            //     panic!(
            //         "Failed to deserialize the mediator's credentials: {}",
            //         error
            //     )
            // });
            // println!("mediator_account: {:?}", mediator_account);
            // std::fs::write(
            //     key,
            //     serde_json::to_string(&mediator_signing_pair)
            //     .unwrap(),
            // )
            // .expect("Failed to write the mediator_keys to file.");
            // println!("mediator_signing_pair.public: {:?}", mediator_signing_pair.public);
            println!("Successfully wrote the mediator_keys.");
        }

        // ----------------------- Justification
        // let mediator = AssetTxIssueMediator {};
        // let (justified_tx, _updated_issuer_account) = mediator
        //     .justify_and_process(
        //         asset_tx,
        //         &issuer_public_account,
        //         state,
        //         &mediator_enc_key,
        //         &mediator_signing_pair,
        //     )
        //     .unwrap();
        // assert_eq!(
        //     justified_tx.content.state,
        //     AssetTxState::Justification(TxSubstate::Started)
        // );
    */
}
