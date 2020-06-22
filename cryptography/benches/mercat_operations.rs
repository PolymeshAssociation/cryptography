use criterion::{criterion_group, criterion_main, Criterion};

use cryptography::{
    asset_proofs::{
        encryption_proofs::{single_property_prover, single_property_verifier},
        membership_proof::{
            MembershipProofFinalResponse, MembershipProofInitialMessage, MembershipProofVerifier,
            MembershipProverAwaitingChallenge,
        },
        one_out_of_many_proof::OooNProofGenerators,
        CommitmentWitness, ElgamalSecretKey,
    },
    errors::Fallible,
    mercat::{
        account::{convert_asset_ids, create_account, AccountValidator},
        asset::{AssetTxIssueValidator, CtxIssuer},
        conf_tx::{
            CtxMediator, CtxMediatorValidator, CtxReceiver, CtxReceiverValidator, CtxSender,
            CtxSenderValidator,
        },
        Account, AccountCreaterVerifier, AccountMemo, AssetTransactionInitializeVerifier,
        AssetTransactionIssuer, AssetTransactionMediator, AssetTxState,
        CipherEqualDifferentPubKeyProof, CipherEqualSamePubKeyProof,
        ConfidentialTransactionInitVerifier, ConfidentialTransactionMediator,
        ConfidentialTransactionMediatorVerifier, ConfidentialTransactionSender, ConfidentialTxMemo,
        ConfidentialTxState, CorrectnessProof, EncryptedAmount, EncryptedAssetId, EncryptionKeys,
        EncryptionPubKey, InRangeProof, MembershipProof, PubAccount, PubAccountContent,
        PubInitConfidentialTxData, PubInitConfidentialTxDataContent, SecAccount, Signature,
        SigningKeys, SigningPubKey, TxSubstate, WellformednessProof,
    },
    AssetId, Balance,
};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use rand::{rngs::StdRng, SeedableRng};
use rand_core::{CryptoRng, RngCore};
use schnorrkel::{ExpansionMode, MiniSecretKey};
use sp_std::prelude::*;
use std::time::{Duration, Instant};
use wasm_bindgen_test::*;

const SEED_1: [u8; 32] = [42u8; 32];
const BASE: usize = 4;
const EXPONENT: usize = 8;
const SET_SIZE: u32 = 65536;

fn mock_gen_enc_key_pair(seed: u8) -> EncryptionKeys {
    let mut rng = StdRng::from_seed([seed; 32]);
    let elg_secret = ElgamalSecretKey::new(Scalar::random(&mut rng));
    let elg_pub = elg_secret.get_public_key();
    EncryptionKeys {
        pblc: elg_pub.into(),
        scrt: elg_secret.into(),
    }
}

fn mock_gen_sign_key_pair(seed: u8) -> SigningKeys {
    let mut rng = StdRng::from_seed([seed; 32]);
    schnorrkel::Keypair::generate_with(&mut rng)
}

fn mock_ctx_init_memo<R: RngCore + CryptoRng>(
    rcvr_pub_key: EncryptionPubKey,
    amount: Balance,
    asset_id: AssetId,
    rng: &mut R,
) -> ConfidentialTxMemo {
    let (_, enc_amount_using_rcvr) = rcvr_pub_key.key.encrypt_value(amount.into(), rng);
    let (_, enc_asset_id_using_rcvr) = rcvr_pub_key.key.encrypt_value(asset_id.into(), rng);
    ConfidentialTxMemo {
        sndr_account_id: 0,
        rcvr_account_id: 0,
        enc_amount_using_sndr: EncryptedAmount::default(),
        enc_amount_using_rcvr: EncryptedAmount::from(enc_amount_using_rcvr),
        sndr_pub_key: EncryptionPubKey::default(),
        rcvr_pub_key,
        refreshed_enc_balance: EncryptedAmount::default(),
        refreshed_enc_asset_id: EncryptedAssetId::default(),
        enc_asset_id_using_rcvr: EncryptedAssetId::from(enc_asset_id_using_rcvr),
        enc_amount_for_mdtr: EncryptedAmount::default(),
        enc_asset_id_for_mdtr: EncryptedAssetId::default(),
    }
}

fn mock_gen_account<R: RngCore + CryptoRng>(
    rcvr_enc_pub_key: EncryptionPubKey,
    rcvr_sign_pub_key: SigningPubKey,
    asset_id: AssetId,
    balance: Balance,
    rng: &mut R,
) -> Fallible<PubAccount> {
    let (_, enc_asset_id) = rcvr_enc_pub_key.key.encrypt_value(asset_id.into(), rng);
    let (_, enc_balance) = rcvr_enc_pub_key
        .key
        .encrypt_value(Scalar::from(balance), rng);

    Ok(PubAccount {
        content: PubAccountContent {
            id: 1,
            enc_asset_id: enc_asset_id.into(),
            enc_balance: enc_balance.into(),
            asset_wellformedness_proof: WellformednessProof::default(),
            asset_membership_proof: MembershipProof::default(),
            initial_balance_correctness_proof: CorrectnessProof::default(),
            memo: AccountMemo::new(rcvr_enc_pub_key, rcvr_sign_pub_key),
        },
        initial_sig: Signature::from_bytes(&[128u8; 64]).expect("Invalid Schnorrkel signature"),
    })
}

fn mock_ctx_init_data<R: RngCore + CryptoRng>(
    rcvr_pub_key: EncryptionPubKey,
    expected_amount: Balance,
    asset_id: AssetId,
    sig: Signature,
    rng: &mut R,
) -> PubInitConfidentialTxData {
    PubInitConfidentialTxData {
        content: PubInitConfidentialTxDataContent {
            memo: mock_ctx_init_memo(rcvr_pub_key, expected_amount, asset_id, rng),
            asset_id_equal_cipher_with_sndr_rcvr_keys_proof:
                CipherEqualDifferentPubKeyProof::default(),
            amount_equal_cipher_proof: CipherEqualDifferentPubKeyProof::default(),
            non_neg_amount_proof: InRangeProof::default(),
            enough_fund_proof: InRangeProof::default(),
            balance_refreshed_same_proof: CipherEqualSamePubKeyProof::default(),
            asset_id_refreshed_same_proof: CipherEqualSamePubKeyProof::default(),
            amount_correctness_proof: CorrectnessProof::default(),
            asset_id_correctness_proof: CorrectnessProof::default(),
        },
        sig,
    }
}

fn bench_mercat_confidential_tx_operations(c: &mut Criterion) {
    let sndr = CtxSender {};
    let rcvr = CtxReceiver {};
    let mdtr = CtxMediator {};
    let sndr_vldtr = CtxSenderValidator {};
    let rcvr_vldtr = CtxReceiverValidator {};
    let mdtr_vldtr = CtxMediatorValidator {};
    let asset_id = AssetId::from(20);
    let sndr_balance = 40;
    let rcvr_balance = 0;
    let amount = 30;

    let mut rng = StdRng::from_seed([17u8; 32]);

    let sndr_enc_keys = mock_gen_enc_key_pair(10u8);
    let sndr_sign_keys = mock_gen_sign_key_pair(11u8);

    let rcvr_enc_keys = mock_gen_enc_key_pair(12u8);
    let rcvr_sign_keys = mock_gen_sign_key_pair(13u8);

    let mdtr_enc_keys = mock_gen_enc_key_pair(14u8);
    let mdtr_sign_keys = mock_gen_sign_key_pair(15u8);

    let rcvr_account = Account {
        pblc: mock_gen_account(
            rcvr_enc_keys.pblc,
            rcvr_sign_keys.public.clone(),
            asset_id.clone(),
            rcvr_balance,
            &mut rng,
        )
        .unwrap(),
        scrt: SecAccount {
            enc_keys: rcvr_enc_keys,
            sign_keys: rcvr_sign_keys,
            asset_id: asset_id.clone(),
            asset_id_witness: CommitmentWitness::from((asset_id.clone().into(), &mut rng)),
        },
    };

    let sndr_account = Account {
        pblc: mock_gen_account(
            sndr_enc_keys.pblc,
            sndr_sign_keys.public.clone(),
            asset_id.clone(),
            sndr_balance,
            &mut rng,
        )
        .unwrap(),
        scrt: SecAccount {
            enc_keys: sndr_enc_keys,
            sign_keys: sndr_sign_keys,
            asset_id: asset_id.clone(),
            asset_id_witness: CommitmentWitness::from((asset_id.clone().into(), &mut rng)),
        },
    };

    // Create the trasaction and check its result and state
    let result = sndr.create_transaction(
        &sndr_account,
        &rcvr_account.pblc,
        &mdtr_enc_keys.pblc,
        amount,
        &mut rng,
    );
    let (ctx_init_data, state) = result.unwrap();
    assert_eq!(
        state,
        ConfidentialTxState::Initialization(TxSubstate::Started)
    );

    let label_ctx_init_ver = "Initialized Transaction Verification";
    let sndr_acc_pbc_clone = sndr_account.pblc.clone();

    c.bench_function_over_inputs(
        &label_ctx_init_ver,
        move |b, ctx_init_data| {
            b.iter(|| {
                sndr_vldtr
                    .verify(
                        &ctx_init_data.clone(),
                        &sndr_acc_pbc_clone.clone(),
                        state.clone(),
                    )
                    .unwrap()
            })
        },
        vec![ctx_init_data.clone()],
    );
    // Verify the initialization step
    //let result = sndr_vldtr.verify(&ctx_init_data, &sndr_account.pblc, state);
    //let state = result.unwrap();
    //assert_eq!(
    //    state,
    //    ConfidentialTxState::Initialization(TxSubstate::Validated)
    //);

    // Finalize the transaction and check its state
    let result =
        rcvr.finalize_by_receiver(ctx_init_data, rcvr_account.clone(), state, amount, &mut rng);
    let (ctx_finalized_data, state) = result.unwrap();
    assert_eq!(
        state,
        ConfidentialTxState::Finalization(TxSubstate::Started)
    );

    // verify the finalization step
    let result = rcvr_vldtr.verify_finalize_by_receiver(
        &sndr_account.pblc,
        &rcvr_account.pblc,
        &ctx_finalized_data,
        state,
    );
    let state = result.unwrap();
    assert_eq!(
        state,
        ConfidentialTxState::Finalization(TxSubstate::Validated)
    );

    // justify the transaction
    let mdtr_sec_account = SecAccount {
        enc_keys: mdtr_enc_keys,
        sign_keys: mdtr_sign_keys.clone(),
        asset_id: asset_id.clone(),
        asset_id_witness: CommitmentWitness::from((asset_id.clone().into(), &mut rng)),
    };

    let result = mdtr.justify(ctx_finalized_data, state, &mdtr_sec_account, asset_id);
    let (justified_finalized_ctx_data, state) = result.unwrap();
    assert_eq!(
        state,
        ConfidentialTxState::FinalizationJustification(TxSubstate::Started)
    );

    let result = mdtr_vldtr.verify(&justified_finalized_ctx_data, &mdtr_sign_keys.public, state);
    let state = result.unwrap();
    assert_eq!(
        state,
        ConfidentialTxState::FinalizationJustification(TxSubstate::Validated)
    );
}

fn bench_mercat_asset_issuance_tx_operations(c: &mut Criterion) {
    let mut rng = StdRng::from_seed([10u8; 32]);

    let sign_keys = schnorrkel::Keypair::generate_with(&mut rng);
    let issuer_elg_secret_key = ElgamalSecretKey::new(Scalar::random(&mut rng));
    let issuer_enc_key = EncryptionKeys {
        pblc: issuer_elg_secret_key.get_public_key().into(),
        scrt: issuer_elg_secret_key.into(),
    };

    let asset_id = AssetId::from(15);
    let issued_amount: Balance = 20u32.into();

    let issuer_secret_account = SecAccount {
        enc_keys: issuer_enc_key.clone(),
        sign_keys: sign_keys.clone(),
        asset_id: asset_id.clone(),
        asset_id_witness: CommitmentWitness::from((asset_id.clone().into(), &mut rng)),
    };

    let pub_account_enc_asset_id = EncryptedAssetId::from(
        issuer_enc_key
            .pblc
            .key
            .encrypt(&issuer_secret_account.asset_id_witness),
    );

    let issuer_public_account = PubAccount {
        content: PubAccountContent {
            id: 15,
            enc_asset_id: pub_account_enc_asset_id,
            enc_balance: EncryptedAmount::default(),
            asset_wellformedness_proof: WellformednessProof::default(),
            asset_membership_proof: MembershipProof::default(),
            initial_balance_correctness_proof: CorrectnessProof::default(),
            memo: AccountMemo::new(issuer_enc_key.pblc, sign_keys.public.into()),
        },
        initial_sig: Signature::from_bytes(&[128u8; 64]).expect("Invalid Schnorrkel signature"),
    };

    // Generate keys for the mediator.
    let mediator_elg_secret_key = ElgamalSecretKey::new(Scalar::random(&mut rng));
    let mediator_enc_key = EncryptionKeys {
        pblc: mediator_elg_secret_key.get_public_key().into(),
        scrt: mediator_elg_secret_key.into(),
    };

    let seed = [12u8; 32];
    let mediator_signing_pair = MiniSecretKey::from_bytes(&seed)
        .expect("Invalid seed")
        .expand_to_keypair(ExpansionMode::Ed25519);

    // ----------------------- Initialization
    let issuer = CtxIssuer {};
    let (asset_tx, state) = issuer
        .initialize(
            1234u32,
            &issuer_secret_account,
            &mediator_enc_key.pblc,
            issued_amount,
            &mut rng,
        )
        .unwrap();

    let validator = AssetTxIssueValidator {};
    ///////
    let label_asset_tx_ver = format!("Mercat asset issuance transaction validation");
    let account_vldtr = AccountValidator {};
    c.bench_function_over_inputs(
        &label_asset_tx_ver,
        move |b, asset_tx| {
            b.iter(|| {
                validator
                    .verify_initialization(
                        &asset_tx.clone(),
                        state.clone(),
                        &issuer_public_account.clone(),
                        &mediator_enc_key.pblc.clone(),
                    )
                    .unwrap()
            })
        },
        vec![asset_tx.clone()],
    );
    ///////
    //let state = validator
    //    .verify_initialization(
    //        &asset_tx,
    //        state,
    //        &issuer_public_account,
    //        &mediator_enc_key.pblc,
    //    )
    //    .unwrap();
    //assert_eq!(state, AssetTxState::Initialization(TxSubstate::Validated));
}

fn bench_mercat_account_generation_and_validation(c: &mut Criterion) {
    let mut rng = StdRng::from_seed([10u8; 32]);
    let elg_secret = ElgamalSecretKey::new(Scalar::random(&mut rng));

    let enc_keys = EncryptionKeys {
        pblc: elg_secret.get_public_key().into(),
        scrt: elg_secret.into(),
    };

    let sign_keys = schnorrkel::Keypair::generate_with(&mut rng);

    let valid_asset_ids: Vec<AssetId> = (0..SET_SIZE)
        .into_iter()
        .map(|id| AssetId::from(id))
        .collect::<Vec<_>>();
    let conversion_time = Instant::now();
    let valid_asset_ids = convert_asset_ids(valid_asset_ids);
    let asset_ids = valid_asset_ids.clone();
    println!(
        "Conversion of asset ids to scalar takes {:?}",
        conversion_time.elapsed()
    );

    let account_id = 1009;
    let asset_id = AssetId::from(20);

    let scrt_account = SecAccount {
        enc_keys,
        sign_keys,
        asset_id: asset_id.clone(),
        asset_id_witness: CommitmentWitness::from((asset_id.clone().into(), &mut rng)),
    };

    let account_gen_time = Instant::now();
    let account = create_account(
        scrt_account.clone(),
        &valid_asset_ids.clone(),
        account_id,
        &mut rng,
    )
    .unwrap();
    let account_vldtr = AccountValidator {};
    println!("Account creation takes {:?}", account_gen_time.elapsed());

    let label_acc_gen = format!("Mercat New Account Generation");

    c.bench_function_over_inputs(
        &label_acc_gen,
        move |b, account_id| {
            b.iter(|| {
                create_account(
                    scrt_account.clone(),
                    &valid_asset_ids.clone(),
                    *account_id,
                    &mut rng.clone(),
                )
                .unwrap()
            })
        },
        vec![3],
    );

    let account_ver_time = Instant::now();
    account_vldtr
        .verify(&account.pblc.clone(), &asset_ids.clone())
        .unwrap();
    println!("Account validation takes {:?}", account_ver_time.elapsed());

    let label_acc_ver = format!("Mercat new account validation");
    let account_vldtr = AccountValidator {};
    c.bench_function_over_inputs(
        &label_acc_ver,
        move |b, account| b.iter(|| account_vldtr.verify(&account, &asset_ids.clone()).unwrap()),
        vec![account.pblc],
    );
}

criterion_group! {
    name = bench_account_validation;
    // Lower the sample size to run faster; larger shuffle sizes are
    // long so we're not microbenchmarking anyways.
    // 10 is the minimum allowed sample size in Criterion.
    config = Criterion::default().sample_size(10).measurement_time(Duration::new(600, 0));
    targets = bench_mercat_asset_issuance_tx_operations, bench_mercat_confidential_tx_operations,//bench_mercat_account_generation_and_validation,
}

criterion_main!(bench_account_validation);
