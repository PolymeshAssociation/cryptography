use criterion::{criterion_group, criterion_main, Criterion};

/*use cryptography::{
    asset_proofs::{
        one_out_of_many_proof::OooNProofGenerators, CommitmentWitness, ElgamalSecretKey,
    },
    errors::Fallible,
    mercat::{
        account::{convert_asset_ids, create_account, AccountValidator},
        asset::{AssetTxIssueValidator, CtxIssuer},
        conf_tx::{
            CtxMediator, CtxMediatorValidator, CtxReceiver, CtxReceiverValidator, CtxSender,
            CtxSenderValidator,
        },
        Account, AccountCreatorVerifier, AccountMemo, AssetTransactionInitializeVerifier,
        AssetTransactionIssuer, AssetTransactionMediator, AssetTxState,
        CipherEqualDifferentPubKeyProof, CipherEqualSamePubKeyProof,
        ConfidentialTransactionFinalizationVerifier, ConfidentialTransactionInitVerifier,
        ConfidentialTransactionMediator, ConfidentialTransactionSender, ConfidentialTxState,
        CorrectnessProof, EncryptedAmount, EncryptedAssetId, EncryptionKeys, EncryptionPubKey,
        MembershipProof, PubAccount, PubAccountContent, PubFinalConfidentialTxData,
        PubInitConfidentialTxData, SecAccount, Signature, SigningKeys, SigningPubKey, TxSubstate,
        WellformednessProof,
    },
    AssetId, Balance,
};
use curve25519_dalek::scalar::Scalar;
use rand::{rngs::StdRng, SeedableRng};
use rand_core::{CryptoRng, RngCore};
use sp_std::prelude::*;
use std::time::{Duration, Instant};

const SEED_1: [u8; 32] = [42u8; 32];
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

fn mock_gen_account<R: RngCore + CryptoRng>(
    rcvr_enc_pub_key: EncryptionPubKey,
    rcvr_sign_pub_key: SigningPubKey,
    asset_id: AssetId,
    balance: Balance,
    rng: &mut R,
) -> Fallible<PubAccount> {
    let (_, enc_asset_id) = rcvr_enc_pub_key.encrypt_value(asset_id.into(), rng);
    let (_, enc_balance) = rcvr_enc_pub_key.encrypt_value(Scalar::from(balance), rng);

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

fn bench_mercat_confidential_tx_operations(c: &mut Criterion) {
    let sndr = CtxSender {};
    let rcvr = CtxReceiver {};
    let mdtr = CtxMediator {};
    let sndr_vldtr = CtxSenderValidator {};
    let rcvr_vldtr = CtxReceiverValidator {};
    let mdtr_vldtr = CtxMediatorValidator {};
    let asset_id = AssetId::from(20);
    let sndr_balance = 500;
    let rcvr_balance = 0;
    let amount = 5;

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
    // Generate multiple accounts with different balances
    let sndr_accounts: Vec<Account> = [5u32, 5000u32, 50000u32]
        .iter()
        .zip([AssetId::from(20), AssetId::from(30), AssetId::from(40)].iter())
        .map(|(balance, asset_id)| {
            let seed = 11u8;
            let sndr_enc_keys_inner = mock_gen_enc_key_pair(seed);
            let sndr_sign_keys_inner = mock_gen_sign_key_pair(seed + 6);

            Account {
                pblc: mock_gen_account(
                    sndr_enc_keys_inner.pblc,
                    sndr_sign_keys_inner.public.clone(),
                    asset_id.clone(),
                    *balance,
                    &mut rng,
                )
                .unwrap(),
                scrt: SecAccount {
                    enc_keys: sndr_enc_keys_inner,
                    sign_keys: sndr_sign_keys_inner,
                    asset_id: asset_id.clone(),
                    asset_id_witness: CommitmentWitness::from((asset_id.clone().into(), &mut rng)),
                },
            }
        })
        .collect();

    // Benchmarking the creation of initialized transaction
    // We clone all input parameters below for passing it to the criterion.
    let sndr_clone = sndr.clone();
    let rcvr_clone = rcvr.clone();
    let rcvr_account_clone = rcvr_account.clone();
    let rcvr_account_pblc_clone = rcvr_account.pblc.clone();
    let mdtr_enc_keys_pblc_clone = mdtr_enc_keys.pblc.clone();

    let amount_clone = amount.clone();

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

    let (ctx_init_data, state) = sndr
        .create_transaction(
            &sndr_account,
            &rcvr_account.pblc,
            &mdtr_enc_keys.pblc,
            amount,
            &mut rng,
        )
        .unwrap();

    // Benchmarking the verification of initialized transaction
    // We create multiple initialized transactions with different amounts

    let amount_vector = vec![4u32, 40u32, 400u32];

    let init_ctxs: Vec<(PubInitConfidentialTxData, ConfidentialTxState)> = amount_vector
        .clone()
        .iter()
        .map(|amount| {
            let (ctx, state) = sndr
                .create_transaction(
                    &sndr_account,
                    &rcvr_account.pblc,
                    &mdtr_enc_keys.pblc,
                    *amount,
                    &mut rng,
                )
                .unwrap();
            (ctx, state)
        })
        .collect();

    // We keep these final_ctxs along with the finalization state and final verification state for future use in the benchmarking of mediator justification.
    let final_ctxs: Vec<(
        PubFinalConfidentialTxData,
        ConfidentialTxState,
        ConfidentialTxState,
    )> = init_ctxs
        .clone()
        .iter()
        .zip(amount_vector.clone().iter())
        .map(|(init_data, expected_amount)| {
            let mut rng_final = StdRng::from_seed([17u8; 32]);
            let sndr_vld_state = sndr_vldtr
                .verify(
                    &init_data.0,
                    &sndr_account.pblc,
                    init_data.1,
                    &mut rng_final,
                )
                .unwrap();
            let (ctx_finalized_data, fnlz_state) = rcvr_clone
                .finalize_by_receiver(
                    init_data.0.clone(),
                    rcvr_account_clone.clone(),
                    sndr_vld_state,
                    *expected_amount,
                    &mut rng_final,
                )
                .unwrap();
            assert_eq!(
                fnlz_state,
                ConfidentialTxState::Finalization(TxSubstate::Started)
            );
            let fnlz_vld_state = rcvr_vldtr
                .verify_finalize_by_receiver(
                    &sndr_account.pblc.clone(),
                    &rcvr_account_pblc_clone.clone(),
                    &ctx_finalized_data,
                    fnlz_state.clone(),
                    &mut rng_final,
                )
                .unwrap();
            (ctx_finalized_data, fnlz_state, fnlz_vld_state)
        })
        .collect();

    let sndr_vldtr_clone = sndr_vldtr.clone();
    let ctx_init_data_clone = ctx_init_data.clone();
    let sndr_acc_pbc_clone = sndr_account.pblc.clone();
    let state_clone = state.clone();
    let init_ctxs_clone = init_ctxs.clone();

    // Benchmarking the generation of initialized transaction of fixed amount with multiple accounts of different balances
    c.bench_function_over_inputs(
        "Generation of Initialized Transaction",
        move |b, sndr_account| {
            b.iter(|| {
                let mut rng_init = StdRng::from_seed([37u8; 32]);
                let (ctx_init_data, state) = sndr_clone
                    .create_transaction(
                        &sndr_account.clone(),
                        &rcvr_account_pblc_clone.clone(),
                        &mdtr_enc_keys_pblc_clone.clone(),
                        amount_clone.clone(),
                        &mut rng_init,
                    )
                    .unwrap();

                assert_eq!(
                    state,
                    ConfidentialTxState::Initialization(TxSubstate::Started)
                );
            })
        },
        sndr_accounts,
    );

    // Benchmarking the verificaiton of initialized transactions
    // The initialized transacations are transfering different amounts.
    c.bench_function_over_inputs(
        "Initialized Transaction Verification",
        move |b, ctx_init_data| {
            b.iter(|| {
                let mut rng = StdRng::from_seed([79u8; 32]);
                let state = sndr_vldtr_clone
                    .verify(
                        &ctx_init_data.0.clone(),
                        &sndr_acc_pbc_clone.clone(),
                        ctx_init_data.1.clone(),
                        &mut rng,
                    )
                    .unwrap();
                assert_eq!(
                    state,
                    ConfidentialTxState::Initialization(TxSubstate::Validated)
                );
            })
        },
        init_ctxs_clone,
    );

    // We run the verification function over again in order to get the final
    // verification state and pass it to the next finalization function.
    let state = sndr_vldtr
        .verify(&ctx_init_data, &sndr_account.pblc, state, &mut rng)
        .unwrap();

    let rcvr_account_clone = rcvr_account.clone();
    let rcvr_clone = rcvr.clone();
    let ctx_init_data_clone = ctx_init_data.clone();
    let amount_clone = amount.clone();
    let state_clone = state.clone();
    let init_ctxs_clone = init_ctxs.clone();

    // Benchmarking the Transaction Finalization phase for initialized transactions of different amounts.
    c.bench_function_over_inputs(
        "Generation of Finalized Transaction",
        move |b, ctx_init_data| {
            b.iter(|| {
                let mut rng_final = StdRng::from_seed([39u8; 32]);
                let (ctx_finalized_data, state) = rcvr_clone
                    .finalize_by_receiver(
                        ctx_init_data_clone.clone(),
                        rcvr_account_clone.clone(),
                        state_clone,
                        amount_clone,
                        &mut rng_final,
                    )
                    .unwrap();
                assert_eq!(
                    state,
                    ConfidentialTxState::Finalization(TxSubstate::Started)
                );
            })
        },
        init_ctxs_clone,
    );

    // We finalize the transaction and get the finalization state in order to
    // pass these outputs to the next verification step.
    let (ctx_finalized_data, _state) = rcvr
        .finalize_by_receiver(ctx_init_data, rcvr_account.clone(), state, amount, &mut rng)
        .unwrap();

    // Bencharking of finalized transaction verification step
    // We clone all parameters before passing them to the criterion.
    let rcvr_vldtr_clone = rcvr_vldtr.clone();
    let sndr_acc_pbc_clone = sndr_account.pblc.clone();
    let rcvr_account_pbc_clone = rcvr_account.pblc.clone();

    c.bench_function_over_inputs(
        "Finalized Transaction Verification",
        move |b, ctx_finalized_data| {
            b.iter(|| {
                let mut rng = StdRng::from_seed([177u8; 32]);
                let state = rcvr_vldtr_clone
                    .verify_finalize_by_receiver(
                        &sndr_acc_pbc_clone.clone(),
                        &rcvr_account_pbc_clone.clone(),
                        &ctx_finalized_data.0,
                        ctx_finalized_data.1,
                        &mut rng,
                    )
                    .unwrap();
                assert_eq!(
                    state,
                    ConfidentialTxState::Finalization(TxSubstate::Validated)
                );
            })
        },
        final_ctxs.clone(),
    );

    // Bencharking the transaction justification
    // We clone all parameters before passing them to the criterion.

    let mdtr_clone = mdtr.clone();
    let asset_id_clone = asset_id.clone();

    c.bench_function_over_inputs(
        "Justify the Finalized Transaction",
        move |b, ctx_fnlzd_data| {
            b.iter(|| {
                let (justified_finalized_ctx_data, state) = mdtr_clone
                    .justify(
                        ctx_fnlzd_data.0.clone(),
                        ctx_fnlzd_data.2,
                        &mdtr_enc_keys.clone(),
                        &mdtr_sign_keys.clone(),
                        asset_id_clone.clone(),
                    )
                    .unwrap();
                assert_eq!(
                    state,
                    ConfidentialTxState::Justification(TxSubstate::Started)
                );
            })
        },
        final_ctxs.clone(),
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
    // ----------------------- Initialization
    let issuer = CtxIssuer {};
    let (asset_tx1, state1) = issuer
        .initialize(
            1234u32,
            &issuer_secret_account,
            &mediator_enc_key.pblc,
            issued_amount,
            &mut rng,
        )
        .unwrap();
    let (asset_tx2, state2) = issuer
        .initialize(
            1254u32,
            &issuer_secret_account,
            &mediator_enc_key.pblc,
            300u32.into(),
            &mut rng,
        )
        .unwrap();

    let validator = AssetTxIssueValidator {};
    ///////
    let label_asset_tx_ver = format!("Mercat asset issuance transaction validation");
    let account_vldtr = AccountValidator {};
    c.bench_function_over_inputs(
        &label_asset_tx_ver,
        move |b, asset_tx_and_state| {
            b.iter(|| {
                validator
                    .verify_initialization(
                        &asset_tx_and_state.0.clone(),
                        asset_tx_and_state.1.clone(),
                        &issuer_public_account.clone(),
                        &mediator_enc_key.pblc.clone(),
                    )
                    .unwrap()
            })
        },
        vec![
            (asset_tx1.clone(), state1.clone()),
            (asset_tx2.clone(), state2.clone()),
        ],
    );
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
    println!("Account creation takes {:?}", account_gen_time.elapsed());
    let account_vldtr = AccountValidator {};

    c.bench_function_over_inputs(
        "Mercat New Account Generation",
        move |b, account_id| {
            b.iter(|| {
                let seed = 11u8;
                let sndr_enc_keys = mock_gen_enc_key_pair(seed);
                let sndr_sign_keys = mock_gen_sign_key_pair(seed + 20);
                let scrt_account = SecAccount {
                    enc_keys: sndr_enc_keys,
                    sign_keys: sndr_sign_keys,
                    asset_id: asset_id.clone(),
                    asset_id_witness: CommitmentWitness::from((asset_id.clone().into(), &mut rng)),
                };
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
    targets = bench_mercat_confidential_tx_operations, //bench_mercat_account_generation_and_validation, bench_mercat_asset_issuance_tx_operations,
}

criterion_main!(bench_account_validation);
*/
