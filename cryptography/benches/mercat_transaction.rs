use criterion::{criterion_group, criterion_main, Criterion};
use cryptography::{
    // asset_id_from_ticker,
    asset_proofs::{CommitmentWitness, ElgamalSecretKey},
    mercat::{
        account::{convert_asset_ids, create_account},
        asset::CtxIssuer,
        asset::{AssetTxIssueMediator, AssetTxIssueValidator},
        // conf_tx::CtxReceiver,
        conf_tx::CtxSender,
        Account, AccountMemo, AssetTransactionInitializeVerifier, AssetTransactionIssuer,
        AssetTransactionMediator, ConfidentialTransactionSender, //ConfidentialTxState,
        EncryptionKeys, EncryptionPubKey, MediatorAccount, PubAccount, //PubInitConfidentialTxData,
        SecAccount, //TxSubstate,
    },
    AssetId, Balance,
};
use curve25519_dalek::scalar::Scalar;
use rand::{rngs::StdRng, SeedableRng};
use rand::{CryptoRng, RngCore};
use schnorrkel::{ExpansionMode, MiniSecretKey};
use std::time::Duration;

fn bench_transaction_sender(
    c: &mut Criterion,
    sender_accounts: Vec<Account>,
    rcvr_pub_account: PubAccount,
    mdtr_pub_key: EncryptionPubKey,
    amount: Balance, // todo turn this into an array.
) {
    let label = format!("MERCAT Transaction: Sender");
    let mut rng = StdRng::from_seed([42u8; 32]);

    c.bench_function_over_inputs(
        &label,
        move |b, sender_account| {
            b.iter(|| {
                let sender = CtxSender {};
                sender
                    .create_transaction(
                        &sender_account,
                        &rcvr_pub_account.clone(),
                        &mdtr_pub_key.clone(),
                        amount,
                        &mut rng,
                    )
                    .unwrap();
            })
        },
        sender_accounts,
    );
}

fn bench_transaction(c: &mut Criterion) {
    let asset_id = AssetId::from(1);
    let valid_asset_ids: Vec<AssetId> = vec![1, 2, 3]
        .iter()
        .map(|id| AssetId::from(id.clone()))
        .collect();
    let valid_asset_ids = convert_asset_ids(valid_asset_ids);

    let mut rng = StdRng::from_seed([42u8; 32]);
    let (public_account, private_account) = generate_mediator_keys(&mut rng);
    let sender_account = create_secret_account(&mut rng, &asset_id, &valid_asset_ids);
    let receiver_account = create_secret_account(&mut rng, &asset_id, &valid_asset_ids);

    let sender_accounts: Vec<Account> = (1..7)
        .map(|i| {
            let value = 10u32.pow(i);
            Account {
                scrt: sender_account.scrt.clone(),
                pblc: issue_assets(
                    &mut rng,
                    sender_account.clone(),
                    private_account.clone(),
                    public_account.clone(),
                    value,
                ),
            }
        })
        .collect();

    bench_transaction_sender(
        c,
        sender_accounts,
        receiver_account.pblc,
        public_account.owner_enc_pub_key,
        10,
    ); // todo run with different amounts.
}

fn issue_assets<R: RngCore + CryptoRng>(
    rng: &mut R,
    account: Account,
    mediator_account: MediatorAccount,
    mediator_pub_account: AccountMemo,
    amount: u32,
) -> PubAccount {
    // issuer
    let issuer = CtxIssuer {};
    let (asset_tx, state) = issuer
        .initialize(
            0,
            &account.scrt,
            &mediator_pub_account.owner_enc_pub_key,
            amount,
            rng,
        )
        .unwrap();

    // validator
    let validator = AssetTxIssueValidator {};
    let state = validator
        .verify_initialization(
            &asset_tx,
            state,
            &account.pblc,
            &mediator_pub_account.owner_enc_pub_key,
        )
        .unwrap();

    // mediator
    let mediator = AssetTxIssueMediator {};
    let (_, updated_issuer_account) = mediator
        .justify_and_process(
            asset_tx.clone(),
            &account.pblc,
            state,
            &mediator_account.encryption_key,
            &mediator_account.signing_key,
        )
        .unwrap();
    // I'm too lazy to validate this now.
    updated_issuer_account
}

fn generate_mediator_keys<R: RngCore + CryptoRng>(rng: &mut R) -> (AccountMemo, MediatorAccount) {
    let mediator_elg_secret_key = ElgamalSecretKey::new(Scalar::random(rng));
    let mediator_enc_key = EncryptionKeys {
        pblc: mediator_elg_secret_key.get_public_key().into(),
        scrt: mediator_elg_secret_key.into(),
    };

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

fn create_secret_account<R: RngCore + CryptoRng>(
    rng: &mut R,
    asset_id: &AssetId,
    valid_asset_ids: &Vec<Scalar>,
) -> Account {
    let secret_account = gen_keys(rng, asset_id);

    create_account(secret_account, valid_asset_ids, 0, rng).unwrap()
}

fn gen_keys<R: RngCore + CryptoRng>(rng: &mut R, asset_id: &AssetId) -> SecAccount {
    let elg_secret = ElgamalSecretKey::new(Scalar::random(rng));
    let elg_pub = elg_secret.get_public_key();
    let enc_keys = EncryptionKeys {
        pblc: elg_pub.into(),
        scrt: elg_secret.into(),
    };

    let asset_id_witness = CommitmentWitness::new(asset_id.clone().into(), Scalar::random(rng));

    let sign_keys = MiniSecretKey::generate_with(rng).expand_to_keypair(ExpansionMode::Ed25519);

    SecAccount {
        enc_keys,
        sign_keys,
        asset_id: asset_id.clone(),
        asset_id_witness,
    }
}

criterion_group! {
    name = mercat_transaction;
    // Lower the sample size to run faster; larger shuffle sizes are
    // long so we're not microbenchmarking anyways.
    // 10 is the minimum allowed sample size in Criterion.
    config = Criterion::default()
        .sample_size(10)
        .measurement_time(Duration::new(60, 0));
    targets = bench_transaction,
}

criterion_main!(mercat_transaction);
