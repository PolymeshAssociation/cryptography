mod utility;
use criterion::{criterion_group, criterion_main, Criterion};
use cryptography::{
    mercat::{
        account::convert_asset_ids,
        asset::{AssetIssuer, AssetMediator, AssetValidator},
        AssetTransactionIssuer, AssetTransactionMediator, AssetTransactionVerifier,
        EncryptionPubKey, InitializedAssetTx, JustifiedAssetTx, MediatorAccount, PubAccount,
        SecAccount, SigningPubKey,
    },
    AssetId, Balance,
};
use rand::thread_rng;

// The issued amount. Will be in:
// [10^MIN_ISSUER_AMOUNT_ORDER, 10^(MIN_ISSUER_AMOUNT_ORDER+1), ..., 10^MAX_ISSUER_AMOUNT_ORDER]
const MIN_ISSUED_AMOUNT_ORDER: u32 = 1;
const MAX_ISSUED_AMOUNT_ORDER: u32 = 7;

// The size of the valid asset id set.
const MAX_ASSET_ID_INDEX: u32 = 1000000;
// The asset id to use for transactions.
// Must be in [0, MAX_ASSET_ID_INDEX)
const ASSET_ID: u32 = 1;

const ISSUER_ACCOUNT_ID: u32 = 1234;

fn bench_transaction_issuer(
    c: &mut Criterion,
    issuer_account: SecAccount,
    mdtr_pub_key: EncryptionPubKey,
    amounts: Vec<Balance>,
) -> Vec<InitializedAssetTx> {
    let label = format!("MERCAT Transaction: Issuer");
    let mut rng = thread_rng();
    let issuer_account_cloned = issuer_account.clone();

    c.bench_function_over_inputs(
        &label,
        move |b, &amount| {
            b.iter(|| {
                let issuer = AssetIssuer {};
                issuer
                    .initialize_asset_transaction(
                        ISSUER_ACCOUNT_ID,
                        &issuer_account_cloned.clone(),
                        &mdtr_pub_key.clone(),
                        &[],
                        amount,
                        &mut rng,
                    )
                    .unwrap()
            })
        },
        amounts.clone(),
    );

    amounts
        .iter()
        .map(|&amount| {
            let issuer = AssetIssuer {};
            issuer
                .initialize_asset_transaction(
                    ISSUER_ACCOUNT_ID,
                    &issuer_account.clone(),
                    &mdtr_pub_key.clone(),
                    &[],
                    amount,
                    &mut rng,
                )
                .unwrap()
        })
        .collect()
}

fn bench_transaction_mediator(
    c: &mut Criterion,
    transactions: Vec<InitializedAssetTx>,
    issuer_account: PubAccount,
    mediator_account: MediatorAccount,
) -> Vec<JustifiedAssetTx> {
    let label = format!("MERCAT Transaction: Mediator");
    let issuer_account_cloned = issuer_account.clone();
    let mediator_account_cloned = mediator_account.clone();

    let indexed_transaction: Vec<(String, InitializedAssetTx)> = (MIN_ISSUED_AMOUNT_ORDER
        ..MAX_ISSUED_AMOUNT_ORDER)
        .map(|i| format!("issued_amount ({:?})", 10u32.pow(i)))
        .zip(transactions.clone())
        .collect();

    c.bench_function_over_inputs(
        &label,
        move |b, (_label, tx)| {
            b.iter(|| {
                let mediator = AssetMediator {};
                mediator
                    .justify_asset_transaction(
                        tx.clone(),
                        &issuer_account_cloned.clone(),
                        &mediator_account_cloned.encryption_key.clone(),
                        &mediator_account_cloned.signing_key.clone(),
                        &[],
                    )
                    .unwrap()
            })
        },
        indexed_transaction.clone(),
    );

    transactions
        .iter()
        .map(|tx| {
            let mediator = AssetMediator {};
            mediator
                .justify_asset_transaction(
                    tx.clone(),
                    &issuer_account.clone(),
                    &mediator_account.encryption_key.clone(),
                    &mediator_account.signing_key.clone(),
                    &[],
                )
                .unwrap()
        })
        .collect()
}

fn bench_transaction_validator(
    c: &mut Criterion,
    transactions: Vec<JustifiedAssetTx>,
    issuer_account: PubAccount,
    mediator_enc_pub_key: EncryptionPubKey,
    mediator_sign_pub_key: SigningPubKey,
) {
    let label = format!("MERCAT Transaction: Validator");

    let indexed_transaction: Vec<(String, JustifiedAssetTx)> = (MIN_ISSUED_AMOUNT_ORDER
        ..MAX_ISSUED_AMOUNT_ORDER)
        .map(|i| format!("issued_amount ({:?})", 10u32.pow(i)))
        .zip(transactions.clone())
        .collect();

    c.bench_function_over_inputs(
        &label,
        move |b, (_label, tx)| {
            b.iter(|| {
                let validator = AssetValidator {};
                validator
                    .verify_asset_transaction(
                        &tx,
                        issuer_account.clone(),
                        &mediator_enc_pub_key,
                        &mediator_sign_pub_key,
                        &[],
                    )
                    .unwrap()
            })
        },
        indexed_transaction.clone(),
    );
}

fn bench_asset_transaction(c: &mut Criterion) {
    let asset_id = AssetId::from(ASSET_ID);
    let valid_asset_ids: Vec<AssetId> = (0..MAX_ASSET_ID_INDEX)
        .map(|id| AssetId::from(id.clone()))
        .collect();
    let valid_asset_ids = convert_asset_ids(valid_asset_ids);

    let mut rng = thread_rng();
    let (public_account, private_account) = utility::generate_mediator_keys(&mut rng);
    let issuer_account = utility::create_account_with_amount(
        &mut rng,
        &asset_id,
        &valid_asset_ids,
        &private_account,
        &public_account,
        0,
    );

    let issued_amounts: Vec<u32> = (MIN_ISSUED_AMOUNT_ORDER..MAX_ISSUED_AMOUNT_ORDER)
        .map(|i| 10u32.pow(i))
        .collect();

    // Initialization
    let transactions = bench_transaction_issuer(
        c,
        issuer_account.scrt,
        public_account.owner_enc_pub_key,
        issued_amounts,
    );

    // Justification
    let transactions = bench_transaction_mediator(
        c,
        transactions,
        issuer_account.pblc.clone(),
        private_account,
    );

    // Validation
    bench_transaction_validator(
        c,
        transactions,
        issuer_account.pblc,
        public_account.owner_enc_pub_key,
        public_account.owner_sign_pub_key,
    );
}

criterion_group! {
    name = mercat_asset;
    // Lower the sample size to run faster; larger shuffle sizes are
    // long so we're not microbenchmarking anyways.
    // 10 is the minimum allowed sample size in Criterion.
    config = Criterion::default()
        .sample_size(10);
        // .measurement_time(Duration::new(60, 0));
    targets = bench_asset_transaction,
}

criterion_main!(mercat_asset);
