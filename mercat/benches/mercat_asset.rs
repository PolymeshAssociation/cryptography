mod utility;
use confidential_identity_core::asset_proofs::{AssetId, Balance};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use mercat::{
    account::convert_asset_ids,
    asset::{AssetIssuer, AssetValidator},
    Account, AssetTransactionIssuer, AssetTransactionVerifier, EncryptedAmount, InitializedAssetTx,
    PubAccount,
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

fn bench_transaction_issuer(
    c: &mut Criterion,
    issuer_account: Account,
    amounts: Vec<Balance>,
) -> Vec<InitializedAssetTx> {
    let mut rng = thread_rng();

    let mut group = c.benchmark_group("MERCAT Transaction");
    for amount in &amounts {
        group.bench_with_input(BenchmarkId::new("Issuer", *amount), amount, |b, &amount| {
            b.iter(|| {
                let issuer = AssetIssuer;
                issuer
                    .initialize_asset_transaction(&issuer_account, &[], amount, &mut rng)
                    .unwrap()
            })
        });
    }
    group.finish();

    amounts
        .iter()
        .map(|&amount| {
            let issuer = AssetIssuer;
            issuer
                .initialize_asset_transaction(&issuer_account.clone(), &[], amount, &mut rng)
                .unwrap()
        })
        .collect()
}

fn bench_transaction_validator(
    c: &mut Criterion,
    transactions: Vec<InitializedAssetTx>,
    issuer_account: PubAccount,
    issuer_init_balance: EncryptedAmount,
) {
    let indexed_transaction: Vec<((String, u32), InitializedAssetTx)> = (MIN_ISSUED_AMOUNT_ORDER
        ..MAX_ISSUED_AMOUNT_ORDER)
        .map(|i| {
            let amount = 10u32.pow(i);
            (format!("issued_amount ({:?})", amount), amount)
        })
        .zip(transactions)
        .collect();

    let mut group = c.benchmark_group("MERCAT Transaction");
    for ((label, amount), tx) in &indexed_transaction {
        group.bench_with_input(
            BenchmarkId::new("Validator", label),
            &(amount, tx),
            |b, (&amount, tx)| {
                b.iter(|| {
                    let validator = AssetValidator;
                    validator
                        .verify_asset_transaction(
                            amount,
                            &tx,
                            &issuer_account,
                            &issuer_init_balance,
                            &[],
                        )
                        .unwrap()
                })
            },
        );
    }
    group.finish();
}

fn bench_asset_transaction(c: &mut Criterion) {
    let asset_id = AssetId::from(ASSET_ID);
    let valid_asset_ids: Vec<AssetId> = (0..MAX_ASSET_ID_INDEX).map(AssetId::from).collect();
    let valid_asset_ids = convert_asset_ids(valid_asset_ids);

    let mut rng = thread_rng();
    let (issuer_account, issuer_init_balance) =
        utility::create_account_with_amount(&mut rng, &asset_id, &valid_asset_ids, 0);

    let issued_amounts: Vec<u32> = (MIN_ISSUED_AMOUNT_ORDER..MAX_ISSUED_AMOUNT_ORDER)
        .map(|i| 10u32.pow(i))
        .collect();

    // Initialization
    let transactions = bench_transaction_issuer(c, issuer_account.clone(), issued_amounts);

    // Validation
    bench_transaction_validator(c, transactions, issuer_account.public, issuer_init_balance);
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
