mod utility;
use criterion::{criterion_group, criterion_main, Criterion};
use cryptography::{
    mercat::{
        account::{convert_asset_ids, AccountValidator},
        AccountCreatorVerifier, PubAccountTx,
    },
    AssetId,
};
use rand::thread_rng;

// The size of the valid asset id set.
const MAX_ASSET_ID_INDEX: u32 = 10000;
// The asset ids to use for the account.
// Must be in [0, MAX_ASSET_ID_INDEX)
const ASSET_IDS: [u32; 4] = [10, 20, 300, 4000];

fn bench_account_creation(c: &mut Criterion) {
    let valid_asset_ids: Vec<AssetId> = (0..MAX_ASSET_ID_INDEX).map(AssetId::from).collect();
    let valid_asset_ids = convert_asset_ids(valid_asset_ids);

    let mut rng = thread_rng();
    let tx_id = 0;
    let public_accounts: Vec<(String, PubAccountTx)> = ASSET_IDS
        .iter()
        .map(|&id| {
            (
                format!("asset_id: {:?}", id),
                utility::create_account(&mut rng, &AssetId::from(id), &valid_asset_ids, 0, tx_id),
            )
        })
        .collect();

    let label = "MERCAT Transaction: Validator".to_string();
    c.bench_function_over_inputs(
        &label,
        move |b, (_label, account)| {
            b.iter(|| {
                let validator = AccountValidator {};
                validator.verify(account, &valid_asset_ids).unwrap()
            })
        },
        public_accounts,
    );
}

criterion_group! {
    name = mercat_account;
    // Lower the sample size to run faster; larger shuffle sizes are
    // long so we're not microbenchmarking anyways.
    // 10 is the minimum allowed sample size in Criterion.
    config = Criterion::default()
        .sample_size(10);
        // .measurement_time(Duration::new(60, 0));
    targets = bench_account_creation,
}

criterion_main!(mercat_account);
