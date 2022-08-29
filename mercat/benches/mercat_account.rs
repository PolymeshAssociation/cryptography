mod utility;
use confidential_identity_core::asset_proofs::AssetId;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use mercat::{
    account::{convert_asset_ids, AccountCreator, AccountValidator},
    AccountCreatorInitializer, AccountCreatorVerifier,
};
use rand::thread_rng;

// The size of the valid asset id set.
const MAX_ASSET_ID_INDEX: u32 = 65536;
// The asset ids to use for the account.
// Must be in [0, MAX_ASSET_ID_INDEX)
// Side note: 65536 is 4^8.
const ASSET_IDS: [u32; 5] = [10, 20, 300, 4000, 65535];

fn bench_account_creation(c: &mut Criterion) {
    let valid_asset_ids: Vec<AssetId> = (0..MAX_ASSET_ID_INDEX).map(AssetId::from).collect();
    let valid_asset_ids = convert_asset_ids(valid_asset_ids);
    let valid_asset_ids_cloned = valid_asset_ids.clone();

    let mut rng = thread_rng();

    let mut group = c.benchmark_group("MERCAT Transaction");

    for id in ASSET_IDS {
        let label = format!("asset_id: {:?}", id);
        let secret_account = utility::gen_keys(&mut rng, &AssetId::from(id));
        group.bench_with_input(
            BenchmarkId::new("Creator", label),
            &secret_account,
            |b, secret_account| {
                b.iter(|| {
                    let account_creator = AccountCreator;
                    account_creator
                        .create(&secret_account, &valid_asset_ids, &mut rng)
                        .unwrap();
                })
            },
        );
    }

    for id in ASSET_IDS {
        let label = format!("asset_id: {:?}", id);
        let account =
            utility::create_account(&mut rng, &AssetId::from(id), &valid_asset_ids_cloned);
        group.bench_with_input(
            BenchmarkId::new("Validator", label),
            &account,
            |b, account| {
                b.iter(|| {
                    let validator = AccountValidator;
                    validator.verify(account, &valid_asset_ids_cloned).unwrap()
                })
            },
        );
    }

    group.finish();
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
