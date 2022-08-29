mod utility;
use confidential_identity_core::asset_proofs::AssetId;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use mercat::{
    account::convert_asset_ids,
    transaction::{CtxMediator, CtxReceiver, CtxSender, TransactionValidator},
    Account, EncryptedAmount, EncryptionPubKey, FinalizedTransferTx, InitializedTransferTx,
    JustifiedTransferTx, MediatorAccount, PubAccount, TransferTransactionMediator,
    TransferTransactionReceiver, TransferTransactionSender, TransferTransactionVerifier,
};
use rand::thread_rng;

// The sender's initial balance. Will be in:
// [10^MIN_SENDER_BALANCE_ORDER, 10^(MIN_SENDER_BALANCE_ORDER+1), ..., 10^MAX_SENDER_BALANCE_ORDER]
// The transferred amout on each iteration will be all the balance the sender has: 10^SENDER_BALANCE_ORDER
const MIN_SENDER_BALANCE_ORDER: u32 = 1;
const MAX_SENDER_BALANCE_ORDER: u32 = 7;

// The receiver's initial balance.
const RECEIVER_INIT_BALANCE: u32 = 10000;

// The size of the valid asset id set.
const MAX_ASSET_ID_INDEX: u32 = 1000000;
// The asset id to use for transactions.
// Must be in [0, MAX_ASSET_ID_INDEX)
const ASSET_ID: u32 = 1;

fn bench_transaction_sender(
    c: &mut Criterion,
    sender_account: Account,
    sender_balances: Vec<EncryptedAmount>,
    rcvr_pub_account: PubAccount,
    mediator_pub_key: EncryptionPubKey,
) -> Vec<InitializedTransferTx> {
    let mut rng = thread_rng();
    let indexed_transaction: Vec<(u32, EncryptedAmount)> = (MIN_SENDER_BALANCE_ORDER
        ..MAX_SENDER_BALANCE_ORDER)
        .map(|i| 10u32.pow(i))
        .zip(sender_balances)
        .collect();

    let mut group = c.benchmark_group("MERCAT Transaction");
    for (amount, sender_balance) in &indexed_transaction {
        group.bench_with_input(
            BenchmarkId::new("Sender", *amount),
            &(amount, sender_balance),
            |b, (&amount, sender_balance)| {
                b.iter(|| {
                    let sender = CtxSender;
                    sender
                        .create_transaction(
                            &sender_account,
                            sender_balance,
                            &rcvr_pub_account,
                            &mediator_pub_key.clone(),
                            &[],
                            amount,
                            &mut rng,
                        )
                        .unwrap()
                })
            },
        );
    }
    group.finish();

    indexed_transaction
        .iter()
        .map(|(amount, sender_balance)| {
            let ctx_sender = CtxSender;
            ctx_sender
                .create_transaction(
                    &sender_account,
                    sender_balance,
                    &rcvr_pub_account,
                    &mediator_pub_key,
                    &[],
                    *amount,
                    &mut rng,
                )
                .unwrap()
        })
        .collect()
}

fn bench_transaction_receiver(
    c: &mut Criterion,
    receiver_account: Account,
    transactions: Vec<InitializedTransferTx>,
) -> Vec<FinalizedTransferTx> {
    let mut rng = thread_rng();

    let indexed_transaction: Vec<(u32, InitializedTransferTx)> = (MIN_SENDER_BALANCE_ORDER
        ..MAX_SENDER_BALANCE_ORDER)
        .map(|i| 10u32.pow(i))
        .zip(transactions)
        .collect();

    let mut group = c.benchmark_group("MERCAT Transaction");
    for (amount, tx) in &indexed_transaction {
        group.bench_with_input(
            BenchmarkId::new("Receiver", *amount),
            &(amount, tx.clone()),
            |b, (&amount, tx)| {
                b.iter(|| {
                    let receiver = CtxReceiver;
                    receiver
                        .finalize_transaction(
                            tx.clone(),
                            receiver_account.clone(),
                            amount,
                            &mut rng,
                        )
                        .unwrap()
                })
            },
        );
    }
    group.finish();

    indexed_transaction
        .iter()
        .map(|(amount, tx)| {
            let receiver = CtxReceiver;
            receiver
                .finalize_transaction(tx.clone(), receiver_account.clone(), *amount, &mut rng)
                .unwrap()
        })
        .collect()
}

fn bench_transaction_mediator(
    c: &mut Criterion,
    mediator_account: MediatorAccount,
    sender_pub_account: PubAccount,
    sender_pub_balances: Vec<EncryptedAmount>,
    receiver_pub_account: PubAccount,
    transactions: Vec<FinalizedTransferTx>,
    asset_id: AssetId,
) -> Vec<JustifiedTransferTx> {
    let mut rng = thread_rng();

    let indexed_transaction: Vec<((String, EncryptedAmount), FinalizedTransferTx)> =
        (MIN_SENDER_BALANCE_ORDER..MAX_SENDER_BALANCE_ORDER)
            .map(|i| format!("initial_balance ({:?})", 10u32.pow(i)))
            .zip(sender_pub_balances)
            .zip(transactions)
            .collect();

    let mut group = c.benchmark_group("MERCAT Transaction");
    for ((label, sender_balance), tx) in &indexed_transaction {
        group.bench_with_input(
            BenchmarkId::new("Mediator", label),
            &(sender_balance, tx.clone()),
            |b, (sender_balance, tx)| {
                b.iter(|| {
                    let mediator = CtxMediator;
                    mediator
                        .justify_transaction(
                            tx.clone(),
                            &mediator_account.encryption_key,
                            &sender_pub_account,
                            sender_balance,
                            &receiver_pub_account,
                            &[],
                            asset_id.clone(),
                            &mut rng,
                        )
                        .unwrap();
                })
            },
        );
    }
    group.finish();

    indexed_transaction
        .into_iter()
        .map(|((_, sender_balance), tx)| {
            let mediator = CtxMediator;
            mediator
                .justify_transaction(
                    tx,
                    &mediator_account.encryption_key,
                    &sender_pub_account,
                    &sender_balance,
                    &receiver_pub_account,
                    &[],
                    asset_id.clone(),
                    &mut rng,
                )
                .unwrap()
        })
        .collect()
}

fn bench_transaction_validator(
    c: &mut Criterion,
    sender_pub_account: PubAccount,
    sender_pub_balances: Vec<EncryptedAmount>,
    receiver_pub_account: PubAccount,
    transactions: Vec<JustifiedTransferTx>,
) {
    let mut rng = thread_rng();

    let indexed_transaction: Vec<((String, EncryptedAmount), JustifiedTransferTx)> =
        (MIN_SENDER_BALANCE_ORDER..MAX_SENDER_BALANCE_ORDER)
            .map(|i| format!("initial_balance ({:?})", 10u32.pow(i)))
            .zip(sender_pub_balances)
            .zip(transactions)
            .collect();

    let mut group = c.benchmark_group("MERCAT Transaction");
    for ((label, sender_balance), tx) in indexed_transaction {
        group.bench_with_input(
            BenchmarkId::new("Validator", label),
            &(sender_balance, tx.clone()),
            |b, (sender_balance, tx)| {
                b.iter(|| {
                    let validator = TransactionValidator;
                    validator
                        .verify_transaction(
                            &tx,
                            &sender_pub_account,
                            sender_balance,
                            &receiver_pub_account,
                            &[],
                            &mut rng,
                        )
                        .unwrap();
                })
            },
        );
    }
    group.finish();
}

fn bench_transaction(c: &mut Criterion) {
    let asset_id = AssetId::from(ASSET_ID);
    let valid_asset_ids: Vec<AssetId> = (0..MAX_ASSET_ID_INDEX).map(AssetId::from).collect();
    let valid_asset_ids = convert_asset_ids(valid_asset_ids);

    let mut rng = thread_rng();
    let (enc_pub_key, private_account) = utility::generate_mediator_keys(&mut rng);
    let (sender_account, sender_init_balance) =
        utility::create_account_with_amount(&mut rng, &asset_id, &valid_asset_ids, 0);
    let sender_pub_account = sender_account.public.clone();

    // Create a receiver account and load it with some assets.
    let (receiver_account, _receiver_balance) = utility::create_account_with_amount(
        &mut rng,
        &asset_id,
        &valid_asset_ids,
        RECEIVER_INIT_BALANCE,
    );

    // Make (Max - Min) sender accounts with initial balances of: [10^Min, 10^2, ..., 10^(Max-1)]
    let sender_balances: Vec<EncryptedAmount> = (MIN_SENDER_BALANCE_ORDER
        ..MAX_SENDER_BALANCE_ORDER)
        .map(|i| {
            let value = 10u32.pow(i);
            utility::issue_assets(&mut rng, &sender_pub_account, &sender_init_balance, value)
        })
        .collect();

    // Initialization
    let transactions: Vec<InitializedTransferTx> = bench_transaction_sender(
        c,
        sender_account,
        sender_balances.clone(),
        receiver_account.public.clone(),
        enc_pub_key,
    );

    // Finalization
    let finalized_transactions: Vec<FinalizedTransferTx> =
        bench_transaction_receiver(c, receiver_account.clone(), transactions);

    // Justification
    let justified_transaction: Vec<JustifiedTransferTx> = bench_transaction_mediator(
        c,
        private_account,
        sender_pub_account.clone(),
        sender_balances.clone(),
        receiver_account.public.clone(),
        finalized_transactions,
        asset_id,
    );

    // Validation
    bench_transaction_validator(
        c,
        sender_pub_account,
        sender_balances,
        receiver_account.public,
        justified_transaction,
    );
}

criterion_group! {
    name = mercat_transaction;
    // Lower the sample size to run faster; larger shuffle sizes are
    // long so we're not microbenchmarking anyways.
    // 10 is the minimum allowed sample size in Criterion.
    config = Criterion::default()
        .sample_size(10);
        // .measurement_time(Duration::new(60, 0));
    targets = bench_transaction,
}

criterion_main!(mercat_transaction);
