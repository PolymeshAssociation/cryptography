mod utility;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use mercat::{
    transaction::{verify_initialized_transaction, CtxMediator, CtxReceiver, CtxSender, TransactionValidator},
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

fn bench_transaction_sender(
    c: &mut Criterion,
    sender_account: Account,
    sender_balances: Vec<(u32, EncryptedAmount)>,
    rcvr_pub_account: PubAccount,
    mediator_pub_key: EncryptionPubKey,
) -> Vec<(u32, EncryptedAmount, InitializedTransferTx)> {
    let mut rng = thread_rng();

    let mut group = c.benchmark_group("MERCAT Transaction");
    for (amount, sender_balance) in &sender_balances {
        // Skip benchmarking amounts > 1 Million.  They are too slow.
        if *amount > 1_000_000 {
          continue;
        }
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
                            amount,
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

    sender_balances
        .into_iter()
        .map(|(amount, sender_balance)| {
            eprintln!("Generate Sender Proof for: {amount}");
            let now = std::time::Instant::now();
            let ctx_sender = CtxSender;
            let tx = ctx_sender
                .create_transaction(
                    &sender_account,
                    &sender_balance,
                    amount,
                    &rcvr_pub_account,
                    &mediator_pub_key,
                    &[],
                    amount,
                    &mut rng,
                )
                .unwrap();
            eprintln!("elapsed: {:.0?} ms", now.elapsed().as_secs_f32() * 1_000.0);
            (amount, sender_balance, tx)
        })
        .collect()
}

fn bench_transaction_verify_sender_proof(
    c: &mut Criterion,
    sender_account: PubAccount,
    receiver_account: PubAccount,
    transactions: &[(u32, EncryptedAmount, InitializedTransferTx)],
) {
    let mut rng = thread_rng();
    let mut group = c.benchmark_group("MERCAT Transaction");
    for (amount, sender_balance, tx) in transactions {
        group.bench_with_input(
            BenchmarkId::new("Verify Sender Proof", amount),
            &(tx.clone(), sender_balance.clone()),
            |b, (tx, sender_balance)| {
                b.iter(|| {
                    verify_initialized_transaction(
                      &tx, &sender_account, &sender_balance, &receiver_account, &[], &mut rng
                    ).unwrap()
                })
            },
        );
    }
    group.finish();
}

fn bench_transaction_receiver(
    c: &mut Criterion,
    receiver_account: Account,
    transactions: Vec<(u32, EncryptedAmount, InitializedTransferTx)>,
) -> Vec<(u32, EncryptedAmount, InitializedTransferTx, FinalizedTransferTx)> {
    let mut group = c.benchmark_group("MERCAT Transaction");
    for (amount, _, tx) in &transactions {
        group.bench_with_input(
            BenchmarkId::new("Receiver", *amount),
            &(amount, tx.clone()),
            |b, (&amount, tx)| {
                b.iter(|| {
                    let receiver = CtxReceiver;
                    receiver
                        .finalize_transaction(&tx, receiver_account.clone(), amount)
                        .unwrap()
                })
            },
        );
    }
    group.finish();

    transactions
        .into_iter()
        .map(|(amount, sender_balance, init_tx)| {
            let receiver = CtxReceiver;
            let fin_tx = receiver
                .finalize_transaction(&init_tx, receiver_account.clone(), amount)
                .unwrap();
            (amount, sender_balance, init_tx, fin_tx)
        })
        .collect()
}

fn bench_transaction_mediator(
    c: &mut Criterion,
    mediator_account: MediatorAccount,
    sender_pub_account: PubAccount,
    receiver_pub_account: PubAccount,
    transactions: Vec<(u32, EncryptedAmount, InitializedTransferTx, FinalizedTransferTx)>,
) -> Vec<JustifiedTransferTx> {
    let mut rng = thread_rng();

    let mut group = c.benchmark_group("MERCAT Transaction");
    for (amount, sender_balance, init_tx, fin_tx) in &transactions {
        let label = format!("initial_balance ({:?})", amount);
        group.bench_with_input(
            BenchmarkId::new("Mediator", label),
            &(sender_balance, init_tx.clone(), fin_tx.clone()),
            |b, (sender_balance, init_tx, fin_tx)| {
                b.iter(|| {
                    let mediator = CtxMediator;
                    mediator
                        .justify_transaction(
                            init_tx,
                            fin_tx,
                            &mediator_account.encryption_key,
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

    transactions
        .into_iter()
        .map(|(_, sender_balance, init_tx, fin_tx)| {
            let mediator = CtxMediator;
            mediator
                .justify_transaction(
                    &init_tx,
                    &fin_tx,
                    &mediator_account.encryption_key,
                    &sender_pub_account,
                    &sender_balance,
                    &receiver_pub_account,
                    &[],
                    &mut rng,
                )
                .unwrap()
        })
        .collect()
}

fn bench_transaction_validator(
    c: &mut Criterion,
    sender_pub_account: PubAccount,
    receiver_pub_account: PubAccount,
    transactions: Vec<(u32, EncryptedAmount, InitializedTransferTx, FinalizedTransferTx)>,
) {
    let mut rng = thread_rng();

    let mut group = c.benchmark_group("MERCAT Transaction");
    for (amount, sender_balance, init_tx, fin_tx) in &transactions {
        let label = format!("initial_balance ({:?})", amount);
        group.bench_with_input(
            BenchmarkId::new("Validator", label),
            &(sender_balance, init_tx.clone(), fin_tx.clone()),
            |b, (sender_balance, init_tx, fin_tx)| {
                b.iter(|| {
                    let validator = TransactionValidator;
                    validator
                        .verify_transaction(
                            init_tx,
                            fin_tx,
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
    let mut rng = thread_rng();
    let (enc_pub_key, private_account) = utility::generate_mediator_keys(&mut rng);
    let (sender_account, sender_init_balance) = utility::create_account_with_amount(&mut rng, 0);
    let sender_pub_account = sender_account.public.clone();

    // Create a receiver account and load it with some assets.
    let (receiver_account, _receiver_balance) =
        utility::create_account_with_amount(&mut rng, RECEIVER_INIT_BALANCE);

    let mut amounts: Vec<u32> = Vec::new();
    // Make (Max - Min) sender accounts with initial balances of: [10^Min, 10^2, ..., 10^(Max-1)]
    for i in MIN_SENDER_BALANCE_ORDER..MAX_SENDER_BALANCE_ORDER {
      let amount = 10u32.pow(i);
      amounts.push(amount);
    }
    // Add some very large amounts.
    amounts.push(20_000_000); // About 6.97 seconds.
    amounts.push(200_000_000); // About 68.79 seconds (About 1 minute).
    // Very slow to generate sender proof.
    //amounts.push(2_000_000_000); // Estimate 11.5 minutes?
    //amounts.push(3_000_000_000); // Estimate 17.19 minutes?
    //amounts.push(4_000_000_000); // Estimate 22.93 minutes?
    let sender_balances: Vec<_> = amounts.into_iter()
        .map(|amount| {
            (amount, utility::issue_assets(&mut rng, &sender_pub_account, &sender_init_balance, amount))
        })
        .collect();

    // Initialization
    let transactions = bench_transaction_sender(
        c,
        sender_account,
        sender_balances,
        receiver_account.public.clone(),
        enc_pub_key,
    );

    // Verify sender proofs.
    eprintln!("--- Verify Sender Proofs");
    bench_transaction_verify_sender_proof(
        c,
        sender_pub_account.clone(),
        receiver_account.public.clone(),
        &transactions);

    // Finalization
    let finalized_transactions =
        bench_transaction_receiver(c, receiver_account.clone(), transactions);

    // Justification
    bench_transaction_mediator(
        c,
        private_account,
        sender_pub_account.clone(),
        receiver_account.public.clone(),
        finalized_transactions.clone(),
    );

    // Validation
    bench_transaction_validator(
        c,
        sender_pub_account,
        receiver_account.public,
        finalized_transactions,
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
