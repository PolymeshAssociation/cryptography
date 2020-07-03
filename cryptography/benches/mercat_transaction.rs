mod utility;
use criterion::{criterion_group, criterion_main, Criterion};
use cryptography::{
    mercat::{
        account::convert_asset_ids,
        conf_tx::{CtxMediator, CtxReceiver, CtxSender},
        Account, EncryptionPubKey, FinalizedTx, InitializedTx, MediatorAccount, PubAccount,
        SigningPubKey, TransactionMediator, TransactionReceiver, TransactionSender, TxState,
        TxSubstate,
    },
    AssetId, Balance,
};
use rand::thread_rng;

const MIN_SENDER_BALANCE_ORDER: u32 = 1;
const MAX_SENDER_BALANCE_ORDER: u32 = 3;
const RECEIVER_INIT_BALANCE: u32 = 1000; // doesn't affect performance.
const TRANSFERRED_AMOUNT: u32 = 1; // ?
const MAX_ASSET_ID_INDEX: u32 = 100000; // doesn't affect performance.
const ASSET_ID: u32 = 1; // doesn't affect performance.

fn bench_transaction_sender(
    c: &mut Criterion,
    sender_accounts: Vec<Account>,
    rcvr_pub_account: &PubAccount,
    mdtr_pub_key: EncryptionPubKey,
    amount: Balance,
) -> Vec<InitializedTx> {
    let label = format!("MERCAT Transaction: Sender");
    let mut rng = thread_rng();
    let rcvr_pub_account = rcvr_pub_account.clone();
    let rcvr_pub_account_cloned = rcvr_pub_account.clone();

    let indexed_transaction: Vec<(String, Account)> = (MIN_SENDER_BALANCE_ORDER
        ..MAX_SENDER_BALANCE_ORDER)
        .map(|i| format!("initial_balance ({:?})", 10u32.pow(i)))
        .zip(sender_accounts.clone())
        .collect();

    c.bench_function_over_inputs(
        &label,
        move |b, (_label, sender_account)| {
            b.iter(|| {
                let sender = CtxSender {};
                sender
                    .create(
                        &sender_account.clone(),
                        &rcvr_pub_account_cloned.clone(),
                        &mdtr_pub_key.clone(),
                        amount,
                        &mut rng,
                    )
                    .unwrap()
            })
        },
        indexed_transaction,
    );

    sender_accounts
        .iter()
        .map(|sender_account| {
            let ctx_sender = CtxSender {};
            let (tx, state) = ctx_sender
                .create(
                    &sender_account.clone(),
                    &rcvr_pub_account.clone(),
                    &mdtr_pub_key.clone(),
                    amount,
                    &mut rng,
                )
                .unwrap();
            assert_eq!(state, TxState::Initialization(TxSubstate::Started));
            tx
        })
        .collect()
}

fn bench_transaction_receiver(
    c: &mut Criterion,
    receiver_account: Account,
    sender_pub_key: SigningPubKey,
    transactions: Vec<InitializedTx>,
    amount: Balance,
) -> Vec<FinalizedTx> {
    let label = format!("MERCAT Transaction: Receiver");
    let mut rng = thread_rng();
    let sender_pub_key_cloned = sender_pub_key.clone();
    let receiver_account_cloned = receiver_account.clone();

    // todo make Vec<(String, InitializedTx)>  the return type.
    let indexed_transaction: Vec<(String, InitializedTx)> = (MIN_SENDER_BALANCE_ORDER
        ..MAX_SENDER_BALANCE_ORDER)
        .map(|i| format!("initial_balance ({:?})", 10u32.pow(i)))
        .zip(transactions.clone())
        .collect();

    c.bench_function_over_inputs(
        &label,
        move |b, (_label, tx)| {
            b.iter(|| {
                let receiver = CtxReceiver {};
                receiver
                    .finalize(
                        tx.clone(),
                        &sender_pub_key.clone(), // todo right now the sender's pub account is used to get its public key.
                        receiver_account.clone(),
                        amount,
                        TxState::Initialization(TxSubstate::Started),
                        &mut rng,
                    )
                    .unwrap();
            })
        },
        indexed_transaction,
    );

    transactions
        .iter()
        .map(|tx| {
            let receiver = CtxReceiver {};
            let (finalized_tx, state) = receiver
                .finalize(
                    tx.clone(),
                    &sender_pub_key_cloned.clone(),
                    receiver_account_cloned.clone(),
                    TRANSFERRED_AMOUNT,
                    TxState::Initialization(TxSubstate::Started),
                    &mut rng,
                )
                .unwrap();
            assert_eq!(state, TxState::Finalization(TxSubstate::Started));
            finalized_tx
        })
        .collect()
}

fn bench_transaction_mediator(
    c: &mut Criterion,
    mediator_account: MediatorAccount,
    sender_pub_key: SigningPubKey,
    receiver_pub_key: SigningPubKey,
    transactions: Vec<FinalizedTx>,
    asset_id: AssetId,
) {
    let label = format!("MERCAT Transaction: Mediator");

    let indexed_transaction: Vec<(String, FinalizedTx)> = (MIN_SENDER_BALANCE_ORDER
        ..MAX_SENDER_BALANCE_ORDER)
        .map(|i| format!("initial_balance ({:?})", 10u32.pow(i)))
        .zip(transactions)
        .collect();

    c.bench_function_over_inputs(
        &label,
        move |b, (_label, tx)| {
            b.iter(|| {
                let mediator = CtxMediator {};
                mediator
                    .justify(
                        tx.clone(),
                        TxState::Finalization(TxSubstate::Started),
                        &mediator_account.encryption_key,
                        &mediator_account.signing_key,
                        &sender_pub_key,
                        &receiver_pub_key,
                        asset_id.clone(),
                    )
                    .unwrap();
            })
        },
        indexed_transaction,
    );
}

fn bench_transaction(c: &mut Criterion) {
    let asset_id = AssetId::from(ASSET_ID);
    let valid_asset_ids: Vec<AssetId> = (0..MAX_ASSET_ID_INDEX)
        .map(|id| AssetId::from(id.clone()))
        .collect();
    let valid_asset_ids = convert_asset_ids(valid_asset_ids);

    let mut rng = thread_rng();
    let (public_account, private_account) = utility::generate_mediator_keys(&mut rng);
    let sender_account = utility::create_account_with_amount(
        &mut rng,
        &asset_id,
        &valid_asset_ids,
        &private_account,
        &public_account,
        0,
    );
    // Create a receiver account and load it with some assets.
    let receiver_account = utility::create_account_with_amount(
        &mut rng,
        &asset_id,
        &valid_asset_ids,
        &private_account,
        &public_account,
        RECEIVER_INIT_BALANCE,
    );

    // Make (Max - Min) sender accounts with initial balances of: [10^Min, 10^2, ..., 10^(Max-1)]
    let sender_accounts: Vec<Account> = (MIN_SENDER_BALANCE_ORDER..MAX_SENDER_BALANCE_ORDER)
        .map(|i| {
            let value = 10u32.pow(i);
            Account {
                scrt: sender_account.scrt.clone(),
                pblc: utility::issue_assets(
                    &mut rng,
                    sender_account.clone(),
                    &private_account,
                    &public_account,
                    value,
                ),
            }
        })
        .collect();

    // Initialization
    let transactions: Vec<InitializedTx> = bench_transaction_sender(
        c,
        sender_accounts.clone(),
        &receiver_account.pblc,
        public_account.owner_enc_pub_key,
        TRANSFERRED_AMOUNT,
    );

    // Finalization
    let finalized_transactions: Vec<FinalizedTx> = bench_transaction_receiver(
        c,
        receiver_account.clone(),
        sender_account.scrt.sign_keys.public,
        transactions.clone(),
        TRANSFERRED_AMOUNT,
    );

    // Justification
    bench_transaction_mediator(
        c,
        private_account,
        sender_account.scrt.sign_keys.public,
        receiver_account.scrt.sign_keys.public,
        finalized_transactions,
        asset_id,
    );

    // Validation
    // todo
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
