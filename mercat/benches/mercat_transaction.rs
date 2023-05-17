mod utility;
use confidential_identity_core::{
    asset_proofs::{
        bulletproofs::PedersenGens,
        ciphertext_refreshment_proof::{
            CipherEqualSamePubKeyProof, CipherTextRefreshmentProverAwaitingChallenge,
        },
        correctness_proof::{CorrectnessProof, CorrectnessProverAwaitingChallenge},
        elgamal_encryption::encrypt_using_two_pub_keys,
        encrypting_same_value_proof::{
            CipherEqualDifferentPubKeyProof, EncryptingSameValueProverAwaitingChallenge,
        },
        encryption_proofs::single_property_prover,
        errors::Fallible,
        range_proof::{prove_within_range, InRangeProof},
        Balance, CommitmentWitness, BALANCE_RANGE,
    },
    curve25519_dalek::scalar::Scalar,
};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use mercat::{
    transaction::{
        verify_initialized_transaction, CtxMediator, CtxReceiver, CtxSender, TransactionValidator,
    },
    Account, EncryptedAmount, EncryptedAmountWithHint, EncryptionPubKey, EncryptionSecKey,
    FinalizedTransferTx, InitializedTransferTx, JustifiedTransferTx, MediatorAccount, PubAccount,
    TransferTransactionMediator, TransferTransactionReceiver, TransferTransactionSender,
    TransferTransactionVerifier,
};
use rand::thread_rng;
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

// The sender's initial balance. Will be in:
// [10^MIN_SENDER_BALANCE_ORDER, 10^(MIN_SENDER_BALANCE_ORDER+1), ..., 10^MAX_SENDER_BALANCE_ORDER]
// The transferred amout on each iteration will be all the balance the sender has: 10^SENDER_BALANCE_ORDER
use utility::balance_range::{MAX_SENDER_BALANCE_ORDER, MIN_SENDER_BALANCE_ORDER};

// The receiver's initial balance.
const RECEIVER_INIT_BALANCE: Balance = 10000;

#[derive(Clone)]
struct SenderProofGen {
    // Inputs.
    sender_sec: EncryptionSecKey,
    sender_pub: EncryptionPubKey,
    sender_init_balance: EncryptedAmount,
    sender_balance: Balance,
    receiver_pub: EncryptionPubKey,
    mediator_pub: EncryptionPubKey,
    pub amount: Balance,
    // Temps.
    last_stage: u32,
    witness: CommitmentWitness,
    gens: PedersenGens,
    balance_refresh_enc_blinding: Scalar,
    // Outputs.
    amount_equal_cipher_proof: Option<CipherEqualDifferentPubKeyProof>,
    non_neg_amount_proof: Option<InRangeProof>,
    enough_fund_proof: Option<InRangeProof>,
    enc_amount_using_sender: Option<EncryptedAmount>,
    enc_amount_using_receiver: Option<EncryptedAmount>,
    refreshed_enc_balance: Option<EncryptedAmount>,
    enc_amount_for_mediator: Option<EncryptedAmountWithHint>,
    balance_refreshed_same_proof: Option<CipherEqualSamePubKeyProof>,
    amount_correctness_proof: Option<CorrectnessProof>,
}

impl SenderProofGen {
    pub fn new<T: RngCore + CryptoRng>(
        sender_account: &Account,
        sender_init_balance: &EncryptedAmount,
        sender_balance: Balance,
        receiver_pub_account: &PubAccount,
        mediator_pub_key: &EncryptionPubKey,
        amount: Balance,
        rng: &mut T,
    ) -> Self {
        Self {
            // Inputs.
            sender_sec: sender_account.secret.enc_keys.secret.clone(),
            sender_pub: sender_account.secret.enc_keys.public.clone(),
            sender_init_balance: sender_init_balance.clone(),
            sender_balance,
            receiver_pub: receiver_pub_account.owner_enc_pub_key.clone(),
            mediator_pub: mediator_pub_key.clone(),
            amount,

            // Temps.
            last_stage: 0,
            witness: CommitmentWitness::new(amount.into(), Scalar::random(rng)),
            gens: PedersenGens::default(),
            balance_refresh_enc_blinding: Scalar::random(rng),

            // Outputs.
            amount_equal_cipher_proof: None,
            non_neg_amount_proof: None,
            enough_fund_proof: None,
            enc_amount_using_sender: None,
            enc_amount_using_receiver: None,
            refreshed_enc_balance: None,
            enc_amount_for_mediator: None,
            balance_refreshed_same_proof: None,
            amount_correctness_proof: None,
        }
    }

    fn run_to_stage<T: RngCore + CryptoRng>(&mut self, to_stage: u32, rng: &mut T) -> Fallible<()> {
        while self.last_stage < to_stage {
            self.run_next_stage(rng)?;
        }
        Ok(())
    }

    fn run_next_stage<T: RngCore + CryptoRng>(&mut self, rng: &mut T) -> Fallible<()> {
        match self.last_stage {
            0 => {
                // Ensure the sender has enough funds.
                // Verify the sender's balance.
                self.sender_sec
                    .verify(&self.sender_init_balance, &self.sender_balance.into())?;
            }
            1 => {
                // Prove that the amount is not negative.
                let amount_enc_blinding = self.witness.blinding();
                self.non_neg_amount_proof = Some(prove_within_range(
                    self.amount.into(),
                    amount_enc_blinding,
                    BALANCE_RANGE,
                    rng,
                )?);
            }
            2 => {
                // Prove that the amount encrypted under different public keys are the same.
                let (sender_new_enc_amount, receiver_new_enc_amount) =
                    encrypt_using_two_pub_keys(&self.witness, self.sender_pub, self.receiver_pub);
                self.enc_amount_using_sender = Some(sender_new_enc_amount);
                self.enc_amount_using_receiver = Some(receiver_new_enc_amount);
            }
            3 => {
                self.amount_equal_cipher_proof = Some(single_property_prover(
                    EncryptingSameValueProverAwaitingChallenge {
                        pub_key1: self.sender_pub,
                        pub_key2: self.receiver_pub,
                        w: Zeroizing::new(self.witness.clone()),
                        pc_gens: &self.gens,
                    },
                    rng,
                )?);
            }
            4 => {
                // Refresh the encrypted balance and prove that the refreshment was done
                // correctly.
                self.refreshed_enc_balance = Some(self.sender_init_balance.refresh_with_hint(
                    &self.sender_sec,
                    self.balance_refresh_enc_blinding,
                    &self.sender_balance.into(),
                )?);
            }
            5 => {
                let refreshed_enc_balance = self.refreshed_enc_balance.unwrap();
                self.balance_refreshed_same_proof = Some(single_property_prover(
                    CipherTextRefreshmentProverAwaitingChallenge::new(
                        self.sender_sec.clone(),
                        self.sender_init_balance,
                        refreshed_enc_balance,
                        &self.gens,
                    ),
                    rng,
                )?);
            }
            6 => {
                // Prove that the sender has enough funds.
                let amount_enc_blinding = self.witness.blinding();
                let blinding = self.balance_refresh_enc_blinding - amount_enc_blinding;
                self.enough_fund_proof = Some(prove_within_range(
                    (self.sender_balance - self.amount).into(),
                    blinding,
                    BALANCE_RANGE,
                    rng,
                )?);
            }
            7 => {
                let amount_witness_blinding_for_mediator = Scalar::random(rng);
                let amount_witness_for_mediator = CommitmentWitness::new(
                    self.amount.into(),
                    amount_witness_blinding_for_mediator,
                );
                self.enc_amount_for_mediator = Some(
                    self.mediator_pub
                        .const_time_encrypt(&amount_witness_for_mediator, rng),
                );
            }
            8 => {
                self.amount_correctness_proof = Some(single_property_prover(
                    CorrectnessProverAwaitingChallenge {
                        pub_key: self.sender_pub,
                        w: self.witness.clone(),
                        pc_gens: &self.gens,
                    },
                    rng,
                )?);
            }
            _ => {
                return Ok(());
            }
        }
        self.last_stage += 1;

        Ok(())
    }
}

fn bench_transaction_sender_proof_stage(
    c: &mut Criterion,
    sender_account: Account,
    sender_balances: &[(Balance, EncryptedAmount)],
    rcvr_pub_account: PubAccount,
    mediator_pub_key: EncryptionPubKey,
    bench_stage: u32,
) {
    let mut rng = thread_rng();

    let proof_gens: Vec<_> = sender_balances
        .into_iter()
        .map(|(amount, sender_balance)| {
            let mut proof_gen = SenderProofGen::new(
                &sender_account,
                sender_balance,
                *amount,
                &rcvr_pub_account,
                &mediator_pub_key,
                *amount,
                &mut rng,
            );
            if bench_stage > 1 {
                proof_gen
                    .run_to_stage(bench_stage - 1, &mut rng)
                    .expect("Stages run ok");
            }

            proof_gen
        })
        .collect();

    let mut group = c.benchmark_group("MERCAT Transaction");
    for proof_gen in proof_gens {
        // Skip benchmarking amounts > 1 Million.  They are too slow.
        if proof_gen.amount > 1_000_000 {
            continue;
        }
        group.bench_with_input(
            BenchmarkId::new(
                format!("Sender Proof Stage {bench_stage}"),
                proof_gen.amount,
            ),
            &proof_gen,
            |b, proof_gen: &SenderProofGen| {
                b.iter(|| {
                    let mut gen = proof_gen.clone();
                    gen.run_to_stage(bench_stage, &mut rng).expect("Stage ok");
                    gen
                })
            },
        );
    }
    group.finish();
}

fn bench_transaction_sender(
    c: &mut Criterion,
    sender_account: Account,
    sender_balances: Vec<(Balance, EncryptedAmount)>,
    rcvr_pub_account: PubAccount,
    mediator_pub_key: EncryptionPubKey,
) -> Vec<(Balance, EncryptedAmount, InitializedTransferTx)> {
    let mut rng = thread_rng();

    let mut group = c.benchmark_group("MERCAT Transaction");
    for (amount, sender_balance) in &sender_balances {
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
    transactions: &[(Balance, EncryptedAmount, InitializedTransferTx)],
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
                        &tx,
                        &sender_account,
                        &sender_balance,
                        &receiver_account,
                        &[],
                        &mut rng,
                    )
                    .unwrap()
                })
            },
        );
    }
    group.finish();
}

fn bench_transaction_receiver(
    c: &mut Criterion,
    receiver_account: Account,
    transactions: Vec<(Balance, EncryptedAmount, InitializedTransferTx)>,
) -> Vec<(
    Balance,
    EncryptedAmount,
    InitializedTransferTx,
    FinalizedTransferTx,
)> {
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
    transactions: Vec<(
        Balance,
        EncryptedAmount,
        InitializedTransferTx,
        FinalizedTransferTx,
    )>,
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
    transactions: Vec<(
        Balance,
        EncryptedAmount,
        InitializedTransferTx,
        FinalizedTransferTx,
    )>,
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

    // Sender proof gen. bench each stage.
    let sender_balances: Vec<_> = [10 as Balance, 1_000_000_000]
        .iter()
        .map(|&amount| {
            (
                amount,
                utility::issue_assets(&mut rng, &sender_pub_account, &sender_init_balance, amount),
            )
        })
        .collect();
    for stage in 1..=9 {
        bench_transaction_sender_proof_stage(
            c,
            sender_account.clone(),
            &sender_balances,
            receiver_account.public.clone(),
            enc_pub_key.clone(),
            stage,
        );
    }

    let mut amounts: Vec<Balance> = Vec::new();
    // Make (Max - Min) sender accounts with initial balances of: [10^Min, 10^2, ..., 10^(Max-1)]
    for i in MIN_SENDER_BALANCE_ORDER..MAX_SENDER_BALANCE_ORDER {
        let amount = (10 as Balance).pow(i);
        amounts.push(amount);
    }
    let sender_balances: Vec<_> = amounts
        .into_iter()
        .map(|amount| {
            (
                amount,
                utility::issue_assets(&mut rng, &sender_pub_account, &sender_init_balance, amount),
            )
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
        &transactions,
    );

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
