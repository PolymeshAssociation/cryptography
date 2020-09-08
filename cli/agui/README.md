# Asset Granularity Unique Identity: Simple Claim Prover


## Build the CLIs

```bash
cd crypto-framework
cd agui
cargo +nightly build --release
```

The two CLIs (`polymath-scp` and `polymath-scv`) are created in `crypto-framework/target/release`. You can
call them by adding `crypto-framework/target/release` to your `PATH` environment variable,
or call them using the absolute path to the CLI file.


## Run the CLIs

To run the `simple_claim_prover` example:

```bash
polymath-scp -v -r -c rand_cdd_claim.json -s rand_scope_claim.json -p proof.json -m "my claim"
```

It will generate a random claim and save it to `rand_claim.json`. From this claim it will generate a proof of possession of the unique id over the `"my claim"` message, and save it to `proof.json`.
To learn more about the usage, run:

```bash
polymath-scp -h
```

To run the `simple_claim_verifier` example:

```bash
polymath-scv -p proof.json -m "my claim"
```

It will determine whether `proof.json` is a valid proof of possession of the unique ID.
To learn more about the usage, run:

```bash
polymath-scv -h
```