# Confidential Identity Library


To build the cli, follow the steps of the README.md in the root of the
repository. In particular, running `cargo +nightly build --release` will
build the `polymath-scp` and `polymath-scv` and places them in
`cryptography/target/release`. You can view the usage instructions of
each command through the `help` subcommand.


## CDD Provider Usage

Given `my_cdd_claim.json` file with the following content

```json
{
  "investor_did":[32_bytes_array],
  "investor_unique_id":[16_bytes_array]
}
```

A CDD provider can use the `polymath-scp` CLI with the `create-cdd-id` sub-command
to create the CDD Id that they can later bundle as a claim and save on Polymesh.

```bash
polymath-scp create-cdd-id -v --cdd-claim my_cdd_claim.json

# For your convenience we have provided an optional flag (`-r` or `--rand`) to randomly generate the inputted JSON file:
polymath-scp create-cdd-id -v -r --cdd-claim rand_cdd_claim.json
# You can optionally save the resulting CDD Id to file, if you pass in the `cdd-id` with a file name:
polymath-scp create-cdd-id -v --cdd-claim my_cdd_claim.json --cdd-id my_cdd_id.json
# To see the usage for this sub-command, run:
polymath-scp create-cdd-id -h
```

## Investors' Usage

Given `my_scope_claim.json` file with the following content

```json
{
  "scope_did":[12_bytes_array],
  "investor_unique_id":[16_bytes_array]
}
```

and the `my_cdd_claim.json`, the investor can use the `polymath-scp` CLI with the `create-claim-proof` sub-command to generate
a confidential proof which PolyMesh will later use to verify the integrity of scope claim as well as aggregate all
investments made by identities that share the same unique identifier (`investor_unique_id`) without having the knowledge
of the unique id.

<<<<<<< HEAD
=======
## Simple Claim Verifier
The `polymath-scv` CLI can be used to verify an investor's claim proof the same way that the PolyMesh would do.
Note that this verification does not apply to the CDD Id that the CDD Provider generates.

## Build the CLIs

```bash
cargo +nightly build --release
```

The two CLIs (`polymath-scp` and `polymath-scv`) are placed in `cryptography/target/release`. You can
call them by adding `cryptography/target/release` to your `PATH` environment variable,
or call them using the absolute path to the CLI file.

## Run the CLIs
### CDD Provider Usage
To create the CDD Id using the prover CLI:
```bash
polymath-scp create-cdd-id -v --cdd-claim my_cdd_claim.json
```
For your convenience we have provided an optional flag (`-r` or `--rand`) to randomly generate the inputted JSON file:
```bash
polymath-scp create-cdd-id -v -r --cdd-claim rand_cdd_claim.json
```
You can optionally save the resulting CDD Id to file, if you pass in the `cdd-id` with a file name:
```bash
polymath-scp create-cdd-id -v --cdd-claim my_cdd_claim.json --cdd-id my_cdd_id.json
```
To see the usage for this sub-command, run:
```bash
polymath-scp create-cdd-id -h
```

### Investors' Usage
To run Claim prover CLI:
>>>>>>> add the rest of wrappers.
```bash
polymath-scp create-claim-proof -v --cdd-claim my_cdd_claim.json --scope-claim my_scope_claim.json --proof proof.json

# For your convenience we have provided an optional flag (`-r` or `--rand`) to randomly generate the inputted JSON file.
polymath-scp create-claim-proof -v -r --cdd-claim rand_cdd_claim.json --scope-claim rand_scope_claim.json --proof proof.json
# This command will generate a random CDD claim as well as a random scope claim and save them into separate JSON files.
# From these claims it will generate a proof of possession of the unique id and save it to `proof.json`.

# To see the usage for this sub-command, run:
polymath-scp create-claim-proof -h
```

## Simple Claim Verifier

The `polymath-scv` CLI can be used to verify an investor's claim proof the same way that the PolyMesh would do.
Note that this verification does not apply to the CDD Id that the CDD Provider generates.


```bash
polymath-scv --proof proof.json
# It will determine whether `proof.json` is a valid proof of possession of the unique ID.

# To learn more about the usage, run:
polymath-scv -h
```

[cdd-register-did]: https://docs.polymesh.live/pallet_identity/enum.Call.html#variant.cdd_register_did
[IdentityId]: https://docs.polymesh.live/polymesh_primitives/identity_id/struct.IdentityId.html
[add-claim]: https://docs.polymesh.live/pallet_identity/enum.Call.html#variant.add_claim
