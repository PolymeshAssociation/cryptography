//! A simple commandline application to demonstrate a claim verifier's
//! steps to verify a claim proof.
//! Use `polymesh-scv --help` to see the usage.
//!

use cli_common::Proof;
use confidential_identity_v2::{
    claim_proofs::{slice_to_scalar, Verifier},
    VerifierTrait,
};
use serde::{Deserialize, Serialize};
use structopt::StructOpt;

/// polymesh-scv -- a simple claim verifier.{n}
/// The polymesh-scv utility takes in a proof and verifies it.
#[derive(StructOpt, Debug, Serialize, Deserialize)]
struct Cli {
    /// Get the Json formatted proof from file.
    #[structopt(short, long, parse(from_os_str))]
    proof: Option<std::path::PathBuf>,

    /// Verbosity level.
    #[structopt(short, long)]
    verbose: bool,
}

fn main() {
    let args = Cli::from_args();
    let proof_str = match args.proof {
        Some(p) => std::fs::read_to_string(p).expect("Failed to read the proof from file."),
        None => panic!("You must provide a proof!"),
    };

    let proof: Proof = serde_json::from_str(&proof_str)
        .unwrap_or_else(|error| panic!("Failed to deserialize the proof: {}", error));

    if args.verbose {
        println!("Proof: {:?}", proof_str);
    }

    let result = Verifier::verify_scope_claim_proof(
        &proof.proof,
        &slice_to_scalar(&proof.investor_did),
        &slice_to_scalar(&proof.scope_did),
        &proof.cdd_id,
    );

    if result.is_ok() {
        println!("Successfully verified the claim!");
    } else {
        println!("Failed to verify the proof!");
    }
}
