//! A simple commandline application to demonstrate a claim verifier's
//! steps to verify a claim proof.
//! Use `scv --help` to see the usage.
//!

use cli_common::Proof;
use cryptography::claim_proofs::ProofPublicKey;

use schnorrkel::Signature;
use serde::{Deserialize, Serialize};
use structopt::StructOpt;


/// scv -- a simple claim verifier.{n}
/// The scv utility takes in a message and its proof and verifies it.
#[derive(StructOpt, Debug, Serialize, Deserialize)]
struct Cli {
    /// Message to verify.
    #[structopt(short, long, default_value = "A very important claim.")]
    message: String,

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

    if args.verbose {
        println!("Proof: {:?}", proof_str);
        println!("Message: {:?}", args.message);
    }

    let proof: Proof = serde_json::from_str(&proof_str)
        .unwrap_or_else(|error| panic!("Failed to deserialize the proof: {}", error));
    let verifier_pub = ProofPublicKey::new(
        proof.cdd_id,
        &proof.investor_did,
        proof.scope_id,
        &proof.scope_did,
    );

    if verifier_pub.verify_id_match_proof(
        args.message.as_bytes(),
        &Signature::from_bytes(proof.proof.as_slice())
            .unwrap_or_else(|error| panic!("Failed to parse the proof: {}", error)),
    ) {
        println!("Successfully verified the claim!");
    } else {
        println!("Failed to verify the proof!");
    }
}
