//! A simple commandline application to demonstrate a claim verifier's
//! steps to verify a claim proof.
//! Use `polymath-scv --help` to see the usage.
//!

use cli_common::{make_message, Proof};
use confidential_identity::ProofPublicKey;
use schnorrkel::Signature;
use serde::{Deserialize, Serialize};
use structopt::StructOpt;

/// polymath-scv -- a simple claim verifier.{n}
/// The polymath-scv utility takes in a proof and verifies it.
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
    // Recreate the message from the investor DID and the scope DID.
    let message = make_message(&proof.investor_did, &proof.scope_did);

    if args.verbose {
        println!("Proof: {:?}", proof_str);
        println!("Message: {:?}", message);
    }

    let verifier_pub = ProofPublicKey::new(
        proof.cdd_id,
        &proof.investor_did,
        proof.scope_id,
        &proof.scope_did,
    );

    if verifier_pub.verify_id_match_proof(
        &message,
        &Signature::from_bytes(proof.proof.as_slice())
            .unwrap_or_else(|error| panic!("Failed to parse the proof: {}", error)),
    ) {
        println!("Successfully verified the claim!");
    } else {
        println!("Failed to verify the proof!");
    }
}
