//! A simple commandline application to demonstrate a claim verifier's
//! steps to verify a claim proof.
//! Use `scv --help` to see the usage.
//!

use cryptography::claim_proofs::{ProofPublicKey, RawData};
use curve25519_dalek::ristretto::RistrettoPoint;
use schnorrkel::Signature;
use serde::{Deserialize, Serialize};
use structopt::StructOpt;

#[derive(Serialize, Deserialize)]
struct Proof {
    claim_label: RistrettoPoint,
    inv_id_0: RawData,
    did_label: RistrettoPoint,
    iss_id: RawData,
    #[serde(with = "serde_bytes")]
    proof: Vec<u8>,
}

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
        Some(p) => match std::fs::read_to_string(p) {
            Ok(ps) => ps,
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(exitcode::DATAERR);
            }
        },
        None => panic!("You must provide a proof!"),
    };

    if args.verbose {
        println!("Proof: {:?}", proof_str);
        println!("Message: {:?}", args.message);
    }

    let proof: Proof = serde_json::from_str(&proof_str).unwrap();
    let verifier_pub = ProofPublicKey::new(
        proof.did_label,
        &proof.inv_id_0,
        proof.claim_label,
        &proof.iss_id,
    );

    if verifier_pub.verify_id_match_proof(
        args.message.as_bytes(),
        &Signature::from_bytes(proof.proof.as_slice()).unwrap(),
    ) {
        println!("Successfully verified the claim!");
    } else {
        println!("Failed to verify the proof!");
    }
}
