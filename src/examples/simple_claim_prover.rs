//! A simple commandline application to demonstrate a claim prover's (AKA an investor)
//! steps to create proofs for their claims.
//! Use `scp --help` to see the usage.
//!

use cryptography::claim_proofs::{compute_label, ClaimData, ProofKeyPair, RawData};
use curve25519_dalek::ristretto::RistrettoPoint;
use rand::{rngs::StdRng, Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use structopt::StructOpt;

#[derive(Debug, Serialize, Deserialize)]
pub struct Proof {
    claim_label: RistrettoPoint,
    inv_id_0: RawData,
    did_label: RistrettoPoint,
    iss_id: RawData,
    #[serde(with = "serde_bytes")]
    proof: Vec<u8>,
}

/// scp -- a simple claim prover.{n}
/// The scp utility (optionally) creates a random claim and proves it.
#[derive(StructOpt, Debug, Serialize, Deserialize)]
struct Cli {
    /// Generate and use a random claim.
    #[structopt(short, long)]
    rand: bool,

    /// Message to prove.
    #[structopt(short, long, default_value = "A very important claim.")]
    message: String,

    /// Get the Json formatted claim from file.
    #[structopt(short, long, parse(from_os_str))]
    claim: Option<std::path::PathBuf>,

    /// Write the proof to file in Json format.
    #[structopt(short, long, parse(from_os_str))]
    proof: Option<std::path::PathBuf>,

    /// Be verbose.
    #[structopt(short, long)]
    verbose: bool,
}

fn random_claim<R: Rng + ?Sized>(rng: &mut R) -> ClaimData {
    let mut inv_id_0 = RawData::default();
    let mut inv_id_1 = RawData::default();
    let mut inv_blind = RawData::default();
    let mut iss_id = RawData::default();

    rng.fill_bytes(&mut inv_id_0.0);
    rng.fill_bytes(&mut inv_id_1.0);
    rng.fill_bytes(&mut inv_blind.0);
    rng.fill_bytes(&mut iss_id.0);

    ClaimData {
        inv_id_0,
        inv_id_1,
        inv_blind,
        iss_id,
    }
}

fn main() {
    let args = Cli::from_args();

    let claim_data: ClaimData = if args.rand {
        let mut rng = StdRng::from_seed([42u8; 32]);
        random_claim(&mut rng)
    } else {
        match args.claim {
            Some(c) => {
                let result = std::fs::read_to_string(&c);
                match result {
                    Ok(json_file_content) => serde_json::from_str(&json_file_content).unwrap(),
                    Err(error) => {
                        panic!("Can't deal with {}, just exit here", error);
                    }
                }
            }
            None => panic!("You must either pass in a claim file or generate it randomly."),
        }
    };

    if args.verbose {
        println!("Claim: {:?}", serde_json::to_string(&claim_data).unwrap());
        println!("Message: {:?}", args.message);
    }

    let message: &[u8] = args.message.as_bytes();
    let pair = ProofKeyPair::from(claim_data);
    let proof = pair.generate_id_match_proof(message).to_bytes().to_vec();

    let did_label = compute_label(
        &claim_data.inv_id_0,
        &claim_data.inv_id_1,
        Some(&claim_data.inv_blind),
    );
    let claim_label = compute_label(&claim_data.iss_id, &claim_data.inv_id_1, None);

    // => Investor makes {did_label, claim_label, inv_id_0, iss_id, message, proof} public knowledge.
    let packaged_proof = Proof {
        did_label: did_label,
        inv_id_0: claim_data.inv_id_0,
        claim_label: claim_label,
        iss_id: claim_data.iss_id,
        proof: proof,
    };
    let proof_str = serde_json::to_string(&packaged_proof).unwrap();

    if args.verbose {
        println!("Proof Package: {:?}", proof_str);
    }

    if let Some(p) = args.proof {
        match std::fs::write(p, proof_str.as_bytes()) {
            Ok(_) => {
                println!("Successfully wrote the proof.");
            }
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(exitcode::DATAERR);
            }
        }
    }
}
