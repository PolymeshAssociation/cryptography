//! The `asset_proofs` library contains API for generating
//! asset proofs and verifying them as part of the
//! MERCAT project.
//!
//! The `encryption_proofs` library contains API for generating
//! and verifying proofs of various properties of an encrypted
//! value proofs as part of the MERCAT
//! (Mediated, Encrypted, Reversible, SeCure Asset Transfers)
//! Project.
//!
//! For a full description of these proofs see section 5 of the
//! whitepaper.
//!
//! # Interactive Proofs
//! MERCAT's Sigma protocols are a 3 round interactive protocols
//! where the prover convinces the verifier that a statement is
//! true.
//!
//! There are three roles in this protocol: Prover, Dealer, and
//! Verifier. The role of the dealer is to generate the
//! challenge value. In the interactive protocol, Verifier and
//! Dealer are played by the same party. In the non-interactive
//! protocol, both the Prover and the Verifier act as dealer
//! using Fiat-Shamir huristic.
//!
//! The following shows the interaction between these roles.
//! ```text
//! Prover                         Dealer
//! - selects some random values
//!                       -->  (initial message)
//!                            - records the initial message
//!                            - deterministically calculates
//!                              a random challenge
//!           (challenge) <--
//! - generates a final response from the
//!   selected random values and
//!   the challenge
//!                       -->  (final response)
//! ```
//! Now given the `initial message` and the `final response` any
//! verifier can verify the prover's statement. Verifier uses the
//! transcript to generate the challenge:
//! ```text
//! Verifier                       Dealer
//! - receives the (initial message, final response)
//!                       -->  (initial message)
//!                            - records the initial message
//!                            - deterministically calculates
//!                              a random challenge
//!           (challenge) <--
//! - verifies the final response
//! ```
//! # Non-Interactive Proofs
//! The role of the Dealer can be eliminated if the challenge
//! could be generated deterministically but unpredictably from
//! the `initial message`. This technique is known as the
//! Fiat-Shamir huristic. We use Merlin transcripts as the
//! Dealer throughout this implementation.
//!
//! # Batched Proofs
//! Interactive proofs can be batched to create a single challenge
//! that would be used by all of them. In this scenario the Dealer
//! will collect all the initial messages from all the provers
//! and deterministically calculate a scalar challenge and send it
//! to all the provers. Verifier will also need to repeat this
//! process with the dealer to recalculate the challenge and verify
//! all the proofs.
//! ```text
//!                                Dealer
//! Prover_0
//! - selects some random values
//!                       --> (initial message 0)
//! Prover_1
//! - selects some random values
//!                       --> (initial message 1)
//! ...
//! Prover_N
//! - selects some random values
//!                       --> (initial message N)
//!                            - records all the initial messages
//!                            - deterministically calculates
//!                              a random challenge
//!           (challenge) <--
//! Prover_0
//! - generates a final response from the challenge
//!                       -->  (final response 0)
//! Prover_1
//! - generates a final response from the challenge
//!                       -->  (final response 1)
//! ...
//! Prover_N
//! - generates a final response from the challenge
//!                       -->  (final response N)
//! ```
//! On the verifier side:
//! ```text
//!                                Dealer
//! Verifier_0
//! - receives the
//!   (initial message 0, final response 0)
//! Verifier_1
//! - receives the
//!   (initial message 1, final response 1)
//! ...
//! Verifier_N
//! - receives the
//!   (initial message N, final response N)
//!                       -->  (initial message 0,
//!                             initial message 1,
//!                             ...,
//!                             initial message N)
//!                            - records the initial messages
//!                            - deterministically calculates
//!                              a random challenge
//!           (challenge) <--
//! Verifier_0
//! - verifies the final response 0
//! Verifier_1
//! - verifies the final response 1
//! ...
//! Verifier_N
//! - verifies the final response N
//! ```
//!
//! Here's a sample code:
//!
//! ```
//! use confidential_identity_core::asset_proofs::{
//!     encryption_proofs::{
//!         AssetProofProverAwaitingChallenge, AssetProofProver, AssetProofVerifier
//!     },
//!     correctness_proof::{
//!         CorrectnessInitialMessage, CorrectnessProverAwaitingChallenge, CorrectnessVerifier,
//!     },
//!     wellformedness_proof::{
//!         WellformednessProverAwaitingChallenge, WellformednessVerifier,
//!     },
//!     CommitmentWitness, ElgamalSecretKey,
//!     transcript::{TranscriptProtocol, UpdateTranscript},
//! };
//! use rand::{rngs::StdRng, SeedableRng};
//! use std::convert::TryFrom;
//! use zeroize::{Zeroizing};
//! use bulletproofs::PedersenGens;
//! use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
//! use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
//! use merlin::{Transcript, TranscriptRng};
//!
//! let gens = PedersenGens::default();
//! let mut rng = StdRng::from_seed([7u8; 32]);
//! let secret_value = 6u32;
//! let rand_blind = Scalar::random(&mut rng);
//! let w = CommitmentWitness::new(secret_value.into(), rand_blind);
//! let mut transcript = Transcript::new(b"batch_proof_label");
//!
//! let elg_secret = ElgamalSecretKey::new(Scalar::random(&mut rng));
//! let pub_key = elg_secret.get_public_key();
//! let cipher = pub_key.encrypt(&w);
//!
//! let prover_0 = CorrectnessProverAwaitingChallenge{pub_key, w: w.clone(), pc_gens: &gens};
//! let verifier_0 = CorrectnessVerifier{value: Scalar::from(secret_value), pub_key, cipher, pc_gens: &gens};
//!
//! let prover_1 = WellformednessProverAwaitingChallenge { pub_key: pub_key, w: Zeroizing::new(w) , pc_gens :&gens };
//! let verifier_1 = WellformednessVerifier { pub_key, cipher , pc_gens:&gens };
//!
//! let mut transcript_rng0 = prover_0.create_transcript_rng(&mut rng, &transcript);
//! let mut transcript_rng1 =
//!     prover_1.create_transcript_rng(&mut rng, &transcript);
//!
//! // Provers generate the initial messages
//! let (prover_0, initial_message0) =
//!     prover_0.generate_initial_message(&mut transcript_rng0);
//! initial_message0.update_transcript(&mut transcript).unwrap();
//!
//! let (prover_1, initial_message1) =
//!     prover_1.generate_initial_message(&mut transcript_rng1);
//! initial_message1.update_transcript(&mut transcript).unwrap();
//!
//! // Dealer calculates the challenge from the 2 initial messages
//! let challenge = transcript
//!     .scalar_challenge(b"batch_proof_challenge_label")
//!     .unwrap();
//!
//! // Provers generate the final responses
//! let final_response0 = prover_0.apply_challenge(&challenge);
//! let final_response1 = prover_1.apply_challenge(&challenge);
//!
//! // Verifiers verify the proofs
//! let result =
//!     verifier_0.verify(&challenge, &initial_message0, &final_response0);
//! assert!(result.is_ok());
//!
//! let result =
//!     verifier_1.verify(&challenge, &initial_message1, &final_response1);
//! assert!(result.is_ok());
//!
//! ```
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use codec::{Decode, Encode};
use scale_info::TypeInfo;

#[macro_use]
pub(crate) mod macros;

pub mod errors;

#[cfg(feature = "discrete_log")]
pub mod discrete_log;
pub mod elgamal_encryption;
pub use elgamal_encryption::{
    CipherText, CommitmentWitness, CompressedElgamalPublicKey, ElgamalPublicKey, ElgamalSecretKey,
};
pub mod const_time_elgamal_encryption;
pub use const_time_elgamal_encryption::CipherTextWithHint;

pub mod encryption_proofs;

pub mod ciphertext_refreshment_proof;
pub mod correctness_proof;
pub mod encrypting_same_value_proof;
pub mod membership_proof;
pub mod one_out_of_many_proof;
pub mod range_proof;
pub mod transcript;
pub mod wellformedness_proof;
pub use bulletproofs;

/// The balance value to keep confidential.
///
/// Since Elgamal decryption involves searching the entire
/// space of possible values, the decryption time doubles for
/// every extra bit of the value size. We have limited
/// the size of the balance to 32 bits, but even that is very costly.
/// To experiment with runtimes for different ranges use the
/// benchmarking tool in this repo.
///
/// Possible remedies are:
/// #0 limit the range even further since confidential values
///     in the context of Polymesh could be limited.
/// #1 use AVX2 instruction sets if available on the target
///    architectures. Our preliminary investigation using
///    `curve25519_dalek`'s AVX2 features doesn't show a
///    significant improvment.
/// #2 Given the fact that encrypted Elgamal values are mostly used
///    for zero-knowledge proof generations, it is very likely that
///    we won't need to decrypt the encrypted values very often.
///    We can recommend that applications use a different faster
///    encryption mechanism to store the confidentional values on disk.
#[cfg(not(feature = "balance_64"))]
pub type Balance = u32;
#[cfg(not(feature = "balance_64"))]
pub const BALANCE_RANGE: u32 = 32;
#[cfg(feature = "balance_64")]
pub type Balance = u64;
#[cfg(feature = "balance_64")]
pub const BALANCE_RANGE: u32 = 64;

/// Asset ID length.
/// Note that MERCAT's asset id corresponds to PolyMesh's asset ticker.
const ASSET_ID_LEN: usize = 12;

/// The AssetId to keep confidential.
/// Note that since `id` is effectively an array of 12 bytes and
/// the SHA3_512 hash of it is encrypted, the runtime for decrypting
/// it can take indefinitely long. In our application at the time of
/// decrypting an encrypted asset id we have a guess as what the
/// asset id should be, use `ElgamalSecretKey`'s `verify()`
/// to verify that the encrypted value is the same as the hinted value.
#[derive(Default, Debug, Clone, Copy, PartialEq, Encode, Decode, TypeInfo)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AssetId {
    pub id: [u8; ASSET_ID_LEN],
}

impl From<u32> for AssetId {
    fn from(id: u32) -> AssetId {
        let mut array = [0u8; 12];
        array[0..4].copy_from_slice(&id.to_le_bytes());
        AssetId { id: array }
    }
}

use curve25519_dalek::scalar::Scalar;
impl From<AssetId> for Scalar {
    fn from(asset_id: AssetId) -> Scalar {
        use sha3::Sha3_512;
        Scalar::hash_from_bytes::<Sha3_512>(&(asset_id.id))
    }
}

pub fn asset_id_from_ticker(ticker: &str) -> Result<AssetId, errors::Error> {
    ensure!(
        ticker.len() <= ASSET_ID_LEN,
        errors::ErrorKind::TickerIdLengthError {
            want: ASSET_ID_LEN,
            got: ticker.len(),
        }
    );

    let mut asset_id = [0u8; ASSET_ID_LEN];
    let ticker = ticker.as_bytes();
    asset_id[..ticker.len()].copy_from_slice(ticker);
    Ok(AssetId { id: asset_id })
}
