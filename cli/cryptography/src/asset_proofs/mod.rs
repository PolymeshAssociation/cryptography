//! The `asset_proofs` library contains API for generating
//! asset proofs and verifying them as part of the
//! MERCAT project.

#[macro_use]
pub(crate) mod macros;

mod errors;
pub use errors::AssetProofError;

mod elgamal_encryption;
pub use elgamal_encryption::{CipherText, CommitmentWitness, ElgamalPublicKey, ElgamalSecretKey};

pub mod correctness_proof;
pub mod encryption_proofs;
pub mod range_proof;
pub mod transcript;
