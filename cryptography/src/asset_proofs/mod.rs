//! The `asset_proofs` library contains API for generating
//! asset proofs and verifying them as part of the
//! MERCAT project.

#[macro_use]
pub(crate) mod macros;

mod elgamal_encryption;
pub use elgamal_encryption::{CipherText, CommitmentWitness, ElgamalPublicKey, ElgamalSecretKey};

pub mod ciphertext_refreshment_proof;
pub mod correctness_proof;
pub mod encrypting_same_value_proof;
pub mod encryption_proofs;
pub mod range_proof;
pub mod transcript;
pub mod wellformedness_proof;
