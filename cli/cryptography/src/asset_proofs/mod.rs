//! The `asset_proofs` library contains API for generating
//! asset proofs and verifying them as part of the
//! MERCAT project.

#[macro_use]
pub(crate) mod macros;

pub mod errors;

/// Helper macro to assert that `predicate` is an `Error::from( $err)`.
#[allow(unused_macros)]
macro_rules! assert_err {
    ($predicate:expr, $err:expr) => {
        assert_eq!(
            $predicate
                .expect_err("Error expected")
                .downcast::<$crate::asset_proofs::errors::AssetProofError>()
                .expect("It is not an AssetProofError"),
            $err
        );
    };
}

mod elgamal_encryption;
pub use elgamal_encryption::{CipherText, CommitmentWitness, ElgamalPublicKey, ElgamalSecretKey};

pub mod ciphertext_refreshment_proof;
pub mod correctness_proof;
pub mod encrypting_same_value_proof;
pub mod encryption_proofs;
pub mod one_out_of_many_proof;
pub mod range_proof;
pub mod transcript;
pub mod wellformedness_proof;
