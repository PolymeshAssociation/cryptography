#![cfg_attr(not(feature = "std"), no_std)]

use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};
use sha3::Sha3_512;
use zeroize::Zeroize;

pub mod errors;

/// That `ensure` does not transform into a string representation like `failure::ensure` is doing.
#[allow(unused_macros)]
macro_rules! ensure {
    ($predicate:expr, $context_selector:expr) => {
        if !$predicate {
            return Err($context_selector.into());
        }
    };
}

/// Helper macro to assert that `predicate` is an `Error::from( $err)`.
#[allow(unused_macros)]
macro_rules! assert_err {
    ($predicate:expr, $err:expr) => {
        assert_eq!($predicate.expect_err("Error expected").kind(), &$err);
    };
}

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
pub type Balance = u32;
pub const BALANCE_RANGE: usize = 32;

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
#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq, Zeroize)]
#[zeroize(drop)]
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

impl From<AssetId> for Scalar {
    fn from(asset_id: AssetId) -> Scalar {
        Scalar::hash_from_bytes::<Sha3_512>(&(asset_id.id))
    }
}

pub mod asset_proofs;
pub mod claim_proofs;
pub mod mercat;
