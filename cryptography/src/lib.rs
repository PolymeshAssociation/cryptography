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

pub type Balance = u32;
pub const BALANCE_RANGE: usize = 32;

/// Asset ID type.
/// Note that MERCAT's asset id corresponds to PolyMesh's asset ticker.
const ASSET_ID_LEN: usize = 12;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

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

pub mod asset_proofs;
pub mod claim_proofs;
pub mod mercat;
