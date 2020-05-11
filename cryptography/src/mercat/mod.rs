//! The `mercat` library contains API for initiating
//! verifying, and finalizing confidential transfers
//! as part of the MERCAT project.
pub mod conf_tx;
pub mod errors;
pub mod lib;

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
