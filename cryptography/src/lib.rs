pub mod errors;

/// That `ensure` does not transform into a string representation like `failure::ensure` is doing.
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
        assert_eq!(
            $predicate
                .expect_err("Error expected")
                .downcast::<$crate::errors::AssetProofError>()
                .expect("It is not an AssetProofError"),
            $err
        );
    };
}

pub mod asset_proofs;
pub mod claim_proofs;
