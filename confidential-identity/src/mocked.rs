use crate::uuid;

use sp_io::hashing::blake2_128;

/// Create an mocked version of InvestorUid using a DID as input.
///
/// That InvestorUid is just a hash of the given DID, where some bits are updated to be compliant
/// with UUID v4 spec.
pub fn make_investor_uid(did: &[u8]) -> [u8; 16] {
    let mut investor_uid = blake2_128(did);
    uuid::set_variant(&mut investor_uid, uuid::Variant::RFC4122);
    uuid::set_version(&mut investor_uid, uuid::Version::V4);

    investor_uid
}
