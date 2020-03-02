/// [PA] todo: add documentation.

use curve25519_dalek::{
    scalar::Scalar,
    ristretto::RistrettoPoint
};
use sha3::Sha3_512;
use schnorrkel::{Keypair, signing_context, Signature, PublicKey};
use crate::pedersen_commitments::{PedersenGenerators};

/// Signing context.
const SIGNING_CTX: &[u8] = b"PolymathClaimProofs";

#[derive(Debug, Copy, Clone)]
pub struct Data {
    a0: [u8; 32],
    a1: [u8; 32],
    a2: [u8; 32],
    b0: [u8; 32],
}

impl Data {
    pub fn new(a0: [u8; 32], a1: [u8; 32], a2: [u8; 32], b0: [u8; 32]) -> Self {
        Data {
            a0,
            a1,
            a2,
            b0,
        }
    }
}
/// An Schnorrkel/Ristretto x25519 ("sr25519") public key.
/// This is the construct that the blockchain validator will use.
// #[cfg_attr(feature = "full_crypto", derive(Hash))]
// #[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Encode, Decode, Default, PassByInner)]
// pub struct PublicKey(pub [u8; 32]);
pub struct ProofPublicKey {
    pub_key: PublicKey,
}

// An Schnorrkel/Ristretto x25519 ("sr25519") key pair.
// pub struct ProofPair(Keypair);
pub struct ProofPair {
    keypair: Keypair,
}

/*
/// compute_did_label( KYC_id, investor_unique_id): Output(did_label
/// A Pedersen commitment with respect to the fixed generators and serialized))
///
/// DID_LABEL = p_hash(INVESTOR_DID, INVESTOR_UNIQUE_ID, RANDOM_BLIND)
/// CLAIM_LABEL = p_hash(TARGET_ASSET_ISSUER, INVESTOR_UNIQUE_ID, SHA(TARGET_ASSET_ISSUER, INVESTOR_UNIQUE_ID))
*/
pub fn compute_label(id:[u8; 32], unique_id: [u8; 32], blind: Option<[u8; 32]>) -> RistrettoPoint {
    let third_term: Vec<u8> = match blind {
        Some(t) => t.to_vec(),
        None => {
            let mut t = Vec::with_capacity(id.len() + unique_id.len());
            t.extend_from_slice(&id.to_vec());
            t.extend_from_slice(&unique_id.to_vec());
            t
        },
    };

    let pg = PedersenGenerators::default();
    pg.commit(&[
        Scalar::hash_from_bytes::<Sha3_512>(&id),
        Scalar::hash_from_bytes::<Sha3_512>(&unique_id),
        Scalar::hash_from_bytes::<Sha3_512>(&third_term)])
}

impl ProofPair {
    pub fn new(d: Data) -> Self {
        let mut second_term = Vec::with_capacity(d.b0.len() + d.a1.len());
        second_term.extend_from_slice(&d.b0.to_vec());
        second_term.extend_from_slice(&d.a1.to_vec());

        let secret_key_scalar = Scalar::hash_from_bytes::<Sha3_512>(&d.a2) -
            Scalar::hash_from_bytes::<Sha3_512>(&second_term);
        // [PA] todo: see what's the best way to generate the nonce.
        let mut exported_private_key = Vec::with_capacity(64);
        exported_private_key.extend_from_slice(&secret_key_scalar.to_bytes());
        exported_private_key.extend_from_slice(&[1u8; 32]);
        // let mut secret: schnorrkel::SecretKey = {.key = secret_key_scalar, .nonce = [0u8; 32]};
        let secret = schnorrkel::SecretKey::from_bytes(&exported_private_key)
            .expect("key is always the correct size; qed");
        let public_key = secret.to_public();

        ProofPair{
            keypair: schnorrkel::Keypair { public: public_key, secret: secret },
        }
    }

    // [PA] todo: see if signing changes the nonce, and do we have to export the nonce after signing.
    // generate_id_match_proof(DID_LABEL, CLAIM_LABEL): Outputs( Proof material . //a serialized byte array, which is basically an sr25519 signature)
    pub fn generate_id_match_proof(&self, message: &[u8]) -> Signature {
        let context = signing_context(SIGNING_CTX);
        self.keypair.sign(context.bytes(message)).into()
    }
}

impl ProofPublicKey {
    pub fn new(did_label: RistrettoPoint, investor_public_value: [u8; 32], claim_label: RistrettoPoint, issuer_public_value: [u8; 32]) -> Self {
        let pg = PedersenGenerators::default();
        let did_label_prime = pg.label_prime(did_label, Scalar::hash_from_bytes::<Sha3_512>(&investor_public_value));
        let claim_label_prime = pg.label_prime(claim_label, Scalar::hash_from_bytes::<Sha3_512>(&issuer_public_value));

        let pub_key = PublicKey::from_point(did_label_prime - claim_label_prime);
        ProofPublicKey {
            pub_key: pub_key,
        }
    }

    pub fn verify_id_match_proof(&self, message: &[u8], sig: &Signature) -> bool {
        self.pub_key.verify_simple(SIGNING_CTX, message, sig).is_ok()
    }
}

// ------------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // [PA] todo: test the failure case.
    #[test]
    fn match_pub_key_both_sides() {
        // Note that generally testing with random numbers isn't desirable, since
        // when/if it fails in production, and you don't have access to the trace
        // it is not helpful.
        let a0: [u8; 32] = rand::random();
        let a1: [u8; 32] = rand::random();
        let a2: [u8; 32] = rand::random();
        let b0: [u8; 32] = rand::random();

        // Commiter side.
        let d = Data::new(a0, a1, a2, b0);
        let pair = ProofPair::new(d);
        let did_label = compute_label(a0, a1, Some(a2));
        let claim_label = compute_label(b0, a1, None);

        // Verifier side.
        let verifier_pub = ProofPublicKey::new(did_label, a0, claim_label, b0);

        assert_eq!(pair.keypair.public, verifier_pub.pub_key);
    }

    #[test]
    fn verify_proofs() {
        let message = &b"I didn't claim anyrhing!".to_vec();

        // Investor side.
        let a0: [u8; 32] = rand::random();
        let a1: [u8; 32] = rand::random();
        let a2: [u8; 32] = rand::random();
        let b0: [u8; 32] = rand::random();
        let d = Data::new(a0, a1, a2, b0);
        let pair = ProofPair::new(d);
        let sig = pair.generate_id_match_proof(message);

        let did_label = compute_label(a0, a1, Some(a2));
        let claim_label = compute_label(b0, a1, None);

        // Verifier side.
        // Verifier receives the did_label, claim_label, a message,
        // and a proof for it. And it verifies the proof on the message
        // given the labels.
        let verifier_pub = ProofPublicKey::new(did_label, a0, claim_label, b0);
        let result = verifier_pub.verify_id_match_proof(message, &sig);

        assert!(result);
    }

}
