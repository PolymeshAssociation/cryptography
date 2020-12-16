#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include "c_example.h"

<<<<<<< HEAD
/**
 * Creates a CDD ID from a CDD claim.
 * (copy/pasted here from confidential-identity/ffi/examples/c_example.h
 *  for convenience.)
 *
 * SAFETY: Caller is responsible to make sure `cdd_claim` pointer is a valid
 *         `CddClaimData` object, created by this API.
 * Caller is responsible for deallocating memory after use.
 */
extern RistrettoPoint *compute_cdd_id_wrapper(const CddClaimData *cdd_claim);

=======
>>>>>>> add the rest of wrappers.
int main(void) {
    uint8_t investor_did[32] = {0x49, 0x99, 0x52, 0x43, 0x74, 0x8c, 0x4a, 0xe7,
        0x11, 0x8, 0x3c, 0x97, 0x56, 0x5f, 0xfd, 0xfd, 0x60, 0xdb, 0x1d, 0x8c, 0xc5,
        0x85, 0xf8, 0xa7, 0x1d, 0x99, 0x93, 0x9c, 0xbe, 0xab, 0xdd, 0x5};
    size_t investor_did_size = sizeof(investor_did);

<<<<<<< HEAD
    uint8_t investor_unique_id1[16] = {0x32, 0xc6, 0x26, 0xc, 0x2f, 0x7e, 0x4f, 0x70, 0xb4,
        0x91, 0xc4, 0x59, 0xec, 0x33, 0x62, 0x4b,};
    size_t investor_unique_id_size1 = sizeof(investor_unique_id1);

    uint8_t investor_unique_id2[16] = {0x5d, 0xa8, 0xdf, 0xe3, 0x37, 0xf7, 0x4a, 0x24,
        0x8f, 0x95, 0xde, 0x16, 0x16, 0xb6, 0xb, 0xe8,};
    size_t investor_unique_id_size2 = sizeof(investor_unique_id2);

    // We use a set of static seeds here. In a real application these must be generated
    // using a secure random number generator on the fly.
    uint8_t seed1[32] = {0x49, 0x99, 0x52, 0x43, 0x74, 0x8c, 0x4a, 0xe7,
        0x11, 0x8, 0x3c, 0x97, 0x56, 0x5f, 0xfd, 0xfd, 0x60, 0xdb, 0x1d, 0x8c, 0xc5,
        0x85, 0xf8, 0xa7, 0x1d, 0x99, 0x93, 0x9c, 0xbe, 0xab, 0xdd, 0x5};
    size_t seed_size1 = sizeof(seed1);

    uint8_t seed2[32] = {0x49, 0x99, 0x52, 0x43, 0x74, 0x8c, 0x4a, 0xe7,
        0x11, 0x8, 0x3c, 0x97, 0x56, 0x5f, 0xfd, 0xfd, 0x60, 0xdb, 0x1d, 0x8c, 0xc5,
        0x85, 0xf8, 0xa7, 0x1d, 0x99, 0x93, 0x9c, 0xbe, 0xab, 0xdd, 0x6};
    size_t seed_size2 = sizeof(seed2);

    uint8_t seed3[32] = {0x49, 0x99, 0x52, 0x43, 0x74, 0x8c, 0x4a, 0xe7,
        0x11, 0x8, 0x3c, 0x97, 0x56, 0x5f, 0xfd, 0xfd, 0x60, 0xdb, 0x1d, 0x8c, 0xc5,
        0x85, 0xf8, 0xa7, 0x1d, 0x99, 0x93, 0x9c, 0xbe, 0xab, 0xdd, 0x7};
    size_t seed_size3 = sizeof(seed3);

    // Set up on PUIS/Verifier side:
    Scalar *uuid1 = uuid_new(investor_unique_id1, investor_unique_id_size1);
    Scalar *uuid2 = uuid_new(investor_unique_id2, investor_unique_id_size2);
    Scalar *private_unique_identifiers[] = {uuid1, uuid2};
    size_t private_unique_identifiers_size = sizeof(private_unique_identifiers)/sizeof(private_unique_identifiers[0]);

    // Set up on Prover side:
    CddClaimData *cdd_claim = cdd_claim_data_new(investor_did, investor_did_size, investor_unique_id1, investor_unique_id_size1);
    RistrettoPoint *cdd_id = compute_cdd_id_wrapper(cdd_claim);

    // Prover makes the initial proof:
    InitialProverResults *initial_prover_results = generate_initial_proofs_wrapper(cdd_claim, seed1, seed_size1);

    // Verifier responds with a challenge:
    size_t min_set_size = 4;
    VerifierSetGeneratorResults *verifier_set_generator_results = generate_committed_set_and_challenge_wrapper(*private_unique_identifiers,
        private_unique_identifiers_size, &min_set_size, seed2, seed_size2);

    // Prover makes final proofs:
    FinalProverResults *final_prover_results = generate_challenge_response_wrapper(initial_prover_results->prover_secrets,
        verifier_set_generator_results->committed_uids, verifier_set_generator_results->committed_uids_size, verifier_set_generator_results->challenge, seed3, seed_size3);

    // Verifier/PUIS verifies the membership proof:
    bool verification_result = verify_proofs(initial_prover_results->proofs, final_prover_results->prover_final_response, verifier_set_generator_results->challenge, cdd_id,
        verifier_set_generator_results->verifier_secrets, final_prover_results->committed_uids);
    printf("UUID memebrship verification result: %d\n", verification_result);

    // Cleanup.
    // Investor's unique id is sensitive data, it's a good practice to zeroize it at cleanup.
    memset_s(investor_unique_id1, investor_unique_id_size1, 0, investor_unique_id_size1);
    memset_s(investor_unique_id2, investor_unique_id_size2, 0, investor_unique_id_size2);
    scalar_free(uuid1);
    scalar_free(uuid2);
    cdd_claim_data_free(cdd_claim);
    initial_prover_results_free(initial_prover_results);
    verifier_set_generator_results_free(verifier_set_generator_results);
=======
    uint8_t investor_unique_id[32] = {0x96, 0xd2, 0x2c, 0x25, 0x4a, 0xe1, 0xf4, 0x44,
        0xe1, 0x3c, 0x6d, 0x7f, 0xc6, 0xde, 0xc2, 0xca, 0xe2, 0xd1, 0x91, 0x7a, 0xf2, 0x94,
        0x81, 0x9, 0xf2, 0x74, 0x61, 0x28, 0xc4, 0xf, 0x6d, 0x1};
    size_t investor_unique_id_size = sizeof(investor_unique_id);

    uint8_t investor_unique_id2[32] = {0x96, 0xd2, 0x2c, 0x25, 0x4a, 0xe1, 0xf4, 0x44,
        0xe1, 0x3c, 0x6d, 0x7f, 0xc6, 0xde, 0xc2, 0xca, 0xe2, 0xd1, 0x91, 0x7a, 0xf2, 0x94,
        0x81, 0x9, 0xf2, 0x74, 0x61, 0x28, 0xc4, 0xf, 0x6d, 0x2};
    size_t investor_unique_id_size2 = sizeof(investor_unique_id2);

    uint8_t **unique_ids[] = {investor_unique_id, investor_unique_id2};

    // uint8_t scope_did[32] = {0x8a, 0xe1, 0x49, 0xda, 0xb0, 0x2a, 0xa9, 0x8f,
    //     0x7e, 0xd2, 0xe8, 0x2, 0xd4, 0x28, 0xee, 0xf8, 0xd1, 0x6b, 0xb7, 0xff,
    //     0x9d, 0x24, 0x72, 0xfd, 0xc9, 0x29, 0x44, 0x2b, 0x6, 0xf, 0xd, 0xa};
    // size_t scope_did_size = sizeof(scope_did);

    uint8_t seed[32] = {0x49, 0x99, 0x52, 0x43, 0x74, 0x8c, 0x4a, 0xe7,
        0x11, 0x8, 0x3c, 0x97, 0x56, 0x5f, 0xfd, 0xfd, 0x60, 0xdb, 0x1d, 0x8c, 0xc5,
        0x85, 0xf8, 0xa7, 0x1d, 0x99, 0x93, 0x9c, 0xbe, 0xab, 0xdd, 0x5};
    size_t seed_size = sizeof(seed);

    /*
    // Set up on Prover side:
    CddClaimData *cdd_claim = cdd_claim_data_new(investor_did, investor_did_size, investor_unique_id, investor_unique_id_size);
    ScopeClaimData *scope_claim = scope_claim_data_new(scope_did, scope_did_size, investor_unique_id, investor_unique_id_size);
    ScopeClaimProofData *prover = build_scope_claim_proof_data_wrapper(cdd_claim, scope_claim);

    // Create Proof.
    Signature *sig = generate_id_match_proof_wrapper(prover, message, message_size);
    RistrettoPoint *cdd_id = compute_cdd_id_wrapper(cdd_claim);
    RistrettoPoint *scope_id = compute_scope_id_wrapper(scope_claim);

    // Set up on the Verifier side:
    ProofPublicKey *pub_key = proof_public_key_new(cdd_id, investor_did, investor_did_size, scope_id, scope_did, scope_did_size);
    bool result = verify_id_match_proof_wrapper(pub_key, message, message_size, sig);
    printf("Verification result: %d\n", result);

    // Cleanup.
    // Investor's unique id is sensitive data, it's a good practice to zeroize it at cleanup.
    memset_s(investor_unique_id, investor_unique_id_size, 0, investor_unique_id_size);
    cdd_claim_data_free(cdd_claim);
    scope_claim_data_free(scope_claim);
    scope_claim_proof_data_free(prover);
    proof_public_key_free(pub_key);
    signature_free(sig);
    */
    // Set up on Prover side:
    CddClaimData *cdd_claim = cdd_claim_data_new(investor_did, investor_did_size, investor_unique_id, investor_unique_id_size);
    // Prover makes the initial proof:
    // InitialProverResults *generate_initial_proofs_wrapper(const CddClaimData *cdd_claim,
    //                                                   const uint8_t *seed,
    //                                                   size_t seed_size);
    InitialProverResults *initial_prover_results = generate_initial_proofs_wrapper(cdd_claim, seed, seed_size);
    // Verifier responds with a challenge:
    // VerifierSetGeneratorResults *generate_committed_set_and_challenge_wrapper(Scalar *private_unique_identifiers,
    //                                                                       size_t private_unique_identifiers_size,
    //                                                                       const size_t *min_set_size,
    //                                                                       const uint8_t *seed,
    //                                                                       size_t seed_size);
    // VerifierSetGeneratorResults *verifier_set_generator_results = generate_committed_set_and_challenge_wrapper();

    // Cleanup.
    // Investor's unique id is sensitive data, it's a good practice to zeroize it at cleanup.
    memset_s(investor_unique_id, investor_unique_id_size, 0, investor_unique_id_size);
    cdd_claim_data_free(cdd_claim);
    initial_prover_results_free(initial_prover_results);
>>>>>>> add the rest of wrappers.
}

