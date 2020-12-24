#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include "c_example.h"

int main(void) {
    uint8_t investor_did[32] = {0x49, 0x99, 0x52, 0x43, 0x74, 0x8c, 0x4a, 0xe7,
        0x11, 0x8, 0x3c, 0x97, 0x56, 0x5f, 0xfd, 0xfd, 0x60, 0xdb, 0x1d, 0x8c, 0xc5,
        0x85, 0xf8, 0xa7, 0x1d, 0x99, 0x93, 0x9c, 0xbe, 0xab, 0xdd, 0x5};
    size_t investor_did_size = sizeof(investor_did);

    uint8_t investor_unique_id1[16] = {0x96, 0xd2, 0x2c, 0x25, 0x4a, 0xe1, 0xf4, 0x44,
        0xe1, 0x3c, 0x6d, 0x7f, 0xc6, 0xde, 0xc2, 0xca,}; //0xe2, 0xd1, 0x91, 0x7a, 0xf2, 0x94,
        // 0x81, 0x9, 0xf2, 0x74, 0x61, 0x28, 0xc4, 0xf, 0x6d, 0x1};
    size_t investor_unique_id_size1 = sizeof(investor_unique_id1);

    uint8_t investor_unique_id2[16] = {0x96, 0xd2, 0x2c, 0x25, 0x4a, 0xe1, 0xf4, 0x44,
        0xe1, 0x3c, 0x6d, 0x7f, 0xc6, 0xde, 0xc2, 0xcb,};// 0xe2, 0xd1, 0x91, 0x7a, 0xf2, 0x94,
        // 0x81, 0x9, 0xf2, 0x74, 0x61, 0x28, 0xc4, 0xf, 0x6d, 0x2};
    size_t investor_unique_id_size2 = sizeof(investor_unique_id2);

    uint8_t seed[32] = {0x49, 0x99, 0x52, 0x43, 0x74, 0x8c, 0x4a, 0xe7,
        0x11, 0x8, 0x3c, 0x97, 0x56, 0x5f, 0xfd, 0xfd, 0x60, 0xdb, 0x1d, 0x8c, 0xc5,
        0x85, 0xf8, 0xa7, 0x1d, 0x99, 0x93, 0x9c, 0xbe, 0xab, 0xdd, 0x5};
    size_t seed_size = sizeof(seed);

    // Set up on PUIS/Verifier side:
    Scalar *uuid1 = uuid_new(investor_unique_id1, investor_unique_id_size1);
    Scalar *uuid2 = uuid_new(investor_unique_id2, investor_unique_id_size2);
    Scalar *private_unique_identifiers[] = {uuid1, uuid2};
    size_t private_unique_identifiers_size = sizeof(private_unique_identifiers)/sizeof(private_unique_identifiers[0]);
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
    CddClaimData *cdd_claim = cdd_claim_data_new(investor_did, investor_did_size, uuid1);//, investor_unique_id_size1);
    // let claim = CddClaimData {
    //         investor_unique_id: private_uid_set[0],
    //         investor_did: Scalar::random(&mut rng),
    //     };
    RistrettoPoint *cdd_id = compute_cdd_id_wrapper(cdd_claim);
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
    size_t min_set_size = 4;
    VerifierSetGeneratorResults *verifier_set_generator_results = generate_committed_set_and_challenge_wrapper(*private_unique_identifiers,
        private_unique_identifiers_size, &min_set_size, seed, seed_size);

    // Prover makes final proofs:
    // FinalProverResults *generate_challenge_response_wrapper(ProverSecrets *secrets,
    //                                                     RistrettoPoint *committed_uids,
    //                                                     size_t committed_uids_size,
    //                                                     Scalar *challenge,
    //                                                     const uint8_t *seed,
    //                                                     size_t seed_size);
    FinalProverResults *final_prover_results = generate_challenge_response_wrapper(initial_prover_results->prover_secrets,
        verifier_set_generator_results->committed_uids, verifier_set_generator_results->committed_uids_size, verifier_set_generator_results->challenge, seed, seed_size);

    // Verifier/PUIS verifies the membership proof:
    // bool verify_proofs(const Proofs *initial_message,
    //                const ProverFinalResponse *final_response,
    //                Scalar *challenge,
    //                RistrettoPoint *cdd_id,
    //                const VerifierSecrets *verifier_secrets,
    //                const CommittedUids *re_committed_uids);
    bool verification_result = verify_proofs(initial_prover_results->proofs, final_prover_results->prover_final_response, verifier_set_generator_results->challenge, cdd_id,
        verifier_set_generator_results->verifier_secrets, final_prover_results->committed_uids);
    printf("UUID memebrship verification result: %d\n", verification_result);

    // Cleanup.
    // Investor's unique id is sensitive data, it's a good practice to zeroize it at cleanup.
    memset_s(investor_unique_id1, investor_unique_id_size1, 0, investor_unique_id_size1);
    memset_s(investor_unique_id2, investor_unique_id_size2, 0, investor_unique_id_size2);
    cdd_claim_data_free(cdd_claim);
    initial_prover_results_free(initial_prover_results);
    verifier_set_generator_results_free(verifier_set_generator_results);
}

