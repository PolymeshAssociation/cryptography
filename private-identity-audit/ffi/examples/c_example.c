#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include "private_identity_audit.h"
#include "confidential_identity.h"

/**
 * Creates a CDD ID from a CDD claim.
 * (copy/pasted here from confidential-identity/ffi/include/confidential_identity.h
 *  for convenience.)
 *
 * SAFETY: Caller is responsible to make sure `cdd_claim` pointer is a valid
 *         `CddClaimData` object, created by this API.
 * Caller is responsible for deallocating memory after use.
 */
extern CddId *compute_cdd_id_wrapper(const CddClaimData *cdd_claim);

int main(void) {
    uint8_t investor_did[32] = {0x49, 0x99, 0x52, 0x43, 0x74, 0x8c, 0x4a, 0xe7,
        0x11, 0x8, 0x3c, 0x97, 0x56, 0x5f, 0xfd, 0xfd, 0x60, 0xdb, 0x1d, 0x8c, 0xc5,
        0x85, 0xf8, 0xa7, 0x1d, 0x99, 0x93, 0x9c, 0xbe, 0xab, 0xdd, 0x5};
    size_t investor_did_size = sizeof(investor_did);

    uint8_t investor_unique_ids_2d[2][16] = {
      {0x32, 0xc6, 0x26, 0xc, 0x2f, 0x7e, 0x4f, 0x70, 0xb4, 0x91, 0xc4, 0x59, 0xec, 0x33, 0x62, 0x4b},
      {0x5d, 0xa8, 0xdf, 0xe3, 0x37, 0xf7, 0x4a, 0x24, 0x8f, 0x95, 0xde, 0x16, 0x16, 0xb6, 0xb, 0xe8}
    };
    size_t investor_unique_id_size = 16;

    uint8_t investor_unique_ids[32];
    for(int i=0; i<2; i++) {
      for(int j=0;j<investor_unique_id_size;j++) {
        investor_unique_ids[i * investor_unique_id_size + j] = investor_unique_ids_2d[i][j];
      }
    }
    size_t investor_unique_ids_size = sizeof(investor_unique_ids);

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

    MatrixEncoding private_unique_identifiers = { .ptr = investor_unique_ids, .rows = 2, .cols = 16 };

    // Set up on Prover side:
    CddClaimData *cdd_claim = cdd_claim_data_new(investor_did, investor_did_size, investor_unique_ids_2d[0], investor_unique_id_size);
    CddId *cdd_id = create_cdd_id(cdd_claim);

    // Verifier generates the set:
    size_t min_set_size = 4;
    VerifierSetGeneratorResults *verifier_set_generator_results = generate_committed_set(private_unique_identifiers, &min_set_size, seed2, seed_size2);

    // Prover creates the proofs:
    ArrCddClaimData cdd_claims = { .ptr = cdd_claim, .n = 1 };
    ProverResults *prover_results = generate_proofs(cdd_claims, verifier_set_generator_results->committed_uids, seed1, seed_size1);

    // Verifier verifies the membership proof:
    ArrCddId cdd_ids = { .ptr = cdd_id, .n = 1 };
    bool verification_result = verify_proofs(prover_results->prover_initial_messages, prover_results->prover_final_responses, cdd_ids,
        verifier_set_generator_results->verifier_secrets, prover_results->committed_uids);
    printf("UUID memebrship verification result: %d\n", verification_result);

    // Cleanup.
    // Investor's unique id is sensitive data, it's a good practice to zeroize it at cleanup.
    memset(investor_unique_ids_2d, 0, sizeof(investor_unique_ids_2d));
    memset(investor_unique_ids, 0, investor_unique_ids_size);

    prover_results_free(prover_results);
    //cdd_claim_data_free(cdd_claim);
    //verifier_set_generator_results_free(verifier_set_generator_results);
}

