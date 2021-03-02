#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include "../confidential_identity.h"

int main(void) {
    uint8_t investor_did[32] = {0x49, 0x99, 0x52, 0x43, 0x74, 0x8c, 0x4a, 0xe7,
        0x11, 0x8, 0x3c, 0x97, 0x56, 0x5f, 0xfd, 0xfd, 0x60, 0xdb, 0x1d, 0x8c, 0xc5,
        0x85, 0xf8, 0xa7, 0x1d, 0x99, 0x93, 0x9c, 0xbe, 0xab, 0xdd, 0x5};
    size_t investor_did_size = sizeof(investor_did);

    uint8_t investor_unique_id[32] = {0x96, 0xd2, 0x2c, 0x25, 0x4a, 0xe1, 0xf4, 0x44,
        0xe1, 0x3c, 0x6d, 0x7f, 0xc6, 0xde, 0xc2, 0xca, 0xe2, 0xd1, 0x91, 0x7a, 0xf2, 0x94,
        0x81, 0x9, 0xf2, 0x74, 0x61, 0x28, 0xc4, 0xf, 0x6d, 0x1};
    size_t investor_unique_id_size = sizeof(investor_unique_id);

    uint8_t scope_did[32] = {0x8a, 0xe1, 0x49, 0xda, 0xb0, 0x2a, 0xa9, 0x8f,
        0x7e, 0xd2, 0xe8, 0x2, 0xd4, 0x28, 0xee, 0xf8, 0xd1, 0x6b, 0xb7, 0xff,
        0x9d, 0x24, 0x72, 0xfd, 0xc9, 0x29, 0x44, 0x2b, 0x6, 0xf, 0xd, 0xa};
    size_t scope_did_size = sizeof(scope_did);


    // Set up on claim data side:
    CddClaimData *cdd_claim = cdd_claim_data_new(investor_did, investor_did_size, investor_unique_id, investor_unique_id_size);
    ScopeClaimData *scope_claim = scope_claim_data_new(scope_did, scope_did_size, investor_unique_id, investor_unique_id_size);

    // Create Proof.
    CddId *cdd_id = create_cdd_id(cdd_claim);
    ScopeClaimProof *proof = create_scope_claim_proof(cdd_claim, scope_claim);

    // Set up on the Verifier side:
    bool result = verify_scope_claim_proof(proof, investor_did, investor_unique_id_size, cdd_id);
    printf("Verification result: %d\n", result);

    // Cleanup.
    // Investor's unique id is sensitive data, it's a good practice to zeroize it at cleanup.
    memset(investor_unique_id, 0, investor_unique_id_size);
    cdd_claim_data_free(cdd_claim);
    scope_claim_data_free(scope_claim);
    scope_claim_proof_free(proof);
}
