#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    pial_ok = 0,
    pial_initial_message_generation_error,
    pial_zkp_verification_error,
    pial_membership_proof_error,
    pial_cdd_id_mismatch_error,
} pial_error_t;

#ifdef __cplusplus
}
#endif