/* Fuzzware Coverage Tracking API for Unicorn 2.x
 *
 * This module provides AFL-compatible edge coverage tracking using
 * Unicorn 2.x's UC_HOOK_EDGE_GENERATED hook.
 *
 * These functions replace the custom uc_fuzzer_init_cov/uc_fuzzer_reset_cov
 * APIs that were present in the original fuzzware-unicorn fork.
 */

#ifndef FUZZWARE_COV_H
#define FUZZWARE_COV_H

#include <unicorn/unicorn.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Initialize coverage tracking for the given Unicorn engine.
 *
 * @uc: Unicorn engine handle
 * @bitmap: Pointer to the AFL coverage bitmap (typically 64KB)
 * @bitmap_size: Size of the bitmap (typically MAP_SIZE = 65536)
 *
 * @return: UC_ERR_OK on success, error code on failure
 *
 * This function registers an edge generation hook that updates the
 * coverage bitmap in AFL-compatible format.
 */
uc_err uc_fuzzer_init_cov(uc_engine *uc, uint8_t *bitmap, uint32_t bitmap_size);

/*
 * Reset coverage tracking state.
 *
 * @uc: Unicorn engine handle
 * @full_reset: If non-zero, fully reset the bitmap and previous location.
 *              If zero, only reset the previous location (partial reset).
 *
 * @return: UC_ERR_OK on success, error code on failure
 *
 * Full reset (full_reset=1): Clears the bitmap and resets prev_loc.
 *   Used at the start of a new fuzzing campaign or snapshot.
 *
 * Partial reset (full_reset=0): Only resets prev_loc.
 *   Used at the start of each fuzzing iteration within a fork server loop.
 */
uc_err uc_fuzzer_reset_cov(uc_engine *uc, int full_reset);

/*
 * Remove coverage tracking hooks.
 *
 * @uc: Unicorn engine handle
 *
 * @return: UC_ERR_OK on success, error code on failure
 */
uc_err uc_fuzzer_cleanup_cov(uc_engine *uc);

#ifdef __cplusplus
}
#endif

#endif /* FUZZWARE_COV_H */
