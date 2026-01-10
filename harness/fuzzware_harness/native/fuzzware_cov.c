/* Fuzzware Coverage Tracking Implementation for Unicorn 2.x
 *
 * Implements AFL-compatible edge coverage using UC_HOOK_BLOCK.
 *
 * NOTE: Originally used UC_HOOK_EDGE_GENERATED, but that only fires when
 * NEW edges are JIT compiled. In persistent mode, after the first run,
 * all blocks are cached and no new edges are generated - breaking coverage.
 *
 * UC_HOOK_BLOCK fires on every block execution, enabling persistent mode.
 */

#include "fuzzware_cov.h"
#include <string.h>
#include <stdio.h>

/* Coverage state - global for performance */
static uint8_t *cov_bitmap = NULL;
static uint32_t cov_bitmap_size = 0;
static uint32_t cov_prev_loc = 0;
static uc_hook cov_hook_handle = 0;

/* Hash function for block addresses - same as AFL */
static inline uint32_t hash_addr(uint64_t addr) {
    /* Simple hash: use lower bits XORed with upper bits */
    return (uint32_t)((addr ^ (addr >> 16)) & 0xFFFF);
}

/*
 * Block execution callback - called when each block is executed.
 * This is the core of AFL-style coverage tracking.
 *
 * Using UC_HOOK_BLOCK instead of UC_HOOK_EDGE_GENERATED because
 * the latter only fires when new edges are JIT compiled, which
 * doesn't work in persistent mode where blocks are cached.
 */
static void hook_block(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    if (!cov_bitmap) {
        return;
    }

    /* Calculate current location hash */
    uint32_t cur_loc = hash_addr(address);

    /* Update coverage bitmap: bitmap[cur_loc ^ prev_loc]++ */
    uint32_t index = (cur_loc ^ cov_prev_loc) & (cov_bitmap_size - 1);
    cov_bitmap[index]++;

    /* Update previous location for next edge */
    cov_prev_loc = cur_loc >> 1;
}

uc_err uc_fuzzer_init_cov(uc_engine *uc, uint8_t *bitmap, uint32_t bitmap_size) {
    uc_err err;

    if (!uc || !bitmap || bitmap_size == 0) {
        return UC_ERR_ARG;
    }

    /* Verify bitmap_size is a power of 2 */
    if ((bitmap_size & (bitmap_size - 1)) != 0) {
        fprintf(stderr, "[COV] Warning: bitmap_size %u is not a power of 2\n", bitmap_size);
    }

    /* Store bitmap reference */
    cov_bitmap = bitmap;
    cov_bitmap_size = bitmap_size;
    cov_prev_loc = 0;

    /* Clear bitmap */
    memset(bitmap, 0, bitmap_size);

    /* Register block execution hook for coverage tracking
     * Using UC_HOOK_BLOCK which fires on every block execution,
     * unlike UC_HOOK_EDGE_GENERATED which only fires on first JIT compilation */
    err = uc_hook_add(uc, &cov_hook_handle, UC_HOOK_BLOCK,
                      (void *)hook_block, NULL, 1, 0);

    if (err != UC_ERR_OK) {
        fprintf(stderr, "[COV] Failed to add block hook: %s\n",
                uc_strerror(err));
        cov_bitmap = NULL;
        cov_bitmap_size = 0;
        return err;
    }

    #ifdef DEBUG
    printf("[COV] Coverage tracking initialized with %u byte bitmap\n", bitmap_size);
    #endif

    return UC_ERR_OK;
}

uc_err uc_fuzzer_reset_cov(uc_engine *uc, int full_reset) {
    (void)uc;  /* Unused, but kept for API compatibility */

    if (full_reset) {
        /* Full reset: clear bitmap and reset prev_loc */
        if (cov_bitmap && cov_bitmap_size > 0) {
            memset(cov_bitmap, 0, cov_bitmap_size);
        }
        cov_prev_loc = 0;

        #ifdef DEBUG
        printf("[COV] Full coverage reset\n");
        #endif
    } else {
        /* Partial reset: only reset prev_loc */
        cov_prev_loc = 0;

        #ifdef DEBUG
        printf("[COV] Partial coverage reset (prev_loc only)\n");
        #endif
    }

    return UC_ERR_OK;
}

uc_err uc_fuzzer_cleanup_cov(uc_engine *uc) {
    uc_err err = UC_ERR_OK;

    if (cov_hook_handle && uc) {
        err = uc_hook_del(uc, cov_hook_handle);
        if (err != UC_ERR_OK) {
            fprintf(stderr, "[COV] Failed to remove coverage hook: %s\n",
                    uc_strerror(err));
        }
        cov_hook_handle = 0;
    }

    cov_bitmap = NULL;
    cov_bitmap_size = 0;
    cov_prev_loc = 0;

    return err;
}
