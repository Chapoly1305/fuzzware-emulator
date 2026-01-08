/* Unicorn 2.x Compatibility Layer for Fuzzware
 *
 * This header provides compatibility shims for APIs that existed in
 * fuzzware-unicorn (Unicorn 1.x fork) but are not present in Unicorn 2.x.
 */

#ifndef UNICORN2_COMPAT_H
#define UNICORN2_COMPAT_H

#include <unicorn/unicorn.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* CONTROL register bit definitions for Cortex-M */
#define CONTROL_SPSEL_BIT   (1 << 1)  /* Stack pointer select: 0=MSP, 1=PSP */
#define CONTROL_NPRIV_BIT   (1 << 0)  /* Thread mode privilege: 0=privileged, 1=unprivileged */

/*
 * Get the "other" stack pointer value.
 * In Cortex-M, if currently using MSP, this returns PSP and vice versa.
 *
 * IMPORTANT: In Handler mode, MSP is ALWAYS used regardless of CONTROL.SPSEL.
 * CONTROL.SPSEL only affects Thread mode.
 * So in Handler mode, the "other" SP is always PSP.
 */
static inline uc_err uc_get_other_sp(uc_engine *uc, uint32_t *value) {
    uint32_t xpsr;
    uc_err err = uc_reg_read(uc, UC_ARM_REG_XPSR, &xpsr);
    if (err != UC_ERR_OK) return err;

    /* Check if in Handler mode (XPSR[8:0] != 0) */
    if (xpsr & 0x1FF) {
        /* In Handler mode, we're always using MSP, so "other" is PSP */
        return uc_reg_read(uc, UC_ARM_REG_PSP, value);
    }

    /* In Thread mode, use CONTROL.SPSEL to determine current SP */
    uint32_t control;
    err = uc_reg_read(uc, UC_ARM_REG_CONTROL, &control);
    if (err != UC_ERR_OK) return err;

    if (control & CONTROL_SPSEL_BIT) {
        /* Currently using PSP, return MSP */
        return uc_reg_read(uc, UC_ARM_REG_MSP, value);
    } else {
        /* Currently using MSP, return PSP */
        return uc_reg_read(uc, UC_ARM_REG_PSP, value);
    }
}

/*
 * Set the "other" stack pointer value.
 */
static inline uc_err uc_set_other_sp(uc_engine *uc, uint32_t value) {
    uint32_t control;
    uc_err err = uc_reg_read(uc, UC_ARM_REG_CONTROL, &control);
    if (err != UC_ERR_OK) return err;

    if (control & CONTROL_SPSEL_BIT) {
        /* Currently using PSP, set MSP */
        return uc_reg_write(uc, UC_ARM_REG_MSP, &value);
    } else {
        /* Currently using MSP, set PSP */
        return uc_reg_write(uc, UC_ARM_REG_PSP, &value);
    }
}

/*
 * Check if currently using PSP (Process Stack Pointer).
 * Returns 1 if PSP is active, 0 if MSP is active.
 *
 * IMPORTANT: In Handler mode, MSP is ALWAYS used regardless of CONTROL.SPSEL.
 */
static inline uint32_t uc_get_curr_sp_mode_is_psp(uc_engine *uc) {
    uint32_t xpsr = 0;
    uc_reg_read(uc, UC_ARM_REG_XPSR, &xpsr);

    /* In Handler mode (XPSR[8:0] != 0), always using MSP */
    if (xpsr & 0x1FF) {
        return 0;
    }

    /* In Thread mode, check CONTROL.SPSEL */
    uint32_t control = 0;
    uc_reg_read(uc, UC_ARM_REG_CONTROL, &control);
    return (control & CONTROL_SPSEL_BIT) ? 1 : 0;
}

/*
 * Set the SPSEL bit in CONTROL register.
 * value: 0 = use MSP, 1 = use PSP
 */
static inline uc_err uc_set_spsel(uc_engine *uc, uint32_t value) {
    uint32_t control;
    uc_err err = uc_reg_read(uc, UC_ARM_REG_CONTROL, &control);
    if (err != UC_ERR_OK) return err;

    if (value) {
        control |= CONTROL_SPSEL_BIT;
    } else {
        control &= ~CONTROL_SPSEL_BIT;
    }

    return uc_reg_write(uc, UC_ARM_REG_CONTROL, &control);
}

/*
 * Cached register access structure.
 * Since uc_reg_ptr is not available in Unicorn 2.x, we use a caching
 * mechanism for frequently accessed registers.
 */
struct uc_cached_reg {
    uc_engine *uc;
    int regid;
    uint32_t cached_value;
    int dirty;
};

static inline void uc_cached_reg_init(struct uc_cached_reg *reg, uc_engine *uc, int regid) {
    reg->uc = uc;
    reg->regid = regid;
    reg->cached_value = 0;
    reg->dirty = 0;
}

static inline uint32_t uc_cached_reg_read(struct uc_cached_reg *reg) {
    uc_reg_read(reg->uc, reg->regid, &reg->cached_value);
    return reg->cached_value;
}

static inline void uc_cached_reg_write(struct uc_cached_reg *reg, uint32_t value) {
    reg->cached_value = value;
    uc_reg_write(reg->uc, reg->regid, &value);
}

#ifdef __cplusplus
}
#endif

#endif /* UNICORN2_COMPAT_H */
