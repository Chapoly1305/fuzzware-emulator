"""
Heiman Smoke Detector - Crypto/SE Hooks

Contains hooks for bypassing hardware crypto operations that may spin-wait.
"""
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2


def sli_radioaes_acquire(uc):
    """
    Skip sli_radioaes_acquire @ 0x08016e8c
    Returns 0 (success).
    """
    uc.reg_write(UC_ARM_REG_R0, 0)


def sli_radioaes_release(uc):
    """
    Skip sli_radioaes_release @ 0x08016f60
    """
    pass


def aes_ccm_radio(uc):
    """
    Skip aes_ccm_radio @ 0x08016be4
    Returns 0 (success).
    """
    uc.reg_write(UC_ARM_REG_R0, 0)


def sli_aes_crypt_ctr_radio(uc):
    """
    Skip sli_aes_crypt_ctr_radio @ 0x08016dc4
    Returns 0 (success).
    """
    uc.reg_write(UC_ARM_REG_R0, 0)


def psa_generate_random(uc):
    """
    Hook psa_generate_random to provide fake random data.
    psa_status_t psa_generate_random(uint8_t *output, size_t output_size)
    R0 = output buffer, R1 = size
    Returns PSA_SUCCESS (0).
    """
    output_ptr = uc.reg_read(UC_ARM_REG_R0)
    output_size = uc.reg_read(UC_ARM_REG_R1)
    # Fill buffer with deterministic "random" data
    fake_random = bytes([i & 0xFF for i in range(output_size)])
    if output_ptr and output_size > 0:
        uc.mem_write(output_ptr, fake_random)
    uc.reg_write(UC_ARM_REG_R0, 0)


def sli_se_mailbox_execute_command(uc):
    """
    Skip sli_se_mailbox_execute_command to bypass hardware SE operations.
    Returns SL_STATUS_OK (0).
    """
    uc.reg_write(UC_ARM_REG_R0, 0)


def sli_se_execute_and_wait(uc):
    """
    Skip sli_se_execute_and_wait @ 0x08015a20
    This function waits for SE hardware response.
    Returns SL_STATUS_OK (0).
    """
    uc.reg_write(UC_ARM_REG_R0, 0)


def sli_se_lock_acquire(uc):
    """
    Skip sli_se_lock_acquire @ 0x08015974
    Returns SL_STATUS_OK (0).
    """
    uc.reg_write(UC_ARM_REG_R0, 0)


def sli_se_lock_release(uc):
    """
    Skip sli_se_lock_release @ 0x080159ac
    """
    pass


def sl_se_init(uc):
    """
    Skip sl_se_init @ 0x080158c8
    Returns SL_STATUS_OK (0).
    """
    uc.reg_write(UC_ARM_REG_R0, 0)


def sl_se_get_random(uc):
    """
    Hook sl_se_get_random to provide fake random data.
    sl_status_t sl_se_get_random(sl_se_command_context_t *cmd_ctx, void *data, uint32_t num_bytes)
    R0 = cmd_ctx (ignore), R1 = data buffer, R2 = num_bytes
    Returns SL_STATUS_OK (0).
    """
    data_ptr = uc.reg_read(UC_ARM_REG_R1)
    num_bytes = uc.reg_read(UC_ARM_REG_R2)
    # Fill buffer with deterministic "random" data
    fake_random = bytes([i & 0xFF for i in range(num_bytes)])
    if data_ptr and num_bytes > 0:
        uc.mem_write(data_ptr, fake_random)
    uc.reg_write(UC_ARM_REG_R0, 0)
