"""
Silicon Labs BRD2601B Matter Lighting Example - Project-Specific Hooks

This module provides Matter Provision::Storage hooks with device-specific
configuration values for the BRD2601B (EFR32MG24) Matter lighting example.

These hooks return provisioning data that would normally be stored in NVM3
flash, allowing the Matter stack to run without real flash storage.
"""

import sys
import os
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_LR

from ...fuzz import get_fuzz

# ============================================================================
# Provisioning Configuration for BRD2601B
# ============================================================================
# These values match the Matter lighting example firmware configuration

PROVISION_VENDOR_ID = 0xFFF1          # Test Vendor ID
PROVISION_PRODUCT_ID = 0x8005         # Lighting example
PROVISION_PRODUCT_NAME = b"SL_Sample"
PROVISION_VENDOR_NAME = b"Silabs"
PROVISION_SERIAL_NUMBER = b"FUZZ0001"
PROVISION_DISCRIMINATOR = 0xF00       # 3840
PROVISION_PASSCODE = 20202021         # Default Matter test passcode
PROVISION_HW_VERSION = 0
PROVISION_HW_VERSION_STRING = b"1.0"
PROVISION_SW_VERSION_STRING = b"v1.0"

# ============================================================================
# Logging Utilities (minimal implementation)
# ============================================================================

LOG_LEVEL_DEBUG = 0
LOG_LEVEL_INFO = 1
LOG_LEVEL_WARN = 2

_log_level = LOG_LEVEL_INFO
_env_log_level = os.environ.get('FUZZWARE_LOG_LEVEL', 'INFO').upper()
if _env_log_level == 'DEBUG':
    _log_level = LOG_LEVEL_DEBUG
elif _env_log_level == 'INFO':
    _log_level = LOG_LEVEL_INFO
elif _env_log_level == 'WARN':
    _log_level = LOG_LEVEL_WARN

LOG_FILE_PATH = os.environ.get('FUZZWARE_LOG_FILE', '/tmp/fuzzware_console.log')
_log_file = None

def _log_debug(msg):
    """Write debug log message"""
    global _log_file
    if _log_level <= LOG_LEVEL_DEBUG:
        sys.stdout.write(msg)
        sys.stdout.flush()
        if _log_file is None:
            try:
                _log_file = open(LOG_FILE_PATH, 'a')
            except:
                pass
        if _log_file:
            _log_file.write(msg)
            _log_file.flush()

def _log_warn(msg):
    """Write warning log message"""
    global _log_file
    if _log_level <= LOG_LEVEL_WARN:
        sys.stdout.write(msg)
        sys.stdout.flush()
        if _log_file is None:
            try:
                _log_file = open(LOG_FILE_PATH, 'a')
            except:
                pass
        if _log_file:
            _log_file.write(msg)
            _log_file.flush()

# ============================================================================
# Matter Provision::Storage Hooks
# ============================================================================

_fuzz_consumed_once = False

def consume_fuzz_once(uc):
    global _fuzz_consumed_once
    if not _fuzz_consumed_once:
        get_fuzz(uc, 1)
        _fuzz_consumed_once = True
    uc.reg_write(UC_ARM_REG_R0, 0)

def UARTDRV_Receive_fuzz(uc):
    """
    Ecode_t UARTDRV_Receive(UARTDRV_Handle_t handle, uint8_t *data, UARTDRV_Count_t count, ...)
    R0 = handle, R1 = data buffer, R2 = count
    """
    buf_ptr = uc.reg_read(UC_ARM_REG_R1)
    count = uc.reg_read(UC_ARM_REG_R2)
    if buf_ptr != 0 and count:
        fuzz_data = get_fuzz(uc, count) or b""
        if len(fuzz_data) < count:
            fuzz_data = fuzz_data.ljust(count, b"\0")
        uc.mem_write(buf_ptr, fuzz_data[:count])
    uc.reg_write(UC_ARM_REG_R0, 0)

def ProvisionStorage_GetVendorId(uc):
    """
    CHIP_ERROR GetVendorId(uint16_t& vendorId)
    C++ method: R0 = this, R1 = &vendorId (output pointer)
    Returns CHIP_NO_ERROR (0) on success
    """
    out_ptr = uc.reg_read(UC_ARM_REG_R1)
    if out_ptr != 0:
        uc.mem_write(out_ptr, PROVISION_VENDOR_ID.to_bytes(2, 'little'))
    uc.reg_write(UC_ARM_REG_R0, 0)  # CHIP_NO_ERROR


def ProvisionStorage_GetProductId(uc):
    """
    CHIP_ERROR GetProductId(uint16_t& productId)
    C++ method: R0 = this, R1 = &productId (output pointer)
    """
    out_ptr = uc.reg_read(UC_ARM_REG_R1)
    if out_ptr != 0:
        uc.mem_write(out_ptr, PROVISION_PRODUCT_ID.to_bytes(2, 'little'))
    uc.reg_write(UC_ARM_REG_R0, 0)  # CHIP_NO_ERROR


def ProvisionStorage_GetProductName(uc):
    """
    CHIP_ERROR GetProductName(char* buf, size_t bufSize)
    C++ method: R0 = this, R1 = buf, R2 = bufSize
    """
    buf_ptr = uc.reg_read(UC_ARM_REG_R1)
    buf_size = uc.reg_read(UC_ARM_REG_R2)
    if buf_ptr != 0 and buf_size > 0:
        name = PROVISION_PRODUCT_NAME[:buf_size-1] + b'\0'
        uc.mem_write(buf_ptr, name)
    uc.reg_write(UC_ARM_REG_R0, 0)  # CHIP_NO_ERROR


def ProvisionStorage_GetVendorName(uc):
    """
    CHIP_ERROR GetVendorName(char* buf, size_t bufSize)
    C++ method: R0 = this, R1 = buf, R2 = bufSize
    """
    buf_ptr = uc.reg_read(UC_ARM_REG_R1)
    buf_size = uc.reg_read(UC_ARM_REG_R2)
    if buf_ptr != 0 and buf_size > 0:
        name = PROVISION_VENDOR_NAME[:buf_size-1] + b'\0'
        uc.mem_write(buf_ptr, name)
    uc.reg_write(UC_ARM_REG_R0, 0)  # CHIP_NO_ERROR


def ProvisionStorage_GetSerialNumber(uc):
    """
    CHIP_ERROR GetSerialNumber(char* buf, size_t bufSize)
    C++ method: R0 = this, R1 = buf, R2 = bufSize
    """
    buf_ptr = uc.reg_read(UC_ARM_REG_R1)
    buf_size = uc.reg_read(UC_ARM_REG_R2)
    if buf_ptr != 0 and buf_size > 0:
        serial = PROVISION_SERIAL_NUMBER[:buf_size-1] + b'\0'
        uc.mem_write(buf_ptr, serial)
    uc.reg_write(UC_ARM_REG_R0, 0)  # CHIP_NO_ERROR


def ProvisionStorage_GetSetupDiscriminator(uc):
    """
    CHIP_ERROR GetSetupDiscriminator(uint16_t& discriminator)
    C++ method: R0 = this, R1 = &discriminator (output pointer)
    """
    out_ptr = uc.reg_read(UC_ARM_REG_R1)
    if out_ptr != 0:
        uc.mem_write(out_ptr, PROVISION_DISCRIMINATOR.to_bytes(2, 'little'))
    uc.reg_write(UC_ARM_REG_R0, 0)  # CHIP_NO_ERROR


def ProvisionStorage_GetSetupPasscode(uc):
    """
    CHIP_ERROR GetSetupPasscode(uint32_t& passcode)
    C++ method: R0 = this, R1 = &passcode (output pointer)
    """
    out_ptr = uc.reg_read(UC_ARM_REG_R1)
    if out_ptr != 0:
        uc.mem_write(out_ptr, PROVISION_PASSCODE.to_bytes(4, 'little'))
    uc.reg_write(UC_ARM_REG_R0, 0)  # CHIP_NO_ERROR


def ProvisionStorage_GetHardwareVersion(uc):
    """
    CHIP_ERROR GetHardwareVersion(uint16_t& hwVersion)
    C++ method: R0 = this, R1 = &hwVersion (output pointer)
    """
    out_ptr = uc.reg_read(UC_ARM_REG_R1)
    if out_ptr != 0:
        uc.mem_write(out_ptr, PROVISION_HW_VERSION.to_bytes(2, 'little'))
    uc.reg_write(UC_ARM_REG_R0, 0)  # CHIP_NO_ERROR


def ProvisionStorage_GetHardwareVersionString(uc):
    """
    CHIP_ERROR GetHardwareVersionString(char* buf, size_t bufSize)
    C++ method: R0 = this, R1 = buf, R2 = bufSize
    """
    buf_ptr = uc.reg_read(UC_ARM_REG_R1)
    buf_size = uc.reg_read(UC_ARM_REG_R2)
    if buf_ptr != 0 and buf_size > 0:
        ver = PROVISION_HW_VERSION_STRING[:buf_size-1] + b'\0'
        uc.mem_write(buf_ptr, ver)
    uc.reg_write(UC_ARM_REG_R0, 0)  # CHIP_NO_ERROR


def ProvisionStorage_GetSoftwareVersionString(uc):
    """
    CHIP_ERROR GetSoftwareVersionString(char* buf, size_t bufSize)
    C++ method: R0 = this, R1 = buf, R2 = bufSize
    """
    buf_ptr = uc.reg_read(UC_ARM_REG_R1)
    buf_size = uc.reg_read(UC_ARM_REG_R2)
    if buf_ptr != 0 and buf_size > 0:
        ver = PROVISION_SW_VERSION_STRING[:buf_size-1] + b'\0'
        uc.mem_write(buf_ptr, ver)
    uc.reg_write(UC_ARM_REG_R0, 0)  # CHIP_NO_ERROR


def ProvisionStorage_GetProductLabel(uc):
    """
    CHIP_ERROR GetProductLabel(char* buf, size_t bufSize)
    C++ method: R0 = this, R1 = buf, R2 = bufSize
    """
    buf_ptr = uc.reg_read(UC_ARM_REG_R1)
    buf_size = uc.reg_read(UC_ARM_REG_R2)
    if buf_ptr != 0 and buf_size > 0:
        label = PROVISION_PRODUCT_NAME[:buf_size-1] + b'\0'  # Reuse product name
        uc.mem_write(buf_ptr, label)
    uc.reg_write(UC_ARM_REG_R0, 0)  # CHIP_NO_ERROR


def ProvisionStorage_GetProductURL(uc):
    """
    CHIP_ERROR GetProductURL(char* buf, size_t bufSize)
    C++ method: R0 = this, R1 = buf, R2 = bufSize
    """
    buf_ptr = uc.reg_read(UC_ARM_REG_R1)
    buf_size = uc.reg_read(UC_ARM_REG_R2)
    if buf_ptr != 0 and buf_size > 0:
        url = b"https://silabs.com\0"[:buf_size]
        uc.mem_write(buf_ptr, url)
    uc.reg_write(UC_ARM_REG_R0, 0)  # CHIP_NO_ERROR


def ProvisionStorage_GetPartNumber(uc):
    """
    CHIP_ERROR GetPartNumber(char* buf, size_t bufSize)
    C++ method: R0 = this, R1 = buf, R2 = bufSize
    """
    buf_ptr = uc.reg_read(UC_ARM_REG_R1)
    buf_size = uc.reg_read(UC_ARM_REG_R2)
    if buf_ptr != 0 and buf_size > 0:
        part = b"BRD2601B\0"[:buf_size]
        uc.mem_write(buf_ptr, part)
    uc.reg_write(UC_ARM_REG_R0, 0)  # CHIP_NO_ERROR


# ============================================================================
# NVM3 Debug Hooks - Log key accesses to detect missing hooks
# ============================================================================

def nvm3_readData_debug(uc):
    """
    Ecode_t nvm3_readData(nvm3_Handle_t *h, nvm3_ObjectKey_t key, void *value, size_t len)
    R0 = handle, R1 = key, R2 = value buffer, R3 = len

    Logs the NVM3 key being accessed so we can identify unhooked provision values.
    Returns ECODE_NVM3_ERR_KEY_NOT_FOUND (0x00072003) to indicate key doesn't exist.
    """
    from unicorn.arm_const import UC_ARM_REG_R3
    handle = uc.reg_read(UC_ARM_REG_R0)
    key = uc.reg_read(UC_ARM_REG_R1)
    value_ptr = uc.reg_read(UC_ARM_REG_R2)
    length = uc.reg_read(UC_ARM_REG_R3)

    # Log the key access - this helps identify what we're missing
    _log_debug(f"[NVM3] nvm3_readData: key=0x{key:08x}, len={length}\n")

    # Return ECODE_NVM3_ERR_KEY_NOT_FOUND (0x00072003)
    # This tells the caller the key doesn't exist
    uc.reg_write(UC_ARM_REG_R0, 0x00072003)


def nvm3_getObjectInfo_debug(uc):
    """
    Ecode_t nvm3_getObjectInfo(nvm3_Handle_t *h, nvm3_ObjectKey_t key, uint32_t *type, size_t *len)
    R0 = handle, R1 = key, R2 = type ptr, R3 = len ptr

    Logs the NVM3 key being queried.
    Returns ECODE_NVM3_ERR_KEY_NOT_FOUND (0x00072003).
    """
    handle = uc.reg_read(UC_ARM_REG_R0)
    key = uc.reg_read(UC_ARM_REG_R1)

    _log_debug(f"[NVM3] nvm3_getObjectInfo: key=0x{key:08x}\n")

    # Return key not found
    uc.reg_write(UC_ARM_REG_R0, 0x00072003)


# ============================================================================
# Catch-all for unhooked Provision::Storage functions
# ============================================================================

def ProvisionStorage_Unimplemented(uc):
    """
    Catch-all for Provision::Storage functions we haven't specifically hooked.
    Logs a warning and returns CHIP_ERROR_NOT_IMPLEMENTED (0x00000009).
    """
    # Get the PC to identify which function was called
    lr = uc.reg_read(UC_ARM_REG_LR)
    _log_warn(f"[PROVISION] WARNING: Unimplemented Provision::Storage function called! LR=0x{lr:08x}\n")

    # Return CHIP_ERROR_NOT_IMPLEMENTED
    uc.reg_write(UC_ARM_REG_R0, 0x09)
