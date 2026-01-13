"""
Heiman Smoke Detector - NVM3 Bypass Hooks

Contains hooks for bypassing NVM3 and returning appropriate responses to Matter.
"""
import struct
from unicorn.arm_const import (
    UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
    UC_ARM_REG_LR, UC_ARM_REG_SP
)

from .logging import _emu_log

# NVM3 Error Codes - Simple integer values (NOT full ECODE format)
NVM3_OK = 0              # Success
NVM3_ERR_KEY_NOT_FOUND = 45   # Key not found (objGroupDeleted)
NVM3_ERR_NOT_OPENED = 17      # NVM3 not opened
NVM3_ERR_NULL_HANDLE = 33     # NULL handle
NVM3_ERR_KEY_INVALID = 41     # Invalid key (>= 0x100000)


# ============================================================================
# NVM3 Bypass Hooks
# ============================================================================

def nvm3_readData_bypass(uc):
    """
    Bypass nvm3_readData - return "key not found" error.

    Ecode_t nvm3_readData(nvm3_Handle_t *h, nvm3_ObjectKey_t key, void *value, size_t len)
    R0 = handle, R1 = key, R2 = value buffer, R3 = len
    Returns: 45 (key not found)
    """
    key = uc.reg_read(UC_ARM_REG_R1)
    _emu_log(f"[NVM3_BYPASS] nvm3_readData(key=0x{key:05x}) -> KEY_NOT_FOUND(45)\n")
    uc.reg_write(UC_ARM_REG_R0, NVM3_ERR_KEY_NOT_FOUND)


def nvm3_readPartialData_bypass(uc):
    """
    Bypass nvm3_readPartialData - return "key not found" error.
    """
    key = uc.reg_read(UC_ARM_REG_R1)
    _emu_log(f"[NVM3_BYPASS] nvm3_readPartialData(key=0x{key:05x}) -> KEY_NOT_FOUND(45)\n")
    uc.reg_write(UC_ARM_REG_R0, NVM3_ERR_KEY_NOT_FOUND)


def nvm3_readCounter_bypass(uc):
    """
    Bypass nvm3_readCounter - return "key not found" error.
    """
    key = uc.reg_read(UC_ARM_REG_R1)
    _emu_log(f"[NVM3_BYPASS] nvm3_readCounter(key=0x{key:05x}) -> KEY_NOT_FOUND(45)\n")
    uc.reg_write(UC_ARM_REG_R0, NVM3_ERR_KEY_NOT_FOUND)


def nvm3_writeData_bypass(uc):
    """
    Bypass nvm3_writeData - return success without writing.
    """
    key = uc.reg_read(UC_ARM_REG_R1)
    _emu_log(f"[NVM3_BYPASS] nvm3_writeData(key=0x{key:05x}) -> OK(0)\n")
    uc.reg_write(UC_ARM_REG_R0, NVM3_OK)


def nvm3_writeCounter_bypass(uc):
    """
    Bypass nvm3_writeCounter - return success.
    """
    key = uc.reg_read(UC_ARM_REG_R1)
    _emu_log(f"[NVM3_BYPASS] nvm3_writeCounter(key=0x{key:05x}) -> OK(0)\n")
    uc.reg_write(UC_ARM_REG_R0, NVM3_OK)


def nvm3_incrementCounter_bypass(uc):
    """
    Bypass nvm3_incrementCounter - return success.
    """
    key = uc.reg_read(UC_ARM_REG_R1)
    _emu_log(f"[NVM3_BYPASS] nvm3_incrementCounter(key=0x{key:05x}) -> OK(0)\n")
    uc.reg_write(UC_ARM_REG_R0, NVM3_OK)


def nvm3_deleteObject_bypass(uc):
    """
    Bypass nvm3_deleteObject - return success.
    """
    key = uc.reg_read(UC_ARM_REG_R1)
    _emu_log(f"[NVM3_BYPASS] nvm3_deleteObject(key=0x{key:05x}) -> OK(0)\n")
    uc.reg_write(UC_ARM_REG_R0, NVM3_OK)


def nvm3_getObjectInfo_bypass(uc):
    """
    Bypass nvm3_getObjectInfo - return "key not found" error.
    """
    key = uc.reg_read(UC_ARM_REG_R1)
    _emu_log(f"[NVM3_BYPASS] nvm3_getObjectInfo(key=0x{key:05x}) -> KEY_NOT_FOUND(45)\n")
    uc.reg_write(UC_ARM_REG_R0, NVM3_ERR_KEY_NOT_FOUND)


def nvm3_enumObjects_bypass(uc):
    """
    Bypass nvm3_enumObjects - return 0 (no objects found).
    """
    key_min = uc.reg_read(UC_ARM_REG_R3)
    _emu_log(f"[NVM3_BYPASS] nvm3_enumObjects(keyMin=0x{key_min:05x}) -> 0 objects\n")
    uc.reg_write(UC_ARM_REG_R0, 0)


def nvm3_enumDeletedObjects_bypass(uc):
    """
    Bypass nvm3_enumDeletedObjects - return 0 (no deleted objects).
    """
    _emu_log(f"[NVM3_BYPASS] nvm3_enumDeletedObjects() -> 0 objects\n")
    uc.reg_write(UC_ARM_REG_R0, 0)


def nvm3_open_bypass(uc):
    """
    Bypass nvm3_open - return success and mark handle as opened.

    This is CRITICAL: nvm3_open contains blocking xQueueReceive calls.
    We skip the actual initialization but set hasBeenOpened = true.

    sl_status_t nvm3_open(nvm3_Handle_t *h, const nvm3_Init_t *i)
    R0 = handle pointer, R1 = init struct pointer
    """
    handle_ptr = uc.reg_read(UC_ARM_REG_R0)
    _emu_log(f"[NVM3_BYPASS] nvm3_open(handle=0x{handle_ptr:08x}) -> OK(0)\n")

    # Set hasBeenOpened flag (offset 0x34 in nvm3_Handle_t)
    if handle_ptr and handle_ptr >= 0x20000000:
        try:
            uc.mem_write(handle_ptr + 0x34, b'\x01')
            _emu_log(f"[NVM3_BYPASS] Set hasBeenOpened=1 at 0x{handle_ptr + 0x34:08x}\n")
        except:
            pass

    uc.reg_write(UC_ARM_REG_R0, NVM3_OK)


def nvm3_initDefault_bypass(uc):
    """
    Bypass nvm3_initDefault - return success but don't actually initialize.
    nvm3_initDefault calls nvm3_open internally, so we skip both.
    """
    _emu_log(f"[NVM3_BYPASS] nvm3_initDefault() -> OK(0)\n")
    uc.reg_write(UC_ARM_REG_R0, NVM3_OK)


def nvm3_close_bypass(uc):
    """
    Bypass nvm3_close - return success.
    """
    _emu_log(f"[NVM3_BYPASS] nvm3_close() -> OK(0)\n")
    uc.reg_write(UC_ARM_REG_R0, NVM3_OK)


def nvm3_async_operation_bypass(uc):
    """
    Bypass the async NVM3 operation that uses FreeRTOS queues.
    """
    lr = uc.reg_read(UC_ARM_REG_LR)
    _emu_log(f"[NVM3_BYPASS] Async NVM3 operation skipped (caller=0x{lr:08x})\n")
    uc.reg_write(UC_ARM_REG_R0, NVM3_OK)


# ============================================================================
# NVM3 Flash Read Tracing - logs to emulator.log
# ============================================================================

def nvm3_halFlashReadWords_trace(uc):
    """Trace NVM3 flash reads. Use with do_return: false."""
    nvm_addr = uc.reg_read(UC_ARM_REG_R0)
    dst_addr = uc.reg_read(UC_ARM_REG_R1)
    word_count = uc.reg_read(UC_ARM_REG_R2)
    lr = uc.reg_read(UC_ARM_REG_LR)
    _emu_log(f"[NVM3_READ] addr=0x{nvm_addr:08x} dst=0x{dst_addr:08x} words={word_count} caller=0x{lr:08x}\n")


def nvm3_enumObjects_trace(uc):
    """Trace NVM3 object enumeration. Use with do_return: false."""
    key_min = uc.reg_read(UC_ARM_REG_R3)
    sp = uc.reg_read(UC_ARM_REG_SP)
    try:
        key_max = int.from_bytes(uc.mem_read(sp, 4), 'little')
    except:
        key_max = 0
    lr = uc.reg_read(UC_ARM_REG_LR)
    _emu_log(f"[NVM3_ENUM] keyMin=0x{key_min:05x} keyMax=0x{key_max:05x} caller=0x{lr:08x}\n")


def nvm3_open_trace(uc):
    """Trace NVM3 open. Use with do_return: false."""
    init_ptr = uc.reg_read(UC_ARM_REG_R1)
    lr = uc.reg_read(UC_ARM_REG_LR)
    flash_addr = 0
    try:
        init_data = uc.mem_read(init_ptr, 16)
        flash_addr = int.from_bytes(init_data[0:4], 'little')
    except:
        pass
    _emu_log(f"[NVM3_OPEN] flash_addr=0x{flash_addr:08x} caller=0x{lr:08x}\n")


def nvm3_halFlashGetInfo(uc):
    """
    Hook nvm3_halFlashGetInfo to provide correct MG24 flash parameters.

    Ecode_t nvm3_halFlashGetInfo(nvm3_HalFlashInfo_t *info)
    R0 = pointer to flash info structure to fill

    For MG24:
    - Page size: 8KB (0x2000)
    - Write size: 4 bytes
    - Memory mapped: 1 (yes)
    """
    info_ptr = uc.reg_read(UC_ARM_REG_R0)

    # MG24 flash info
    device_family = 0x3C  # EFR32MG24 family
    write_size = 4        # 4-byte write granularity
    memory_mapped = 1     # Memory mapped flash
    page_size = 0x2000    # 8KB pages

    # System partition (bootloader area)
    system_part_start = 0x08000000
    system_part_end = 0x08006000

    # User partition (application + NVM3)
    user_part_start = 0x08006000
    user_part_end = 0x08180000  # 1.5MB flash

    # Pack the structure
    flash_info = struct.pack('<HBBIIIII',
        device_family,
        write_size,
        memory_mapped,
        page_size,
        system_part_start,
        system_part_end,
        user_part_start,
        user_part_end
    )

    # Write to the info structure
    if info_ptr and info_ptr >= 0x20000000:
        uc.mem_write(info_ptr, flash_info)
        _emu_log(f"[NVM3_FLASH_INFO] Filled info at 0x{info_ptr:08x}: pageSize=0x{page_size:x}\n")

    # Return ECODE_NVM3_OK (0)
    uc.reg_write(UC_ARM_REG_R0, 0)
