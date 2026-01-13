"""
Heiman Smoke Detector - Debug and OOB Trace Hooks

Contains hooks for debugging, tracing execution flow, and detecting
out-of-bounds memory accesses.
"""
from unicorn.arm_const import (
    UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
    UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
    UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R11,
    UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_SP
)

from .logging import _emu_log, _emu_debug_log, _fw_log
from .uart_protocol import UART_RX_BUFFER_ADDR, UART_RX_BUFFER_SIZE

# Alias for convenience
UART_BUFFER_ADDR = UART_RX_BUFFER_ADDR
UART_BUFFER_SIZE = 128  # Actual buffer size used

# Memory hook state
_oob_hook_installed = False


def install_oob_memory_hook(uc):
    """Install a memory read hook to detect OOB reads past UART buffer"""
    global _oob_hook_installed
    if _oob_hook_installed:
        return

    from unicorn import UC_HOOK_MEM_READ

    # Hook memory reads in the range just after the buffer
    oob_start = UART_BUFFER_ADDR + UART_BUFFER_SIZE
    oob_end = oob_start + 256  # Watch 256 bytes past buffer

    def on_mem_read(uc, access, address, size, value, user_data):
        _emu_debug_log(f"[OOB_READ] *** Memory read at 0x{address:08x} ({size} bytes) - {address - UART_BUFFER_ADDR} bytes from buffer start ***")
        return True  # Allow the read

    uc.hook_add(UC_HOOK_MEM_READ, on_mem_read, begin=oob_start, end=oob_end)
    _oob_hook_installed = True
    _emu_debug_log(f"[OOB_HOOK] Watching for reads in 0x{oob_start:08x}-0x{oob_end:08x}")


def trace_handler_muting(uc):
    """Hook HandleCmd_Muting at 0x8007CD8 - see what payload it receives

    When DEBUG_MODE is set and shell is enabled, drops to ipdb for interactive debugging.
    """
    r0 = uc.reg_read(UC_ARM_REG_R0)  # a1 = payload byte
    _emu_debug_log(f"[HANDLER] HandleCmd_Muting called with payload byte: 0x{r0:02x} ({r0})")

    # Drop to ipdb shell if shell mode is enabled
    if getattr(uc, 'shell', False):
        import sys as _sys
        _sys.stderr.write("\n[DEBUG] Dropping to ipdb shell at HandleCmd_Muting\n")
        _sys.stderr.write("Useful commands:\n")
        _sys.stderr.write("  uc.regs        - Show registers\n")
        _sys.stderr.write("  uc.regs.r0     - R0 = payload byte\n")
        _sys.stderr.write("  uc.mem[addr]   - Read memory\n")
        _sys.stderr.write("  c              - Continue execution\n")
        _sys.stderr.write("  q              - Quit\n\n")
        _sys.stderr.flush()
        import ipdb
        ipdb.set_trace()

    return False


def trace_uart_parse_entry(uc):
    """Hook at entry of UART_ParsePackets (0x800803C) to verify it's called"""
    r0 = uc.reg_read(UC_ARM_REG_R0)  # buffer pointer
    r1 = uc.reg_read(UC_ARM_REG_R1)  # length

    _emu_debug_log(f"[PARSE_TRACE] UART_ParsePackets called: buffer=0x{r0:08x}, length={r1}")

    # Read first 20 bytes of buffer
    try:
        data = uc.mem_read(r0, min(r1, 20))
        _emu_debug_log(f"[PARSE_TRACE] Buffer contents: {data.hex()}")
    except:
        _emu_debug_log(f"[PARSE_TRACE] Could not read buffer")

    return False  # Continue execution


def trace_after_log(uc):
    """Hook at 0x80080A8 - after BL UART_LogPrintf, before CMP cmd==5"""
    r6 = uc.reg_read(UC_ARM_REG_R6)  # cmd
    _emu_debug_log(f"[FLOW_TRACE] Reached 0x80080A8 (after log), cmd=0x{r6:02x}")
    return False


def trace_beq_cmd5(uc):
    """Hook at 0x80080AA - BEQ loc_800812C (branch if cmd==5)"""
    r6 = uc.reg_read(UC_ARM_REG_R6)
    pc = uc.reg_read(UC_ARM_REG_PC)
    _emu_debug_log(f"[FLOW_TRACE] At 0x80080AA (BEQ cmd==5), R6=0x{r6:02x}, PC=0x{pc:08x}")
    if r6 == 5:
        _emu_debug_log(f"[FLOW_TRACE] >>> BRANCH WILL BE TAKEN (cmd==5)! <<<")
    else:
        _emu_debug_log(f"[FLOW_TRACE] >>> BRANCH NOT TAKEN, continuing to 0x80080AC <<<")
    return False


def trace_after_magic_check(uc):
    """Hook at 0x8008054 - after entering loop, checking first byte"""
    r4 = uc.reg_read(UC_ARM_REG_R4)
    r5 = uc.reg_read(UC_ARM_REG_R5)
    _emu_debug_log(f"[FLOW_TRACE] At 0x8008054 (loop start), i={r4}, buffer=0x{r5:08x}")
    return False


def trace_after_validation(uc):
    """Hook at 0x8008074 - after all header validations pass"""
    r4 = uc.reg_read(UC_ARM_REG_R4)
    _emu_debug_log(f"[FLOW_TRACE] At 0x8008074 (validations PASSED!), i={r4}")
    return False


def trace_ldrb_length(uc):
    """Hook at 0x8008078 - LDRB.W R8, [R5,R11] (read length field)"""
    r4 = uc.reg_read(UC_ARM_REG_R4)
    r5 = uc.reg_read(UC_ARM_REG_R5)
    r11 = uc.reg_read(UC_ARM_REG_R11)
    _emu_debug_log(f"[FLOW_TRACE] At 0x8008078, i={r4}, R5=0x{r5:08x}, R11={r11}")
    try:
        length = uc.mem_read(r5 + r11, 1)[0]
        _emu_debug_log(f"[FLOW_TRACE]   Length field: {length} (0x{length:02x})")
    except:
        _emu_debug_log(f"[FLOW_TRACE]   Could not read length")
    return False


def trace_before_crc_calc(uc):
    """Hook at 0x8008086 - BL calculate_crc"""
    r0 = uc.reg_read(UC_ARM_REG_R0)
    r1 = uc.reg_read(UC_ARM_REG_R1)
    _emu_debug_log(f"[FLOW_TRACE] At 0x8008086 (calling calculate_crc), buffer=0x{r0:08x}, size={r1}")
    return False


def trace_validation_failed(uc):
    """Hook at 0x80080C2 - validation failed path"""
    r4 = uc.reg_read(UC_ARM_REG_R4)
    _emu_debug_log(f"[FLOW_TRACE] At 0x80080C2 (validation FAILED), i={r4}")
    return False


def trace_crc_check(uc):
    """Hook at 0x80080AC - ADD R9, R5 (setup for CRC read)"""
    _emu_debug_log(f"[FLOW_TRACE] Reached 0x80080AC (CRC setup)")
    return False


def trace_after_crc_read(uc):
    """Hook at 0x80080B2 - CMP R2, R7 (after CRC read)"""
    r2 = uc.reg_read(UC_ARM_REG_R2)  # CRC byte read
    r7 = uc.reg_read(UC_ARM_REG_R7)  # calculated CRC
    _emu_debug_log(f"[FLOW_TRACE] Reached 0x80080B2, CRC read=0x{r2:02x}, calculated=0x{r7:02x}")
    return False


def trace_crc_read_oob(uc):
    """
    Hook at 0x80080AE - just BEFORE the CRC byte read instruction.

    At this point in UART_ParsePackets:
      R4 = loop index i
      R5 = buffer base (0x200187EC)
      R8 = length field value from packet
      R9 = i + 7 (added at 0x800808a)

    The next instruction (LDRB.W R2, [R9,R8]) reads CRC at buffer[i+7+length]
    """
    _emu_debug_log("[OOB_TRACE] >>> Hook triggered at 0x80080AE <<<")

    r4 = uc.reg_read(UC_ARM_REG_R4)   # i (loop index)
    r5 = uc.reg_read(UC_ARM_REG_R5)   # buffer base
    r8 = uc.reg_read(UC_ARM_REG_R8)   # length from packet
    r9 = uc.reg_read(UC_ARM_REG_R9)   # i + 7

    # CRC will be read from: R5 + R9 + R8 = buffer + (i+7) + length
    crc_offset = (r9 - r5) + r8  # offset from buffer start
    crc_addr = r5 + crc_offset

    is_oob = crc_offset >= UART_BUFFER_SIZE

    _emu_debug_log(f"[OOB_TRACE] CRC read: i={r4}, length={r8}, offset={crc_offset}, addr=0x{crc_addr:08x}")

    if is_oob:
        oob_bytes = crc_offset - UART_BUFFER_SIZE
        _emu_debug_log(f"[OOB_TRACE] *** OUT-OF-BOUNDS READ: {oob_bytes} bytes past buffer! ***")

        try:
            oob_value = uc.mem_read(crc_addr, 1)[0]
            _emu_debug_log(f"[OOB_TRACE] Value at OOB address 0x{crc_addr:08x}: 0x{oob_value:02x}")
        except Exception as e:
            _emu_debug_log(f"[OOB_TRACE] Failed to read OOB address: {e}")

    return False
