"""
Heiman Smoke Detector - UART Fuzzing Core

Contains the main UART fuzzing entry points and persistent loop handlers.
"""
import sys
import ctypes
from unicorn.arm_const import (
    UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
    UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_SP
)

from ...fuzz import get_fuzz

from .logging import (
    _emu_log, _emu_debug_log, _fw_log, _log_uart_packet, _log_input,
    _save_input_log, _clear_input_log, get_tx_rx_stats, increment_tx_count
)
from .uart_protocol import (
    UART_MAGIC, UART_DEV_TYPE, UART_PROTO_VER, UART_DIR_SENSOR_TO_MCU,
    FUZZ_BUFFER_ADDR, _calc_uart_crc
)
from .debug_trace import install_oob_memory_hook

# Track packet count for persistent loop
_packet_count = 0

# Track assert count
_assert_count = 0


def UARTDRV_Receive(uc):
    """
    Hook UARTDRV_Receive - TEMPORARY: Return success without consuming fuzz.
    This allows boot to complete before we inject fuzz.
    """
    pc = uc.reg_read(UC_ARM_REG_PC)
    lr = uc.reg_read(UC_ARM_REG_LR)
    _emu_log(f"[UARTDRV_Receive] Called from LR=0x{lr:08x}\n")
    # Return success but don't consume fuzz or inject data
    uc.reg_write(UC_ARM_REG_R0, 0)


def EUSART_Rx(uc):
    """
    Hook low-level EUSART receive to inject single fuzz byte.
    uint8_t EUSART_Rx(EUSART_TypeDef *eusart)
    R0 = eusart peripheral pointer
    Returns: received byte in R0
    """
    # Get one fuzz byte
    fuzz_byte = get_fuzz(uc, 1)
    if fuzz_byte is None or len(fuzz_byte) == 0:
        uc.reg_write(UC_ARM_REG_R0, 0)
        return

    uc.reg_write(UC_ARM_REG_R0, fuzz_byte[0])
    _emu_log(f"[EUSART] RX byte: 0x{fuzz_byte[0]:02x}\n")


def uart_fuzz_entry(uc):
    """
    Direct entry hook for UART_ParsePackets fuzzing.

    UART_ParsePackets(uint8_t *buffer, uint32_t length)
    R0 = buffer pointer, R1 = length

    This hook:
    1. Gets raw fuzz data
    2. Wraps it in UART protocol format
    3. Writes to a RAM buffer
    4. Sets up R0/R1 for UART_ParsePackets
    5. Lets execution continue into the parser
    """
    # Get fuzz input (raw bytes)
    fuzz_size = 64  # Request up to 64 bytes
    raw_fuzz = get_fuzz(uc, fuzz_size)

    if raw_fuzz is None or len(raw_fuzz) == 0:
        # No fuzz - return immediately
        # Set PC to a return instruction
        uc.reg_write(UC_ARM_REG_R0, 0)
        return True  # Skip function

    # Wrap fuzz in UART protocol format
    cmd = raw_fuzz[0] if len(raw_fuzz) > 0 else 0x01
    payload = raw_fuzz[1:] if len(raw_fuzz) > 1 else b''

    # Build packet
    seq = 0
    direction = UART_DIR_SENSOR_TO_MCU  # 0x01 = Sensor -> MCU
    header = bytes([UART_DEV_TYPE, UART_PROTO_VER, seq, direction, cmd])
    packet_len = len(header) + len(payload)
    packet_body = bytes([packet_len]) + header + payload

    # Calculate CRC (XOR of all bytes after magic)
    crc = _calc_uart_crc(packet_body)

    # Complete packet with magic and CRC
    uart_packet = UART_MAGIC + packet_body + bytes([crc])

    # Write packet to RAM buffer
    uc.mem_write(FUZZ_BUFFER_ADDR, uart_packet)

    # Set up registers for UART_ParsePackets(buffer, length)
    uc.reg_write(UC_ARM_REG_R0, FUZZ_BUFFER_ADDR)
    uc.reg_write(UC_ARM_REG_R1, len(uart_packet))

    _emu_log(f"[UART_FUZZ] Injected {len(uart_packet)} bytes: {uart_packet.hex()}\n")

    # Continue execution into UART_ParsePackets
    return False  # Don't skip, let function execute


def uart_fuzz_harness(uc):
    """
    Interrupt-based harness that repeatedly calls UART_ParsePackets with fuzz data.
    Called via interrupt trigger.
    """
    # Get fuzz input
    fuzz_size = 64
    raw_fuzz = get_fuzz(uc, fuzz_size)

    if raw_fuzz is None or len(raw_fuzz) == 0:
        return

    # Build UART packet from fuzz
    cmd = raw_fuzz[0] if len(raw_fuzz) > 0 else 0x01
    payload = raw_fuzz[1:] if len(raw_fuzz) > 1 else b''

    seq = 0
    direction = UART_DIR_SENSOR_TO_MCU
    header = bytes([UART_DEV_TYPE, UART_PROTO_VER, seq, direction, cmd])
    packet_len = len(header) + len(payload)
    packet_body = bytes([packet_len]) + header + payload

    crc = _calc_uart_crc(packet_body)
    uart_packet = UART_MAGIC + packet_body + bytes([crc])

    # Write to buffer
    uc.mem_write(FUZZ_BUFFER_ADDR, uart_packet)

    # Save current state
    old_pc = uc.reg_read(UC_ARM_REG_PC)
    old_lr = uc.reg_read(UC_ARM_REG_LR)
    old_r0 = uc.reg_read(UC_ARM_REG_R0)
    old_r1 = uc.reg_read(UC_ARM_REG_R1)

    # Set up call to UART_ParsePackets
    uc.reg_write(UC_ARM_REG_R0, FUZZ_BUFFER_ADDR)
    uc.reg_write(UC_ARM_REG_R1, len(uart_packet))
    uc.reg_write(UC_ARM_REG_LR, old_pc | 1)  # Return to where we were
    uc.reg_write(UC_ARM_REG_PC, 0x0800803c | 1)  # UART_ParsePackets (thumb)

    _emu_log(f"[UART_HARNESS] Called UART_ParsePackets with {len(uart_packet)} bytes\n")


def uart_interrupt_inject(uc):
    """
    Interrupt handler that injects fuzz data into UART buffer and triggers parsing.

    This function is called periodically via interrupt triggers to inject
    fuzz data into the UART RX buffer and call UART_ParsePackets.

    It preserves the current execution context and returns after processing.
    """
    from fuzzware_harness import native

    _emu_debug_log("[FUZZ] uart_interrupt_inject CALLED!")

    try:
        uc_handle = uc._uch

        # Check if there's fuzz data available
        remaining = native.fuzz_remaining()
        if remaining == 0:
            return  # No fuzz available, skip

        # Get fuzz data (up to 64 bytes)
        bytes_to_get = min(remaining, 64)
        ptr_addr = native.native_lib.get_fuzz_ptr(uc_handle, bytes_to_get)

        if ptr_addr is None or ptr_addr == 0:
            return

        raw_fuzz = (ctypes.c_char * bytes_to_get).from_address(ptr_addr).raw

        if len(raw_fuzz) == 0:
            return

        # Build UART packet
        cmd = raw_fuzz[0]
        payload = raw_fuzz[1:] if len(raw_fuzz) > 1 else b''

        MAX_PAYLOAD = 250
        if len(payload) > MAX_PAYLOAD:
            payload = payload[:MAX_PAYLOAD]

        seq = 0
        direction = UART_DIR_SENSOR_TO_MCU
        header = bytes([UART_DEV_TYPE, UART_PROTO_VER, seq, direction, cmd])
        packet_len = len(header) + len(payload)
        packet_body = bytes([packet_len]) + header + payload

        crc = _calc_uart_crc(packet_body)
        uart_packet = UART_MAGIC + packet_body + bytes([crc])

        # Write to UART RX buffer
        uc.mem_write(FUZZ_BUFFER_ADDR, uart_packet)

        # Save context
        old_pc = uc.reg_read(UC_ARM_REG_PC)
        old_lr = uc.reg_read(UC_ARM_REG_LR)
        old_r0 = uc.reg_read(UC_ARM_REG_R0)
        old_r1 = uc.reg_read(UC_ARM_REG_R1)

        # Set up call to UART_ParsePackets
        uc.reg_write(UC_ARM_REG_R0, FUZZ_BUFFER_ADDR)
        uc.reg_write(UC_ARM_REG_R1, len(uart_packet))
        uc.reg_write(UC_ARM_REG_LR, old_pc | 1)  # Return to interrupted code
        uc.reg_write(UC_ARM_REG_PC, 0x0800803c | 1)  # UART_ParsePackets

        _emu_log(f"[UART_IRQ] Injected {len(uart_packet)} bytes, calling UART_ParsePackets\n")

    except Exception as e:
        pass  # Silently ignore errors in interrupt context


def start_uart_fuzzing(uc):
    """
    Hook for sl_kernel_start - instead of starting the kernel,
    redirect execution to UART_ParsePackets with fuzz data.

    If input starts with AA 55, treat as raw packet (no wrapping).
    Otherwise, wrap fuzz bytes in UART protocol.
    """
    global _packet_count, _assert_count

    # Install memory hook to detect OOB reads
    install_oob_memory_hook(uc)

    # Reset counters for this fuzzing session
    _packet_count = 0
    _assert_count = 0

    # Disable verbose logging for performance (set DEBUG_UART=1 to enable)
    DEBUG_UART = False

    if DEBUG_UART:
        _emu_debug_log("[UART_FUZZ] Hook entry")
    _emu_log("[UART_FUZZ] Intercepted sl_kernel_start, redirecting to UART parsing\n")

    from fuzzware_harness import native

    try:
        # Get the raw Unicorn handle
        uc_handle = uc._uch

        # First, check if there's any fuzz available
        remaining_before = native.fuzz_remaining()

        # Request 1 byte to trigger input loading
        ptr_addr = native.native_lib.get_fuzz_ptr(uc_handle, 1)

        # Check what's available after loading
        remaining_after = native.fuzz_remaining()
        consumed = native.fuzz_consumed()

        if ptr_addr is None or ptr_addr == 0:
            raw_fuzz = b'\x01'  # Default command byte
        else:
            # Read the first byte
            first_byte = (ctypes.c_char * 1).from_address(ptr_addr).raw

            # Get remaining bytes - limit to 15 per packet for multi-packet fuzzing
            PACKET_CHUNK_SIZE = 15
            bytes_to_get = min(remaining_after, PACKET_CHUNK_SIZE - 1)
            if bytes_to_get > 0:
                ptr_addr2 = native.native_lib.get_fuzz_ptr(uc_handle, bytes_to_get)
                if ptr_addr2 and ptr_addr2 != 0:
                    rest_bytes = (ctypes.c_char * bytes_to_get).from_address(ptr_addr2).raw
                    raw_fuzz = first_byte + rest_bytes
                else:
                    raw_fuzz = first_byte
            else:
                raw_fuzz = first_byte

    except Exception as e:
        import traceback
        _emu_debug_log(f"[UART_FUZZ] Error: {e}\n{traceback.format_exc()}")
        raw_fuzz = b'\x01'  # Use default on error

    # Debug: show what fuzz we got
    _emu_debug_log(f"[FUZZ_DEBUG] Got {len(raw_fuzz)} bytes: {raw_fuzz.hex()}")

    # Check if input is already a raw UART packet (starts with AA 55)
    if len(raw_fuzz) >= 2 and raw_fuzz[0] == 0xAA and raw_fuzz[1] == 0x55:
        # Raw packet mode - use as-is
        uart_packet = raw_fuzz
        _emu_debug_log(f"[RAW_MODE] Using raw packet: {uart_packet.hex()}")
    else:
        # Build UART packet from fuzz bytes
        cmd = raw_fuzz[0] if len(raw_fuzz) > 0 else 0x01
        payload = raw_fuzz[1:] if len(raw_fuzz) > 1 else b''

        MAX_PAYLOAD = 250
        if len(payload) > MAX_PAYLOAD:
            payload = payload[:MAX_PAYLOAD]

        seq = 0
        direction = UART_DIR_SENSOR_TO_MCU
        header = bytes([UART_DEV_TYPE, UART_PROTO_VER, seq, direction, cmd])
        packet_len = len(header) + len(payload)
        packet_body = bytes([packet_len]) + header + payload

        crc = _calc_uart_crc(packet_body)
        uart_packet = UART_MAGIC + packet_body + bytes([crc])

    # Write to buffer
    uc.mem_write(FUZZ_BUFFER_ADDR, uart_packet)

    _emu_log(f"[UART_FUZZ] Prepared {len(uart_packet)} byte packet: {uart_packet.hex()}\n")

    # Log UART RX packet to file with formatting
    _log_uart_packet("RX", uart_packet, "Fuzz input wrapped with UART protocol")

    # Simply set up registers and branch to UART_ParsePackets
    LOOP_ADDR = 0x20018000

    import struct
    # Write infinite loop: b . (0xe7fe in thumb)
    uc.mem_write(LOOP_ADDR, b'\xfe\xe7')

    # Set up registers directly
    uc.reg_write(UC_ARM_REG_R0, FUZZ_BUFFER_ADDR)
    uc.reg_write(UC_ARM_REG_R1, len(uart_packet))

    # Set LR to infinite loop so UART_ParsePackets returns there
    uc.reg_write(UC_ARM_REG_LR, LOOP_ADDR | 1)

    # Set PC to UART_ParsePackets
    uc.reg_write(UC_ARM_REG_PC, 0x0800803c | 1)

    _emu_log(f"[UART_FUZZ] Set up call to UART_ParsePackets({FUZZ_BUFFER_ADDR:#x}, {len(uart_packet)})\n")
    _emu_log(f"[UART_FUZZ] LR={LOOP_ADDR | 1:#x}, PC=0x0800803d\n")

    # Return False to let execution continue at new PC
    return False


def _trigger_uart_tx(uc, tx_func_addr):
    """
    Trigger UART_DoTransmit to send any pending TX response.

    This function saves current state, calls UART_DoTransmit, and restores state.
    """
    # Save current registers
    saved_pc = uc.reg_read(UC_ARM_REG_PC)
    saved_lr = uc.reg_read(UC_ARM_REG_LR)

    # Set up return address to a safe location
    RETURN_ADDR = 0x20018100

    try:
        # Write return instruction at return address
        uc.mem_write(RETURN_ADDR, b'\x70\x47')  # BX LR (return)

        # Set up call to UART_DoTransmit
        uc.reg_write(UC_ARM_REG_LR, RETURN_ADDR | 1)
        uc.reg_write(UC_ARM_REG_PC, tx_func_addr | 1)

        # Execute until return
        try:
            uc.emu_start(tx_func_addr | 1, RETURN_ADDR, timeout=100000, count=10000)
        except Exception as e:
            _emu_log(f"[UART_TX_TRIGGER] Execution ended: {e}\n")

    except Exception as e:
        _emu_log(f"[UART_TX_TRIGGER] Error: {e}\n")

    # Restore PC
    uc.reg_write(UC_ARM_REG_PC, saved_pc)


def uart_persistent_loop(uc):
    """
    Persistent loop handler for UART fuzzing.

    This hook is triggered when UART_ParsePackets returns (at LOOP_ADDR).
    It checks for remaining fuzz input and either:
    - Processes another packet if fuzz remains
    - Exits cleanly if fuzz is exhausted
    """
    global _packet_count

    from fuzzware_harness import native

    _packet_count += 1

    # Check remaining fuzz input
    remaining = native.fuzz_remaining()

    if remaining == 0:
        # Trigger TX for the last packet before exiting
        UART_DO_TRANSMIT_ADDR = 0x8008294
        _trigger_uart_tx(uc, UART_DO_TRANSMIT_ADDR)

        # Print TX/RX stats for verification
        tx_count, rx_count = get_tx_rx_stats()
        _emu_debug_log(f"[STATS] RX packets: {_packet_count}, TX responses: {tx_count}")

        # No more fuzz - exit cleanly
        _emu_log(f"[UART_LOOP] Processed {_packet_count} packets, fuzz exhausted - exiting\n")
        _save_input_log("fuzz_exhausted")
        _clear_input_log()
        native.do_exit(uc, 0)
        return True

    _emu_log(f"[UART_LOOP] Packet {_packet_count} done, {remaining} fuzz bytes remaining - processing next\n")

    try:
        uc_handle = uc._uch

        # Get next chunk of fuzz
        PACKET_CHUNK_SIZE = 15
        bytes_to_get = min(remaining, PACKET_CHUNK_SIZE)
        ptr_addr = native.native_lib.get_fuzz_ptr(uc_handle, bytes_to_get)

        if ptr_addr is None or ptr_addr == 0:
            _emu_log("[UART_LOOP] Failed to get fuzz - exiting\n")
            uc.reg_write(UC_ARM_REG_PC, 0)
            return True

        raw_fuzz = (ctypes.c_char * bytes_to_get).from_address(ptr_addr).raw

        # Log input for crash reproduction
        _log_input(raw_fuzz)

        # Build next UART packet
        cmd = raw_fuzz[0] if len(raw_fuzz) > 0 else 0x01
        payload = raw_fuzz[1:] if len(raw_fuzz) > 1 else b''

        MAX_PAYLOAD = 250
        if len(payload) > MAX_PAYLOAD:
            payload = payload[:MAX_PAYLOAD]

        seq = _packet_count & 0xFF
        direction = UART_DIR_SENSOR_TO_MCU
        header = bytes([UART_DEV_TYPE, UART_PROTO_VER, seq, direction, cmd])
        packet_len = len(header) + len(payload)
        packet_body = bytes([packet_len]) + header + payload

        crc = _calc_uart_crc(packet_body)
        uart_packet = UART_MAGIC + packet_body + bytes([crc])

        # Write to buffer
        uc.mem_write(FUZZ_BUFFER_ADDR, uart_packet)

        _emu_log(f"[UART_LOOP] Packet {_packet_count + 1}: cmd=0x{cmd:02x}, {len(uart_packet)} bytes\n")
        _log_uart_packet("RX", uart_packet)

        # Set up call to UART_ParsePackets again
        LOOP_ADDR = 0x20018000
        uc.reg_write(UC_ARM_REG_R0, FUZZ_BUFFER_ADDR)
        uc.reg_write(UC_ARM_REG_R1, len(uart_packet))
        uc.reg_write(UC_ARM_REG_LR, LOOP_ADDR | 1)
        uc.reg_write(UC_ARM_REG_PC, 0x0800803c | 1)

        return False  # Continue execution

    except Exception as e:
        _emu_log(f"[UART_LOOP] Error: {e} - exiting\n")
        uc.reg_write(UC_ARM_REG_PC, 0)
        return True


# ============================================================================
# Direct Handler Fuzzing - Bypass UART dispatcher
# ============================================================================
DIRECT_FUZZ_BUFFER = 0x20018100  # Separate buffer for direct handler calls
HANDLER_RETURN_LOOP = 0x20018000  # Return to persistent loop


def fuzz_cmd_0x41(uc):
    """
    Direct fuzzing of HandleCmd_SensorStatusAlt (cmd 0x41).

    Bypasses UART dispatcher - fuzz input is raw payload bytes.
    Handler address: 0x8007c44
    Payload: 9 bytes (status[2] + trigger[2] + battery[1] + reserved[2] + voltage[2])
    """
    from fuzzware_harness import native

    # Install OOB memory hook for crash detection
    install_oob_memory_hook(uc)

    _emu_log("[FUZZ_CMD41] Starting direct handler fuzzing for cmd 0x41\n")

    try:
        uc_handle = uc._uch

        # Trigger input loading by requesting 1 byte first (same pattern as start_uart_fuzzing)
        ptr_addr = native.native_lib.get_fuzz_ptr(uc_handle, 1)

        # Now check how much fuzz is available
        remaining = native.fuzz_remaining()
        _emu_log(f"[FUZZ_CMD41] After trigger: remaining={remaining}\n")

        if ptr_addr is None or ptr_addr == 0:
            _emu_log("[FUZZ_CMD41] No fuzz input available - exiting\n")
            native.do_exit(uc, 0)
            return True

        # Read the first byte that was loaded
        first_byte = (ctypes.c_char * 1).from_address(ptr_addr).raw

        # Get remaining bytes (up to 15 more for total of 16)
        bytes_to_get = min(remaining, 15)
        if bytes_to_get > 0:
            ptr_addr2 = native.native_lib.get_fuzz_ptr(uc_handle, bytes_to_get)
            if ptr_addr2 and ptr_addr2 != 0:
                rest_bytes = (ctypes.c_char * bytes_to_get).from_address(ptr_addr2).raw
                fuzz_data = first_byte + rest_bytes
            else:
                fuzz_data = first_byte
        else:
            fuzz_data = first_byte

        _emu_log(f"[FUZZ_CMD41] Got {len(fuzz_data)} bytes: {fuzz_data.hex()}\n")
        _log_input(fuzz_data)

        # Prepare buffer: payload at offset +4
        buffer = bytearray(20)
        buffer[4:4+len(fuzz_data)] = fuzz_data[:16]
        uc.mem_write(DIRECT_FUZZ_BUFFER, bytes(buffer))

        # Write infinite loop at return address
        uc.mem_write(HANDLER_RETURN_LOOP, b'\xfe\xe7')

        # Set up registers for handler call
        uc.reg_write(UC_ARM_REG_R0, DIRECT_FUZZ_BUFFER)
        uc.reg_write(UC_ARM_REG_LR, HANDLER_RETURN_LOOP | 1)
        uc.reg_write(UC_ARM_REG_PC, 0x8007c44 | 1)  # HandleCmd_SensorStatusAlt

        _emu_log(f"[FUZZ_CMD41] Calling handler at 0x8007c44 with buffer at {DIRECT_FUZZ_BUFFER:#x}\n")

        return False

    except Exception as e:
        import traceback
        _emu_log(f"[FUZZ_CMD41] Error: {e}\n{traceback.format_exc()}\n")
        uc.reg_write(UC_ARM_REG_PC, 0)
        return True


def direct_handler_loop(uc):
    """
    Persistent loop handler for direct handler fuzzing.
    """
    from fuzzware_harness import native

    # Check remaining fuzz input
    remaining = native.fuzz_remaining()

    if remaining <= 0:
        _emu_log("[DIRECT_LOOP] Fuzz exhausted - clean exit\n")
        native.do_exit(uc, 0)
        return True

    # Get next chunk of fuzz
    bytes_to_get = min(remaining, 16)
    try:
        uc_handle = uc._uch
        ptr_addr = native.native_lib.get_fuzz_ptr(uc_handle, bytes_to_get)

        if ptr_addr is None or ptr_addr == 0:
            _emu_log("[DIRECT_LOOP] No more fuzz - exiting\n")
            native.do_exit(uc, 0)
            return True

        fuzz_data = (ctypes.c_char * bytes_to_get).from_address(ptr_addr).raw

        _emu_log(f"[DIRECT_LOOP] Next payload: {fuzz_data.hex()}\n")
        _log_input(fuzz_data)

        # Prepare buffer with new payload
        buffer = bytearray(20)
        buffer[4:4+len(fuzz_data)] = fuzz_data[:16]
        uc.mem_write(DIRECT_FUZZ_BUFFER, bytes(buffer))

        # Re-call handler
        uc.reg_write(UC_ARM_REG_R0, DIRECT_FUZZ_BUFFER)
        uc.reg_write(UC_ARM_REG_LR, HANDLER_RETURN_LOOP | 1)
        uc.reg_write(UC_ARM_REG_PC, 0x8007c44 | 1)

        return False

    except Exception as e:
        _emu_log(f"[DIRECT_LOOP] Error: {e} - exiting\n")
        uc.reg_write(UC_ARM_REG_PC, 0)
        return True
