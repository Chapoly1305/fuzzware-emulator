"""
Heiman Smoke Detector - Project-Specific Hooks

Log files (shared with silabs.py):
- /tmp/firmware.log  - Firmware output (UART TX/RX, prints)
- /tmp/emulator.log  - Emulator debug (hooks, NVM3 traces)
"""
import sys
import os
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_SP

from ...fuzz import get_fuzz

# =============================================================================
# Simple Two-File Logging (same as silabs.py)
# =============================================================================
# DEBUG_MODE: Set to True for verbose logging, False for performance
# When False, all logging is disabled for maximum fuzzing speed
DEBUG_MODE = os.environ.get('DEBUG_MODE', '0') == '1'

FIRMWARE_LOG = os.environ.get('FIRMWARE_LOG', '/tmp/firmware.log')
EMULATOR_LOG = os.environ.get('EMULATOR_LOG', '/tmp/emulator.log')

_firmware_log_file = None
_emulator_log_file = None

def _fw_log(msg):
    """Write to firmware.log (only if DEBUG_MODE)"""
    if not DEBUG_MODE:
        return
    global _firmware_log_file
    if _firmware_log_file is None:
        _firmware_log_file = open(FIRMWARE_LOG, 'a')
    _firmware_log_file.write(msg)
    _firmware_log_file.flush()

def _emu_log(msg):
    """Write to emulator.log (only if DEBUG_MODE)"""
    if not DEBUG_MODE:
        return
    global _emulator_log_file
    if _emulator_log_file is None:
        _emulator_log_file = open(EMULATOR_LOG, 'a')
    _emulator_log_file.write(msg)
    _emulator_log_file.flush()

def _emu_debug_log(msg):
    """Write debug message to emulator.log (only if DEBUG_MODE). Adds newline if missing."""
    if not DEBUG_MODE:
        return
    if not msg.endswith('\n'):
        msg = msg + '\n'
    _emu_log(msg)

# =============================================================================
# Input Logging for Crash Reproduction (Persistent No-Reset Mode)
# =============================================================================

INPUT_LOG_DIR = os.environ.get('FUZZ_INPUT_LOG_DIR', '/tmp/fuzz_inputs')
_input_log = []  # List of (iteration, raw_bytes) tuples
_input_iteration = 0

# TX response counting for verification
_tx_response_count = 0
_rx_packet_count = 0

def get_tx_rx_stats():
    """Return TX/RX statistics for verification"""
    return _tx_response_count, _rx_packet_count

def reset_tx_rx_stats():
    """Reset TX/RX counters"""
    global _tx_response_count, _rx_packet_count
    _tx_response_count = 0
    _rx_packet_count = 0

def increment_tx_count():
    """Increment TX response counter"""
    global _tx_response_count
    _tx_response_count += 1

def increment_rx_count():
    """Increment RX packet counter"""
    global _rx_packet_count
    _rx_packet_count += 1

def _log_input(raw_bytes):
    """Log a fuzz input for later reproduction"""
    global _input_iteration
    _input_iteration += 1
    _input_log.append((_input_iteration, raw_bytes))

    # Keep log bounded to prevent memory exhaustion
    MAX_LOG_SIZE = 100000
    if len(_input_log) > MAX_LOG_SIZE:
        _input_log.pop(0)

def _save_input_log(reason="exit"):
    """Save input log to file for crash reproduction"""
    if not _input_log:
        return

    try:
        os.makedirs(INPUT_LOG_DIR, exist_ok=True)
        import time
        timestamp = int(time.time())
        filename = os.path.join(INPUT_LOG_DIR, f"inputs_{timestamp}_{reason}.log")

        with open(filename, 'w') as f:
            f.write(f"# Fuzz input log - {reason}\n")
            f.write(f"# Total inputs: {len(_input_log)}\n")
            f.write(f"# Format: iteration_number hex_bytes\n\n")
            for iteration, raw_bytes in _input_log:
                f.write(f"{iteration} {raw_bytes.hex()}\n")

        _emu_debug_log(f"[INPUT_LOG] Saved {len(_input_log)} inputs to {filename}")
    except Exception as e:
        _emu_debug_log(f"[INPUT_LOG] Failed to save: {e}")

def _clear_input_log():
    """Clear input log for next fuzzing session"""
    global _input_log, _input_iteration
    _input_log = []
    _input_iteration = 0

def _log_uart_packet(direction, data, notes=""):
    """Log UART packet to emulator.log (only if DEBUG_MODE)"""
    if not DEBUG_MODE:
        return
    if isinstance(data, (bytes, bytearray)):
        hex_data = data.hex()
    else:
        hex_data = str(data)
    _emu_log(f"[UART_{direction}] {hex_data}\n")


# ============================================================================
# Queue intercept to capture UART responses
# ============================================================================

def xQueueGenericSend_intercept(uc):
    """
    Intercept FreeRTOS queue sends to capture UART responses.
    When a response is queued, log it to emulator.log.
    """
    queue_handle = uc.reg_read(UC_ARM_REG_R0)
    item_ptr = uc.reg_read(UC_ARM_REG_R1)

    # Try to read the queued item
    if item_ptr != 0:
        try:
            # Read item data - structure unknown, dump first 64 bytes
            data = uc.mem_read(item_ptr, 64)

            # Check if this looks like a UART response (starts with AA 55 or contains it)
            if b'\xaa\x55' in data:
                idx = data.index(b'\xaa\x55')
                _emu_log(f"[UART_TX] {data[idx:idx+32].hex()}\n")
                increment_tx_count()  # Count TX response
        except Exception as e:
            pass

    # Return pdPASS (1)
    uc.reg_write(UC_ARM_REG_R0, 1)


def QueuePutWrapper_intercept(uc):
    """
    Intercept QueuePutWrapper to capture UART response data.
    This is called when command handlers queue a response.
    """
    # Check UART RX buffer area where response might be built
    try:
        uart_area = uc.mem_read(UART_RX_BUFFER_ADDR, 64)
        if b'\xaa\x55' in uart_area:
            # Find the packet length
            aa55_idx = uart_area.find(b'\xaa\x55')
            if aa55_idx != -1 and aa55_idx + 3 < len(uart_area):
                packet_len = uart_area[aa55_idx + 2] + 4  # length + magic(2) + len(1) + crc
                if aa55_idx + packet_len <= len(uart_area):
                    uart_packet = bytes(uart_area[aa55_idx:aa55_idx + packet_len])
                    _emu_log(f"[UART_TX] {uart_packet.hex()}\n")
    except Exception as e:
        pass

    uc.reg_write(UC_ARM_REG_R0, 0)


# ============================================================================
# UART Protocol Constants
# Protocol: AA 55 <len> <devtype> <proto> <seq> <dir> <cmd> <payload...> <crc>
#
# Direction field (verified from IDA analysis):
#   0x01 = Sensor → MCU (request TO firmware) - checked at 0x8008072
#   0x02 = MCU → Sensor (response FROM firmware) - set at 0x800824e
#
# For fuzzing, we send packets with direction=0x01 (pretending to be the sensor)
# ============================================================================

UART_MAGIC = b'\xAA\x55'
UART_DEV_TYPE = 0x60      # Smoke detector device type
UART_PROTO_VER = 0x06     # Protocol version (firmware checks for 0x06)
UART_DIR_SENSOR_TO_MCU = 0x01  # Sensor → MCU (incoming request)
UART_DIR_MCU_TO_SENSOR = 0x02  # MCU → Sensor (outgoing response)

# UART RX buffer address in RAM (found from firmware analysis)
UART_RX_BUFFER_ADDR = 0x200187EC
UART_RX_BUFFER_SIZE = 256

# Track sequence number
_uart_seq = 0


def _calc_uart_crc(data):
    """Calculate XOR CRC for UART protocol (all bytes after magic)"""
    crc = 0
    for b in data:
        crc ^= b
    return crc


def _wrap_fuzz_as_uart_packet(fuzz_payload, cmd=0x01, direction=UART_DIR_SENSOR_TO_MCU):
    """
    Wrap fuzz payload in UART protocol format.
    Returns complete packet: AA 55 <len> <devtype> <proto> <seq> <dir> <cmd> <payload> <crc>
    """
    global _uart_seq

    payload_len = len(fuzz_payload)
    # Length field = payload_len + 5 (devtype, proto, seq, dir, cmd) + 1 (crc) - but protocol uses different calc
    # From sniffed data: len=02 for 0 payload bytes, len=08 for 6 payload bytes
    # So len = actual_payload_len + header_bytes_after_len
    header_after_len = bytes([UART_DEV_TYPE, UART_PROTO_VER, _uart_seq & 0xFF, direction, cmd])
    packet_len = len(header_after_len) + payload_len

    # Build packet without CRC
    packet_body = bytes([packet_len]) + header_after_len + fuzz_payload

    # Calculate CRC (XOR of all bytes after magic)
    crc = _calc_uart_crc(packet_body)

    # Complete packet
    packet = UART_MAGIC + packet_body + bytes([crc])

    _uart_seq += 1
    return packet


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


# ============================================================================
# Radio Spin-Wait Skip Hooks
# The firmware has 274 infinite loop patterns (fee7 = B .-2) that poll
# hardware registers. These hooks skip the functions containing them.
# ============================================================================

def txCurrentPacket(uc):
    """
    Skip txCurrentPacket @ 0x080067f0
    This function contains a spin-wait loop at 0x080069cc that blocks indefinitely
    waiting for radio TX completion. Skip and return 0 (success).
    """
    _emu_log("[HEIMAN] Skipping txCurrentPacket (radio TX spin-wait)\n")
    uc.reg_write(UC_ARM_REG_R0, 0)  # Return success


def efr32RadioProcess(uc):
    """
    Skip efr32RadioProcess @ 0x08023108
    Main radio processing function that could block on hardware.
    """
    _emu_log("[HEIMAN] Skipping efr32RadioProcess\n")
    uc.reg_write(UC_ARM_REG_R0, 0)


def otPlatRadioTransmit(uc):
    """
    Skip otPlatRadioTransmit @ 0x08022e14
    OpenThread radio transmit - skip hardware interaction.
    Returns OT_ERROR_NONE (0).
    """
    _emu_log("[HEIMAN] Skipping otPlatRadioTransmit\n")
    uc.reg_write(UC_ARM_REG_R0, 0)  # OT_ERROR_NONE


def otPlatRadioReceive(uc):
    """
    Skip otPlatRadioReceive @ 0x08022d0c
    OpenThread radio receive - skip hardware interaction.
    Returns OT_ERROR_NONE (0).
    """
    _emu_log("[HEIMAN] Skipping otPlatRadioReceive\n")
    uc.reg_write(UC_ARM_REG_R0, 0)  # OT_ERROR_NONE


def otPlatRadioSleep(uc):
    """
    Skip otPlatRadioSleep @ 0x08022c94
    Returns OT_ERROR_NONE (0).
    """
    uc.reg_write(UC_ARM_REG_R0, 0)


def otPlatRadioEnable(uc):
    """
    Skip otPlatRadioEnable @ 0x08022c54
    Returns OT_ERROR_NONE (0).
    """
    uc.reg_write(UC_ARM_REG_R0, 0)


def otPlatRadioDisable(uc):
    """
    Skip otPlatRadioDisable @ 0x08022c6c
    Returns OT_ERROR_NONE (0).
    """
    uc.reg_write(UC_ARM_REG_R0, 0)


def radioSetIdle(uc):
    """
    Skip radioSetIdle @ 0x08022298
    Skip radio idle state setup.
    """
    _emu_log("[HEIMAN] Skipping radioSetIdle\n")
    uc.reg_write(UC_ARM_REG_R0, 0)


def efr32RailConfigLoad(uc):
    """
    Skip efr32RailConfigLoad @ 0x08022348
    Skip RAIL configuration loading.
    """
    uc.reg_write(UC_ARM_REG_R0, 0)


def efr32RadioLoadChannelConfig(uc):
    """
    Skip efr32RadioLoadChannelConfig @ 0x08022cc0
    Skip channel configuration loading.
    """
    uc.reg_write(UC_ARM_REG_R0, 0)


def txFailedCallback(uc):
    """
    Skip txFailedCallback @ 0x0802249c
    TX failure callback - skip to avoid recursion into radio code.
    """
    _emu_log("[HEIMAN] Skipping txFailedCallback\n")


def RAILCb_Generic(uc):
    """
    Skip RAILCb_Generic @ 0x080224e0
    Generic RAIL callback - skip hardware interaction.
    """
    _emu_log("[HEIMAN] Skipping RAILCb_Generic\n")


def otPlatRadioGetRssi(uc):
    """
    Skip otPlatRadioGetRssi @ 0x08022f28
    Return a fake RSSI value (-60 dBm = 0xFFFFFFC4 signed).
    """
    uc.reg_write(UC_ARM_REG_R0, 0xFFFFFFC4)  # -60 dBm


def otPlatRadioEnergyScan(uc):
    """
    Skip otPlatRadioEnergyScan @ 0x08022fa0
    Returns OT_ERROR_NOT_IMPLEMENTED (0x17).
    """
    uc.reg_write(UC_ARM_REG_R0, 0x17)


def radioProcessTransmitSecurity(uc):
    """
    Skip radioProcessTransmitSecurity @ 0x080221c8
    Skip security processing for TX.
    Returns OT_ERROR_NONE (0).
    """
    uc.reg_write(UC_ARM_REG_R0, 0)


# ============================================================================
# RAIL (Radio Abstraction Interface Layer) hooks
# ============================================================================

def RAIL_InitTxPowerCurvesAlt(uc):
    """
    Skip RAIL_InitTxPowerCurvesAlt @ 0x0800b898
    Returns RAIL_STATUS_NO_ERROR (0).
    """
    uc.reg_write(UC_ARM_REG_R0, 0)


def RAIL_ConvertDbmToRaw(uc):
    """
    RAIL_ConvertDbmToRaw @ 0x0800b8b8
    Return the input value as-is (identity mapping).
    R0 = railHandle, R1 = power (dBm * 10)
    """
    power = uc.reg_read(UC_ARM_REG_R1)
    uc.reg_write(UC_ARM_REG_R0, power)


def RAIL_ConvertRawToDbm(uc):
    """
    RAIL_ConvertRawToDbm @ 0x0800b9b4
    Return the input value as-is (identity mapping).
    """
    power = uc.reg_read(UC_ARM_REG_R1)
    uc.reg_write(UC_ARM_REG_R0, power)


def sl_rail_util_pa_init(uc):
    """
    Skip sl_rail_util_pa_init @ 0x0800ba78
    """
    uc.reg_write(UC_ARM_REG_R0, 0)


def RAIL_IsInitialized(uc):
    """
    RAIL_IsInitialized @ 0x0804dde0
    Return true (1) to indicate RAIL is "initialized".
    """
    uc.reg_write(UC_ARM_REG_R0, 1)


def RAIL_CalibrateIrAlt(uc):
    """
    Skip RAIL_CalibrateIrAlt @ 0x0804df28
    Returns RAIL_STATUS_NO_ERROR (0).
    """
    uc.reg_write(UC_ARM_REG_R0, 0)


# ============================================================================
# Alarm/Timer hooks for OpenThread
# ============================================================================

_alarm_time_ms = 0

def otPlatAlarmMilliGetNow(uc):
    """
    uint32_t otPlatAlarmMilliGetNow(void)
    Returns current millisecond time for OpenThread alarm.
    """
    global _alarm_time_ms
    _alarm_time_ms += 10  # Increment by 10ms each call
    uc.reg_write(UC_ARM_REG_R0, _alarm_time_ms & 0xFFFFFFFF)


def otPlatAlarmMilliStartAt(uc):
    """
    void otPlatAlarmMilliStartAt(otInstance*, uint32_t t0, uint32_t dt)
    Skip timer setup.
    """
    pass


def otPlatAlarmMilliStop(uc):
    """
    void otPlatAlarmMilliStop(otInstance*)
    Skip timer stop.
    """
    pass


def efr32AlarmInit(uc):
    """
    Skip efr32AlarmInit @ 0x08006708
    Skip alarm initialization.
    """
    pass


# ============================================================================
# Crypto hooks - skip hardware crypto that may spin-wait
# ============================================================================

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
    uc.reg_write(UC_ARM_REG_R0, 0)  # PSA_SUCCESS


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
    uc.reg_write(UC_ARM_REG_R0, 0)  # SL_STATUS_OK


# ============================================================================
# MSC (Flash) wait hooks - skip spin-wait on flash operations
# ============================================================================

def mscStatusWait(uc):
    """
    Skip mscStatusWait @ 0x08006170
    This function spin-waits on flash controller status.
    Returns 0 (no error).
    """
    uc.reg_write(UC_ARM_REG_R0, 0)


def MSC_ErasePage(uc):
    """
    Skip MSC_ErasePage @ 0x08006200
    Returns 0 (success).
    """
    uc.reg_write(UC_ARM_REG_R0, 0)


def MSC_WriteWord(uc):
    """
    Skip MSC_WriteWord @ 0x080062a4
    Returns 0 (success).
    """
    uc.reg_write(UC_ARM_REG_R0, 0)


# ============================================================================
# GPIO IRQ handlers - skip to avoid consuming fuzz input
# ============================================================================

def GPIO_EVEN_IRQHandler(uc):
    """
    Skip GPIO_EVEN_IRQHandler @ 0x08009914
    Prevents GPIO handlers from consuming fuzz input.
    """
    _emu_log("[HEIMAN] Skipping GPIO_EVEN_IRQHandler\n")


def GPIO_ODD_IRQHandler(uc):
    """
    Skip GPIO_ODD_IRQHandler @ 0x08009938
    Prevents GPIO handlers from consuming fuzz input.
    """
    _emu_log("[HEIMAN] Skipping GPIO_ODD_IRQHandler\n")


# ============================================================================
# Direct UART fuzzing - bypass firmware init and fuzz UART_ParsePackets
# ============================================================================

# Buffer in RAM for fuzz data
# UART_ParsePackets loads buffer pointer from 0x08008134 which points to 0x200187EC
# We must write data there for the parser to find it
FUZZ_BUFFER_ADDR = 0x200187EC  # Where UART_ParsePackets expects the RX buffer
FUZZ_BUFFER_SIZE = 256

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
    # Protocol: AA 55 <len> <devtype=0x60> <proto=0x04> <seq> <dir=0x01> <cmd> <payload> <crc>
    cmd = raw_fuzz[0] if len(raw_fuzz) > 0 else 0x01
    payload = raw_fuzz[1:] if len(raw_fuzz) > 1 else b''

    # Build packet
    seq = 0
    direction = UART_DIR_SENSOR_TO_MCU  # 0x01 = Sensor → MCU
    header = bytes([UART_DEV_TYPE, UART_PROTO_VER, seq, direction, cmd])  # devtype, proto, seq, dir, cmd
    packet_len = len(header) + len(payload)
    packet_body = bytes([packet_len]) + header + payload

    # Calculate CRC (XOR of all bytes after magic)
    crc = 0
    for b in packet_body:
        crc ^= b

    # Complete packet with magic and CRC
    uart_packet = b'\xAA\x55' + packet_body + bytes([crc])

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
    direction = UART_DIR_SENSOR_TO_MCU  # 0x01 = Sensor → MCU
    header = bytes([UART_DEV_TYPE, UART_PROTO_VER, seq, direction, cmd])
    packet_len = len(header) + len(payload)
    packet_body = bytes([packet_len]) + header + payload

    crc = 0
    for b in packet_body:
        crc ^= b

    uart_packet = b'\xAA\x55' + packet_body + bytes([crc])

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
    import ctypes
    from fuzzware_harness import native

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
        direction = UART_DIR_SENSOR_TO_MCU  # 0x01 = Sensor → MCU
        header = bytes([UART_DEV_TYPE, UART_PROTO_VER, seq, direction, cmd])
        packet_len = len(header) + len(payload)
        packet_body = bytes([packet_len]) + header + payload

        crc = 0
        for b in packet_body:
            crc ^= b

        uart_packet = b'\xAA\x55' + packet_body + bytes([crc])

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


_discovery_triggered = False

def trigger_fuzz_consumption(uc):
    """
    Early fuzz consumption trigger - consumes fuzz bytes when called.
    Use with do_return: false to continue normal execution after consumption.
    """
    import ctypes
    from fuzzware_harness import native

    _emu_debug_log("[FUZZ] trigger_fuzz_consumption CALLED!")

    try:
        uc_handle = uc._uch

        # Get all remaining fuzz bytes (triggers fuzz consumption tracking)
        remaining = native.fuzz_remaining()
        if remaining > 0:
            # Consume up to 64 bytes of fuzz
            bytes_to_get = min(remaining, 64)
            ptr_addr = native.native_lib.get_fuzz_ptr(uc_handle, bytes_to_get)
            if ptr_addr and ptr_addr != 0:
                fuzz_data = (ctypes.c_char * bytes_to_get).from_address(ptr_addr).raw
                _emu_log(f"[FUZZ_CONSUME] mainInit consumed {len(fuzz_data)} bytes: {fuzz_data[:16].hex()}...\n")
                _emu_debug_log(f"[FUZZ] Consumed {len(fuzz_data)} bytes at mainInit")

    except Exception as e:
        _emu_debug_log(f"[FUZZ] Error: {e}")

    # Continue normal execution


_boot_count = 0
_trace_counter = 0
_mainInit_seen = False


_blocking_count = 0
_fuzz_event_injected = False

def trace_blocking_call(uc):
    """Trace blocking FreeRTOS calls and return timeout to allow progress."""
    global _blocking_count
    _blocking_count += 1

    # Only log first 3 blocking calls to reduce overhead
    if _blocking_count <= 3:
        pc = uc.reg_read(UC_ARM_REG_PC)
        lr = uc.reg_read(UC_ARM_REG_LR)
        _emu_log(f"[BLOCKING #{_blocking_count}] PC=0x{pc:08x} LR=0x{lr:08x}\n")

    # Return pdFALSE (0) = timeout/no message, to avoid processing garbage
    uc.reg_write(UC_ARM_REG_R0, 0)


def osMessageQueueGet_fuzz(uc):
    """
    Hook osMessageQueueGet to inject fuzz data as application events.
    TEMPORARY: Disabled fuzz consumption during boot to allow reaching AppTaskLoop.

    osStatus_t osMessageQueueGet(osMessageQueueId_t mq_id, void *msg_ptr, uint8_t *msg_prio, uint32_t timeout)
    R0 = mq_id, R1 = msg_ptr (output buffer), R2 = msg_prio (output), R3 = timeout

    Returns: osOK (0) if message received, osErrorTimeout (-2) if timeout
    """
    # TEMPORARY: Always return timeout without consuming fuzz during boot
    uc.reg_write(UC_ARM_REG_R0, 0xFFFFFFFE)  # osErrorTimeout = -2


def debug_appinit_reached(uc):
    """Debug hook - print and exit when AppInit is reached."""
    pc = uc.reg_read(UC_ARM_REG_PC)
    lr = uc.reg_read(UC_ARM_REG_LR)
    _emu_debug_log(f"[DEBUG] *** AppInit reached! PC=0x{pc:08x} LR=0x{lr:08x} ***")
    _emu_debug_log(f"[DEBUG] Boot sequence successful - exiting")
    _emu_log(f"[AppInit] Reached SilabsMatterConfig::AppInit at 0x{pc:08x}\n")
    # Force exit
    import os
    os._exit(0)


_app_user_init_seen = False

def println_with_uart_redirect(uc):
    """
    println hook that detects applicationUserInit and redirects to UART fuzzing.
    This bypasses FreeRTOS entirely and goes straight to UART parsing.
    """
    from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_LR, UC_ARM_REG_PC
    import time
    global _app_user_init_seen

    # Read the string pointer from R0
    str_ptr = uc.reg_read(UC_ARM_REG_R0)
    lr = uc.reg_read(UC_ARM_REG_LR)
    pc = uc.reg_read(UC_ARM_REG_PC)

    if str_ptr == 0:
        return

    try:
        # Read string up to 100 chars
        raw_bytes = uc.mem_read(str_ptr, 100)
        null_idx = raw_bytes.find(b'\x00')
        if null_idx != -1:
            raw_bytes = raw_bytes[:null_idx]
        msg = raw_bytes.decode('utf-8', errors='replace')
    except:
        msg = "<error reading string>"

    # Firmware logging disabled for performance - uncomment for debugging:
    # timestamp = time.strftime('%Y-%m-%d, %H:%M:%S', time.localtime())
    # _fw_log(f"[{timestamp}, 0x{pc:08x}] {msg}\n")

    # Check for applicationUserInit - this is the last safe point before FreeRTOS ASSERT
    if "applicationUserInit" in msg and not _app_user_init_seen:
        _app_user_init_seen = True
        # Logging disabled for performance - uncomment for debugging:
        # _emu_log(f"[PRINTLN] Detected applicationUserInit - redirecting to UART fuzzing\n")
        # print(f"[UART_REDIRECT] Detected applicationUserInit - redirecting to UART fuzzing", file=sys.stderr, flush=True)

        # Redirect to UART fuzzing - this bypasses FreeRTOS
        start_uart_fuzzing(uc)
        return True  # Prevent return to normal code


def println_mainInit_redirect(uc):
    """
    println hook that detects mainInit and redirects to UART fuzzing.
    Call this instead of the generic firmware_printf.
    """
    from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_LR, UC_ARM_REG_PC
    import time
    global _mainInit_seen

    # Read the string pointer from R0
    str_ptr = uc.reg_read(UC_ARM_REG_R0)
    lr = uc.reg_read(UC_ARM_REG_LR)

    if str_ptr == 0:
        return

    try:
        # Read string up to 100 chars
        raw_bytes = uc.mem_read(str_ptr, 100)
        null_idx = raw_bytes.find(b'\x00')
        if null_idx != -1:
            raw_bytes = raw_bytes[:null_idx]
        msg = raw_bytes.decode('utf-8', errors='replace')
    except:
        msg = "<error reading string>"

    # Log with timestamp
    timestamp = time.strftime('%Y-%m-%d, %H:%M:%S', time.localtime())
    pc = uc.reg_read(UC_ARM_REG_PC)
    _fw_log(f"[{timestamp}, 0x{pc:08x}] {msg}\n")

    # Check for mainInit
    if "mainInit" in msg and not _mainInit_seen:
        _mainInit_seen = True
        _emu_log(f"[PRINTLN] Detected mainInit - redirecting to UART fuzzing\n")
        _emu_debug_log(f"[PRINTLN] Detected mainInit - will redirect to UART fuzzing")

        # Redirect to UART fuzzing
        start_uart_fuzzing(uc)
        return True  # Skip return (start_uart_fuzzing sets PC)

def debug_trace(uc):
    """Generic trace hook."""
    global _trace_counter
    _trace_counter += 1
    pc = uc.reg_read(UC_ARM_REG_PC)
    if _trace_counter <= 20:  # Only first 20 calls
        _emu_debug_log(f"[TRACE {_trace_counter}] PC=0x{pc:08x}")

def debug_kernel_start(uc):
    """Debug hook to trace when kernel start is called."""
    global _boot_count
    _boot_count += 1
    pc = uc.reg_read(UC_ARM_REG_PC)
    _emu_debug_log(f"[DEBUG BOOT {_boot_count}] _start called at PC=0x{pc:08x}")
    # Continue normally (do_return: false in config)


def debug_scheduler_start(uc):
    """Debug hook to trace when vTaskStartScheduler is called."""
    global _boot_count
    pc = uc.reg_read(UC_ARM_REG_PC)
    _emu_debug_log(f"[DEBUG BOOT {_boot_count}] start() called at PC=0x{pc:08x}")
    # Continue normally (do_return: false in config)


def debug_idle_hook(uc):
    """Debug hook to trace idle task execution."""
    global _boot_count
    _emu_debug_log(f"[DEBUG BOOT {_boot_count}] sl_platform_init called")
    # Continue normally (do_return: false in config)


def debug_kernel_real(uc):
    """Debug hook for the real sl_kernel_start."""
    global _boot_count
    pc = uc.reg_read(UC_ARM_REG_PC)
    _emu_debug_log(f"[DEBUG BOOT {_boot_count}] sl_kernel_start (real) at PC=0x{pc:08x}")


def debug_abort(uc):
    """Debug hook for abort calls."""
    global _boot_count
    pc = uc.reg_read(UC_ARM_REG_PC)
    lr = uc.reg_read(UC_ARM_REG_LR)
    _emu_debug_log(f"[DEBUG BOOT {_boot_count}] ABORT called! PC=0x{pc:08x} LR=0x{lr:08x}")


def debug_assert(uc):
    """Debug hook for assert calls."""
    global _boot_count
    pc = uc.reg_read(UC_ARM_REG_PC)
    lr = uc.reg_read(UC_ARM_REG_LR)
    _emu_debug_log(f"[DEBUG BOOT {_boot_count}] ASSERT failed! PC=0x{pc:08x} LR=0x{lr:08x}")


def start_uart_fuzzing(uc):
    """
    Hook for sl_kernel_start - instead of starting the kernel,
    redirect execution to UART_ParsePackets with fuzz data.

    If input starts with AA 55, treat as raw packet (no wrapping).
    Otherwise, wrap fuzz bytes in UART protocol.
    """
    import sys
    import ctypes
    global _packet_count

    # Install memory hook to detect OOB reads
    install_oob_memory_hook(uc)

    # Reset counters for this fuzzing session
    _packet_count = 0
    global _assert_count, _blocking_count
    _assert_count = 0
    _blocking_count = 0

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
            # This allows ~4 packets from a 64-byte fuzz input
            PACKET_CHUNK_SIZE = 15  # 1 cmd byte + up to 14 payload bytes
            bytes_to_get = min(remaining_after, PACKET_CHUNK_SIZE - 1)  # Already got 1
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

        crc = 0
        for b in packet_body:
            crc ^= b

        uart_packet = b'\xAA\x55' + packet_body + bytes([crc])

    # Write to buffer
    uc.mem_write(FUZZ_BUFFER_ADDR, uart_packet)

    _emu_log(f"[UART_FUZZ] Prepared {len(uart_packet)} byte packet: {uart_packet.hex()}\n")

    # Log UART RX packet to file with formatting
    _log_uart_packet("RX", uart_packet, "Fuzz input wrapped with UART protocol")

    # Simply set up registers and branch to UART_ParsePackets
    # The hook patches the function with bx lr, so we set LR to our infinite loop
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

    # Return False to let execution continue at new PC (not the patched bx lr)
    return False


# ============================================================================
# Persistent Fuzzing Loop Handler
# ============================================================================

_packet_count = 0


def _trigger_uart_tx(uc, tx_func_addr):
    """
    Trigger UART_DoTransmit to send any pending TX response.

    This function saves current state, calls UART_DoTransmit, and restores state.
    UART_DoTransmit reads response data from globals and sends via UARTDRV_ForceTransmit.
    """
    from unicorn.arm_const import UC_ARM_REG_PC, UC_ARM_REG_LR, UC_ARM_REG_SP

    # Save current registers
    saved_pc = uc.reg_read(UC_ARM_REG_PC)
    saved_lr = uc.reg_read(UC_ARM_REG_LR)

    # Set up return address to a safe location (we'll catch it)
    RETURN_ADDR = 0x20018100  # Unused RAM location

    try:
        # Write return instruction at return address
        uc.mem_write(RETURN_ADDR, b'\x70\x47')  # BX LR (return)

        # Set up call to UART_DoTransmit
        uc.reg_write(UC_ARM_REG_LR, RETURN_ADDR | 1)  # Thumb mode
        uc.reg_write(UC_ARM_REG_PC, tx_func_addr | 1)  # Thumb mode

        # Execute until return
        try:
            uc.emu_start(tx_func_addr | 1, RETURN_ADDR, timeout=100000, count=10000)
        except Exception as e:
            _emu_log(f"[UART_TX_TRIGGER] Execution ended: {e}\n")

    except Exception as e:
        _emu_log(f"[UART_TX_TRIGGER] Error: {e}\n")

    # Restore PC (LR doesn't need restoring as we're in the loop handler)
    uc.reg_write(UC_ARM_REG_PC, saved_pc)


def uart_persistent_loop(uc):
    """
    Persistent loop handler for UART fuzzing.

    This hook is triggered when UART_ParsePackets returns (at LOOP_ADDR).
    It checks for remaining fuzz input and either:
    - Processes another packet if fuzz remains
    - Exits cleanly if fuzz is exhausted

    This avoids the snapshot/restore overhead for multi-packet fuzzing.
    """
    import ctypes
    import sys
    from fuzzware_harness import native
    global _packet_count

    _packet_count += 1

    # Check remaining fuzz input
    remaining = native.fuzz_remaining()

    if remaining == 0:
        # Trigger TX for the last packet before exiting
        # (nested emu_start causes issues with multi-packet processing,
        # so only do this on the final packet)
        UART_DO_TRANSMIT_ADDR = 0x8008294
        _trigger_uart_tx(uc, UART_DO_TRANSMIT_ADDR)
        # Print TX/RX stats for verification
        tx_count, rx_count = get_tx_rx_stats()
        _emu_debug_log(f"[STATS] RX packets: {_packet_count}, TX responses: {tx_count}")

        # No more fuzz - exit cleanly
        _emu_log(f"[UART_LOOP] Processed {_packet_count} packets, fuzz exhausted - exiting\n")
        # Save input log for this session (useful for persistent no-reset mode)
        _save_input_log("fuzz_exhausted")
        _clear_input_log()
        # Use do_exit for clean exit (returns UC_ERR_OK instead of SIGSEGV)
        # This is important for persistent mode to work correctly with AFL
        native.do_exit(uc, 0)  # 0 = UC_ERR_OK (clean exit)
        return True

    _emu_log(f"[UART_LOOP] Packet {_packet_count} done, {remaining} fuzz bytes remaining - processing next\n")

    try:
        uc_handle = uc._uch

        # Get next chunk of fuzz - limit to 15 bytes per packet
        PACKET_CHUNK_SIZE = 15  # 1 cmd byte + up to 14 payload bytes
        bytes_to_get = min(remaining, PACKET_CHUNK_SIZE)
        ptr_addr = native.native_lib.get_fuzz_ptr(uc_handle, bytes_to_get)

        if ptr_addr is None or ptr_addr == 0:
            _emu_log("[UART_LOOP] Failed to get fuzz - exiting\n")
            uc.reg_write(UC_ARM_REG_PC, 0)
            return True

        raw_fuzz = (ctypes.c_char * bytes_to_get).from_address(ptr_addr).raw

        # Log input for crash reproduction (persistent no-reset mode)
        _log_input(raw_fuzz)

        # Build next UART packet
        cmd = raw_fuzz[0] if len(raw_fuzz) > 0 else 0x01
        payload = raw_fuzz[1:] if len(raw_fuzz) > 1 else b''

        MAX_PAYLOAD = 250
        if len(payload) > MAX_PAYLOAD:
            payload = payload[:MAX_PAYLOAD]

        seq = _packet_count & 0xFF
        direction = UART_DIR_SENSOR_TO_MCU  # 0x01 = Sensor → MCU
        header = bytes([UART_DEV_TYPE, UART_PROTO_VER, seq, direction, cmd])
        packet_len = len(header) + len(payload)
        packet_body = bytes([packet_len]) + header + payload

        crc = 0
        for b in packet_body:
            crc ^= b

        uart_packet = b'\xAA\x55' + packet_body + bytes([crc])

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

        return False  # Continue execution at UART_ParsePackets

    except Exception as e:
        _emu_log(f"[UART_LOOP] Error: {e} - exiting\n")
        uc.reg_write(UC_ARM_REG_PC, 0)
        return True


# ============================================================================
# Trace hooks for debugging FreeRTOS boot sequence
# ============================================================================

def bypass_stackoverflow_hook(uc):
    """Bypass vApplicationStackOverflowHook - prevent ASSERT message and loop."""
    pc = uc.reg_read(UC_ARM_REG_PC)
    lr = uc.reg_read(UC_ARM_REG_LR)
    _emu_debug_log(f"[STACKOVERFLOW_BYPASS] Hook triggered at PC=0x{pc:08x} LR=0x{lr:08x}")
    _emu_log(f"[STACKOVERFLOW_BYPASS] vApplicationStackOverflowHook bypassed, caller=0x{lr:08x}\n")
    # Return immediately - don't let the function execute
    uc.reg_write(UC_ARM_REG_R0, 0)


_assert_count = 0

def force_return_from_assert_loop(uc):
    """
    Force return from ASSERT infinite loop by setting PC to LR.
    This breaks out of the while(1){} loop after ASSERT message.

    After first assertion, exit cleanly since the system is broken.
    """
    global _assert_count
    _assert_count += 1

    # Log only the first assert (reduce logging overhead)
    if _assert_count == 1:
        pc = uc.reg_read(UC_ARM_REG_PC)
        lr = uc.reg_read(UC_ARM_REG_LR)
        _emu_log(f"[ASSERT] First assert at PC=0x{pc:08x}, LR=0x{lr:08x} - exiting\n")
        # Save input log on crash for reproduction
        _save_input_log("assert_crash")

    # Exit immediately on any assert - system is broken
    # Use PC=0 to trigger clean exit
    uc.reg_write(UC_ARM_REG_PC, 0)
    return True


def trace_vStartFirstTask(uc):
    """Trace hook for vStartFirstTask - this starts the first FreeRTOS task."""
    pc = uc.reg_read(UC_ARM_REG_PC)
    lr = uc.reg_read(UC_ARM_REG_LR)
    _emu_debug_log(f"[FREERTOS] vStartFirstTask called! PC=0x{pc:08x} LR=0x{lr:08x}")


def trace_osKernelStart(uc):
    """Trace hook for osKernelStart - CMSIS-RTOS kernel start."""
    pc = uc.reg_read(UC_ARM_REG_PC)
    lr = uc.reg_read(UC_ARM_REG_LR)
    _emu_debug_log(f"[FREERTOS] osKernelStart called! PC=0x{pc:08x} LR=0x{lr:08x}")


def trace_vTaskStartScheduler(uc):
    """Trace hook for vTaskStartScheduler - starts FreeRTOS scheduler."""
    pc = uc.reg_read(UC_ARM_REG_PC)
    lr = uc.reg_read(UC_ARM_REG_LR)
    _emu_debug_log(f"[FREERTOS] vTaskStartScheduler called! PC=0x{pc:08x} LR=0x{lr:08x}")


def trace_AppTaskLoop(uc):
    """Trace hook for AppTaskLoop - main application task."""
    pc = uc.reg_read(UC_ARM_REG_PC)
    lr = uc.reg_read(UC_ARM_REG_LR)
    _emu_debug_log(f"[FREERTOS] AppTaskLoop called! PC=0x{pc:08x} LR=0x{lr:08x}")


def trace_StartJoinHandler(uc):
    """Trace hook for StartJoinHandler - Zigbee join start."""
    pc = uc.reg_read(UC_ARM_REG_PC)
    lr = uc.reg_read(UC_ARM_REG_LR)
    _emu_debug_log(f"[FREERTOS] StartJoinHandler called! PC=0x{pc:08x} LR=0x{lr:08x}")


def trace_xTaskCreateStatic(uc):
    """Trace hook for xTaskCreateStatic - task creation."""
    pc = uc.reg_read(UC_ARM_REG_PC)
    lr = uc.reg_read(UC_ARM_REG_LR)
    _emu_debug_log(f"[FREERTOS] xTaskCreateStatic called! PC=0x{pc:08x} LR=0x{lr:08x}")


def trace_ram_callback(uc):
    """Debug trace when execution reaches RAM callback at 0x20002cb0."""
    pc = uc.reg_read(UC_ARM_REG_PC)
    lr = uc.reg_read(UC_ARM_REG_LR)
    sp = uc.reg_read(UC_ARM_REG_SP)
    r0 = uc.reg_read(UC_ARM_REG_R0)
    _emu_debug_log(f"[RAM_CALLBACK] Hit 0x20002cb0! PC=0x{pc:08x} LR=0x{lr:08x} SP=0x{sp:08x} R0=0x{r0:08x}")
    # Read first few bytes at this address to see what code is there
    try:
        code = uc.mem_read(0x20002cb0, 8)
        _emu_debug_log(f"[RAM_CALLBACK] Code at 0x20002cb0: {code.hex()}")
    except:
        _emu_debug_log(f"[RAM_CALLBACK] Could not read code at 0x20002cb0")


def skip_ram_callback(uc):
    """Skip execution at uninitialized RAM callback - return to caller."""
    lr = uc.reg_read(UC_ARM_REG_LR)
    # Set PC to LR to return from this "function"
    uc.reg_write(UC_ARM_REG_PC, lr)
    # Return False to continue execution at the new PC
    return False


def sl_sleeptimer_get_timer_frequency_high(uc):
    """
    Return high frequency for FreeRTOS configTICK_RATE_HZ check.
    Some firmware uses tick rates > 32768 Hz, so return 1MHz.
    """
    uc.reg_write(UC_ARM_REG_R0, 1000000)  # 1MHz


# ============================================================================
# NVM3 Bypass Hooks - Skip NVM3 and return appropriate responses to Matter
# ============================================================================

# NVM3 Error Codes - Simple integer values (NOT full ECODE format)
# These are the raw values returned by nvm3_* functions
NVM3_OK = 0              # Success
NVM3_ERR_KEY_NOT_FOUND = 45   # Key not found (objGroupDeleted)
NVM3_ERR_NOT_OPENED = 17      # NVM3 not opened
NVM3_ERR_NULL_HANDLE = 33     # NULL handle
NVM3_ERR_KEY_INVALID = 41     # Invalid key (>= 0x100000)


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
    # This prevents "NVM3 not opened" errors (error code 17)
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

    Structure (from GSDK):
    typedef struct {
        uint16_t deviceFamily;    // Device family ID
        uint8_t  writeSize;       // Write granularity (bytes)
        uint8_t  memoryMapped;    // Non-zero if memory mapped
        size_t   pageSize;        // Flash page size (bytes)
        uint32_t systemPartStart; // Start of system partition
        uint32_t systemPartEnd;   // End of system partition
        uint32_t userPartStart;   // Start of user partition
        uint32_t userPartEnd;     // End of user partition
    } nvm3_HalFlashInfo_t;

    For MG24:
    - Page size: 8KB (0x2000)
    - Write size: 4 bytes
    - Memory mapped: 1 (yes)
    """
    import struct

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
    # uint16_t deviceFamily, uint8_t writeSize, uint8_t memoryMapped,
    # size_t pageSize (4 bytes on ARM), 4x uint32_t
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


# ============================================================================
# UART TX Capture Hooks - Capture firmware responses
# ============================================================================

def UART_BuildAndSendTx(uc):
    """
    Hook UART_BuildAndSendTx to capture TX packets.
    This is the main function that builds and sends UART responses.

    void UART_BuildAndSendTx(uint8_t cmd, uint8_t seq, uint16_t len, uint8_t *data)
    R0 = cmd, R1 = seq, R2 = len, R3 = data pointer
    """
    # Note: Don't count here - count at UARTDRV_ForceTransmit_hook instead
    # to avoid double counting

    cmd = uc.reg_read(UC_ARM_REG_R0)
    seq = uc.reg_read(UC_ARM_REG_R1)
    length = uc.reg_read(UC_ARM_REG_R2)
    data_ptr = uc.reg_read(UC_ARM_REG_R3)

    # Debug: only print if DEBUG_MODE
    _emu_debug_log(f"[UART_TX_HOOK] UART_BuildAndSendTx called: cmd=0x{cmd:02x}, seq=0x{seq:02x}, len={length}")

    _emu_log(f"[UART_TX] UART_BuildAndSendTx: cmd=0x{cmd:02x}, data_ptr=0x{data_ptr:08x}, len={length}\n")

    if data_ptr != 0 and length > 0 and length < 512:
        try:
            data = uc.mem_read(data_ptr, length)
            _emu_log(f"[UART_TX] Data: {data.hex()}\n")
        except Exception as e:
            _emu_log(f"[UART_TX] Error reading data: {e}\n")

    # Continue execution - don't skip the function
    return False


def UART_DoTransmit(uc):
    """
    Hook UART_DoTransmit to capture low-level TX.
    This hooks the BL UARTDRV_ForceTransmit at 0x80081f2 where:
    - R0 = UART handle
    - R1 = buffer pointer
    - R2 = length
    """
    buffer_ptr = uc.reg_read(UC_ARM_REG_R1)  # R1 = buffer
    length = uc.reg_read(UC_ARM_REG_R2)      # R2 = length

    _emu_log(f"[UART_TX] UART_DoTransmit: buffer=0x{buffer_ptr:08x}, len={length}\n")

    if buffer_ptr != 0 and length > 0 and length < 512:
        try:
            data = uc.mem_read(buffer_ptr, length)
            _emu_log(f"[UART_TX] TX packet: {data.hex()}\n")
            _log_uart_packet("TX", data, "Response from firmware")
            increment_tx_count()  # Count actual TX response
        except Exception as e:
            _emu_log(f"[UART_TX] Error reading buffer: {e}\n")

    # Continue execution
    return False


def TxCmd_Status(uc):
    """
    Hook TxCmd_Status to capture status responses.
    void TxCmd_Status(void)
    """
    _emu_log("[UART_TX] TxCmd_Status - sending status response\n")
    # Continue execution
    return False


def EUSART_Tx(uc):
    """
    Hook low-level EUSART_Tx to capture individual bytes being sent.
    void EUSART_Tx(EUSART_TypeDef *eusart, uint8_t data)
    R0 = eusart peripheral, R1 = byte to send
    """
    byte_val = uc.reg_read(UC_ARM_REG_R1) & 0xFF
    _emu_log(f"[EUSART_TX] 0x{byte_val:02x}\n")
    # Continue - let the real function execute
    return False


def UARTDRV_ForceTransmit_hook(uc):
    """
    Hook UARTDRV_ForceTransmit to capture TX data without hardware access.

    Ecode_t UARTDRV_ForceTransmit(UARTDRV_Handle_t handle, uint8_t *data, UARTDRV_Count_t count)
    R0 = UART handle, R1 = data buffer, R2 = count (length)
    Returns: ECODE_EMDRV_UARTDRV_OK (0)
    """
    handle = uc.reg_read(UC_ARM_REG_R0)
    buffer_ptr = uc.reg_read(UC_ARM_REG_R1)
    length = uc.reg_read(UC_ARM_REG_R2)

    _emu_log(f"[UARTDRV_ForceTransmit] handle=0x{handle:08x}, buffer=0x{buffer_ptr:08x}, len={length}\n")

    if buffer_ptr != 0 and length > 0 and length < 512:
        try:
            data = uc.mem_read(buffer_ptr, length)
            _emu_log(f"[UART_TX] {data.hex()}\n")
            _log_uart_packet("TX", data, "Response from firmware via ForceTransmit")
            increment_tx_count()

            # Only print to log if DEBUG_MODE for performance
            _emu_debug_log(f"[UART_TX] {data.hex()}")
        except Exception as e:
            _emu_log(f"[UARTDRV_ForceTransmit] Error reading buffer: {e}\n")

    # Return ECODE_EMDRV_UARTDRV_OK (0) - skip hardware access
    uc.reg_write(UC_ARM_REG_R0, 0)


# ============================================================================
# OOB Read Tracing - Verify V1 vulnerability at runtime
# ============================================================================

UART_BUFFER_ADDR = 0x200187EC
UART_BUFFER_SIZE = 128


def trace_handler_muting(uc):
    """Hook HandleCmd_Muting at 0x8007CD8 - see what payload it receives

    When DEBUG_MODE is set and shell is enabled, drops to ipdb for interactive debugging.
    """
    r0 = uc.reg_read(UC_ARM_REG_R0)  # a1 = payload byte
    _emu_debug_log(f"[HANDLER] HandleCmd_Muting called with payload byte: 0x{r0:02x} ({r0})")

    # Drop to ipdb shell if shell mode is enabled
    # NOTE: These prints must go to stderr for interactive ipdb session
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


# Memory hook to detect OOB reads past the UART buffer
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
    from unicorn.arm_const import UC_ARM_REG_R6
    r6 = uc.reg_read(UC_ARM_REG_R6)  # cmd
    _emu_debug_log(f"[FLOW_TRACE] Reached 0x80080A8 (after log), cmd=0x{r6:02x}")
    return False


def trace_beq_cmd5(uc):
    """Hook at 0x80080AA - BEQ loc_800812C (branch if cmd==5)"""
    from unicorn.arm_const import UC_ARM_REG_R6, UC_ARM_REG_PC
    r6 = uc.reg_read(UC_ARM_REG_R6)
    pc = uc.reg_read(UC_ARM_REG_PC)
    _emu_debug_log(f"[FLOW_TRACE] At 0x80080AA (BEQ cmd==5), R6=0x{r6:02x}, PC=0x{pc:08x}")
    # Check condition: if R6 == 5, branch will be taken
    if r6 == 5:
        _emu_debug_log(f"[FLOW_TRACE] >>> BRANCH WILL BE TAKEN (cmd==5)! <<<")
    else:
        _emu_debug_log(f"[FLOW_TRACE] >>> BRANCH NOT TAKEN, continuing to 0x80080AC <<<")
    return False


def trace_after_magic_check(uc):
    """Hook at 0x8008054 - after entering loop, checking first byte"""
    from unicorn.arm_const import UC_ARM_REG_R4, UC_ARM_REG_R5
    r4 = uc.reg_read(UC_ARM_REG_R4)
    r5 = uc.reg_read(UC_ARM_REG_R5)
    _emu_debug_log(f"[FLOW_TRACE] At 0x8008054 (loop start), i={r4}, buffer=0x{r5:08x}")
    return False


def trace_after_validation(uc):
    """Hook at 0x8008074 - after all header validations pass"""
    from unicorn.arm_const import UC_ARM_REG_R4, UC_ARM_REG_R5
    r4 = uc.reg_read(UC_ARM_REG_R4)
    _emu_debug_log(f"[FLOW_TRACE] At 0x8008074 (validations PASSED!), i={r4}")
    return False


def trace_ldrb_length(uc):
    """Hook at 0x8008078 - LDRB.W R8, [R5,R11] (read length field)"""
    from unicorn.arm_const import UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R11
    r4 = uc.reg_read(UC_ARM_REG_R4)
    r5 = uc.reg_read(UC_ARM_REG_R5)
    r11 = uc.reg_read(UC_ARM_REG_R11)
    _emu_debug_log(f"[FLOW_TRACE] At 0x8008078, i={r4}, R5=0x{r5:08x}, R11={r11}")
    # Read the length byte
    try:
        length = uc.mem_read(r5 + r11, 1)[0]
        _emu_debug_log(f"[FLOW_TRACE]   Length field: {length} (0x{length:02x})")
    except:
        _emu_debug_log(f"[FLOW_TRACE]   Could not read length")
    return False


def trace_before_crc_calc(uc):
    """Hook at 0x8008086 - BL calculate_crc"""
    from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1
    r0 = uc.reg_read(UC_ARM_REG_R0)
    r1 = uc.reg_read(UC_ARM_REG_R1)
    _emu_debug_log(f"[FLOW_TRACE] At 0x8008086 (calling calculate_crc), buffer=0x{r0:08x}, size={r1}")
    return False


def trace_validation_failed(uc):
    """Hook at 0x80080C2 - validation failed path"""
    from unicorn.arm_const import UC_ARM_REG_R4
    r4 = uc.reg_read(UC_ARM_REG_R4)
    _emu_debug_log(f"[FLOW_TRACE] At 0x80080C2 (validation FAILED), i={r4}")
    return False


def trace_crc_check(uc):
    """Hook at 0x80080AC - ADD R9, R5 (setup for CRC read)"""
    _emu_debug_log(f"[FLOW_TRACE] Reached 0x80080AC (CRC setup)")
    return False


def trace_after_crc_read(uc):
    """Hook at 0x80080B2 - CMP R2, R7 (after CRC read)"""
    from unicorn.arm_const import UC_ARM_REG_R2, UC_ARM_REG_R7
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
    # Log to verify hook is called
    _emu_debug_log("[OOB_TRACE] >>> Hook triggered at 0x80080AE <<<")

    from unicorn.arm_const import UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R8, UC_ARM_REG_R9

    r4 = uc.reg_read(UC_ARM_REG_R4)   # i (loop index)
    r5 = uc.reg_read(UC_ARM_REG_R5)   # buffer base
    r8 = uc.reg_read(UC_ARM_REG_R8)   # length from packet
    r9 = uc.reg_read(UC_ARM_REG_R9)   # i + 7

    # CRC will be read from: R5 + R9 + R8 = buffer + (i+7) + length
    crc_offset = (r9 - r5) + r8  # offset from buffer start
    crc_addr = r5 + crc_offset

    is_oob = crc_offset >= UART_BUFFER_SIZE

    # Log trace (only if DEBUG_MODE)
    _emu_debug_log(f"[OOB_TRACE] CRC read: i={r4}, length={r8}, offset={crc_offset}, addr=0x{crc_addr:08x}")

    if is_oob:
        oob_bytes = crc_offset - UART_BUFFER_SIZE
        _emu_debug_log(f"[OOB_TRACE] *** OUT-OF-BOUNDS READ: {oob_bytes} bytes past buffer! ***")

        # Try to read what's at the OOB address
        try:
            oob_value = uc.mem_read(crc_addr, 1)[0]
            _emu_debug_log(f"[OOB_TRACE] Value at OOB address 0x{crc_addr:08x}: 0x{oob_value:02x}")
        except Exception as e:
            _emu_debug_log(f"[OOB_TRACE] Failed to read OOB address: {e}")

    # Continue execution (don't skip the instruction)
    return False
