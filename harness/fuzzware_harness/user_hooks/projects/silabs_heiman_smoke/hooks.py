"""
Heiman Smoke Detector - Project-Specific Hooks

Custom hooks for Heiman Smoke Detector firmware (Silicon Labs EFR32MG1x Zigbee).
This module provides device-specific UART protocol handling, radio hardware bypass,
and firmware-specific hooks for the Heiman smoke detector.

Features:
- UART protocol fuzzing with custom packet format (0xAA55 magic, CRC)
- Radio/RAIL/Zigbee hardware bypass hooks
- Crypto, flash, and GPIO hooks for EFR32MG1x
- Interrupt injection and queue interception
"""
import sys
import os
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_SP

# Import fuzz input functions (note: three dots for projects subdirectory)
from ...fuzz import get_fuzz

# Log file paths
LOG_FILE_PATH = os.environ.get('FUZZWARE_LOG_FILE', '/tmp/fuzzware_heiman.log')
UART_LOG_FILE = os.environ.get('UART_LOG_FILE', '/tmp/uart_txrx.log')
_log_file = None
_uart_log_file = None
_log_enabled = os.environ.get('FUZZWARE_LOG_LEVEL', 'WARN').upper() in ('DEBUG', 'INFO')

def _get_log_file():
    """Get or create the log file handle"""
    global _log_file
    if _log_file is None:
        _log_file = open(LOG_FILE_PATH, 'a')
    return _log_file

def _log(msg):
    """Write message to log file if enabled"""
    if _log_enabled:
        f = _get_log_file()
        f.write(msg)
        f.flush()


def _get_uart_log_file():
    """Get or create the UART log file handle"""
    global _uart_log_file
    if _uart_log_file is None:
        _uart_log_file = open(UART_LOG_FILE, 'a')
        # Write CSV header if file is new/empty
        try:
            if os.path.getsize(UART_LOG_FILE) == 0:
                _uart_log_file.write("timestamp,direction,hex\n")
        except:
            _uart_log_file.write("timestamp,direction,hex\n")
    return _uart_log_file


def _log_uart_packet(direction, data, notes=""):
    """
    Log UART packet to CSV file

    Args:
        direction: "RX" or "TX" (from firmware perspective)
        data: bytes, bytearray, or hex string
        notes: ignored (for compatibility)
    """
    import time

    f = _get_uart_log_file()
    timestamp = f"{time.time():.3f}"

    # Convert to hex string without spaces
    if isinstance(data, (bytes, bytearray)):
        hex_data = data.hex()
    elif isinstance(data, str):
        hex_data = data.replace(" ", "").replace("0x", "")
    else:
        hex_data = ""

    # Write CSV line: timestamp,direction,hex
    f.write(f"{timestamp},{direction},{hex_data}\n")
    f.flush()


# ============================================================================
# Queue intercept to capture UART responses
# ============================================================================

def xQueueGenericSend_intercept(uc):
    """
    Intercept FreeRTOS queue sends to capture UART responses.
    When a response is queued, print it and optionally call TX directly.
    """
    import sys

    queue_handle = uc.reg_read(UC_ARM_REG_R0)
    item_ptr = uc.reg_read(UC_ARM_REG_R1)
    ticks_to_wait = uc.reg_read(UC_ARM_REG_R2)
    copy_position = uc.reg_read(UC_ARM_REG_R3)

    print(f"[QUEUE_TX] xQueueGenericSend: queue={queue_handle:#x}, item={item_ptr:#x}", file=sys.stderr, flush=True)

    # Try to read the queued item
    if item_ptr != 0:
        try:
            # Read item data - structure unknown, dump first 64 bytes
            data = uc.mem_read(item_ptr, 64)
            print(f"[QUEUE_TX] Queued data: {data.hex()}", file=sys.stderr, flush=True)

            # Check if this looks like a UART response (starts with AA 55 or contains it)
            if b'\xaa\x55' in data:
                idx = data.index(b'\xaa\x55')
                print(f"[QUEUE_TX] Found UART packet at offset {idx}: {data[idx:idx+32].hex()}", file=sys.stderr, flush=True)
        except Exception as e:
            print(f"[QUEUE_TX] Error reading item: {e}", file=sys.stderr, flush=True)

    # Return pdPASS (1)
    uc.reg_write(UC_ARM_REG_R0, 1)


def QueuePutWrapper_intercept(uc):
    """
    Intercept QueuePutWrapper to capture UART response data.
    This is called when command handlers queue a response.

    Based on analysis: R0 points to a message structure, R1=0x68 might be cmd/type,
    R2=0x5 might be payload length, R3 is callback.
    """
    import sys

    r0 = uc.reg_read(UC_ARM_REG_R0)
    r1 = uc.reg_read(UC_ARM_REG_R1)
    r2 = uc.reg_read(UC_ARM_REG_R2)
    r3 = uc.reg_read(UC_ARM_REG_R3)
    sp = uc.reg_read(UC_ARM_REG_SP)

    print(f"[UART_RESPONSE] QueuePutWrapper: R0={r0:#x} R1={r1:#x} R2={r2:#x} R3={r3:#x} SP={sp:#x}", file=sys.stderr, flush=True)

    # R1 might be command/event type (0x68 = 104 = 'h' or some event ID)
    # R2 might be data length
    # Let's dump the structure at R0 more carefully
    if 0x20000000 <= r0 <= 0x20020000:
        try:
            # Read first 128 bytes of the structure
            struct_data = uc.mem_read(r0, 128)
            print(f"[UART_RESPONSE] Structure at R0:", file=sys.stderr, flush=True)
            # Print in 16-byte rows
            for i in range(0, 128, 16):
                row = struct_data[i:i+16]
                hex_str = ' '.join(f'{b:02x}' for b in row)
                print(f"  +{i:02x}: {hex_str}", file=sys.stderr, flush=True)
        except Exception as e:
            print(f"[UART_RESPONSE] Error reading structure: {e}", file=sys.stderr, flush=True)

    # Also check stack for pushed parameters
    if 0x20000000 <= sp <= 0x20020000:
        try:
            stack_data = uc.mem_read(sp, 32)
            print(f"[UART_RESPONSE] Stack: {stack_data.hex()}", file=sys.stderr, flush=True)
        except:
            pass

    # Check UART RX buffer area where response might be built
    try:
        uart_area = uc.mem_read(UART_RX_BUFFER_ADDR, 64)
        if b'\xaa\x55' in uart_area:
            print(f"[UART_RESPONSE] UART buffer: {uart_area.hex()}", file=sys.stderr, flush=True)

            # Log UART TX packet to file with formatting
            # Find the packet length
            aa55_idx = uart_area.find(b'\xaa\x55')
            if aa55_idx != -1 and aa55_idx + 3 < len(uart_area):
                packet_len = uart_area[aa55_idx + 2] + 4  # length byte + magic(2) + len(1) + crc(2) - 1
                if aa55_idx + packet_len <= len(uart_area):
                    uart_packet = bytes(uart_area[aa55_idx:aa55_idx + packet_len])
                    _log_uart_packet("TX", uart_packet, "Firmware response captured via QueuePutWrapper")
    except Exception as e:
        # Log errors but don't crash the emulator
        print(f"[UART_TX_ERROR] Failed to log TX packet: {e}", file=sys.stderr, flush=True)

    uc.reg_write(UC_ARM_REG_R0, 0)


# ============================================================================
# UART Protocol Constants
# Protocol: AA 55 <len> <devtype> <proto> <seq> <dir> <cmd> <payload...> <crc>
# ============================================================================

UART_MAGIC = b'\xAA\x55'
UART_DEV_TYPE = 0x60      # Smoke detector device type
UART_PROTO_VER = 0x06     # Protocol version (firmware checks for 0x06)
UART_DIR_TO_SENSOR = 0x01 # Direction: host -> sensor
UART_DIR_FROM_SENSOR = 0x02

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


def _wrap_fuzz_as_uart_packet(fuzz_payload, cmd=0x01, direction=UART_DIR_TO_SENSOR):
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
    Hook UARTDRV_Receive to inject fuzz input as UART protocol messages.

    Ecode_t UARTDRV_Receive(UARTDRV_Handle_t handle, uint8_t *data, UARTDRV_Count_t count, UARTDRV_Callback_t callback)
    R0 = handle, R1 = data buffer, R2 = count (max bytes to receive), R3 = callback

    This hook:
    1. Gets fuzz input bytes
    2. Wraps them in UART protocol format
    3. Writes to the provided buffer
    4. Returns success
    """
    buffer_ptr = uc.reg_read(UC_ARM_REG_R1)
    max_count = uc.reg_read(UC_ARM_REG_R2)

    if buffer_ptr == 0 or max_count == 0:
        uc.reg_write(UC_ARM_REG_R0, 0)  # Return success but no data
        return

    # Get fuzz input - request raw bytes for payload
    # Limit payload to reasonable size
    fuzz_size = min(max_count - 10, 64)  # Leave room for protocol overhead
    if fuzz_size <= 0:
        fuzz_size = 1

    # Get fuzz bytes
    fuzz_payload = get_fuzz(uc, fuzz_size)
    if fuzz_payload is None or len(fuzz_payload) == 0:
        # No more fuzz input
        uc.reg_write(UC_ARM_REG_R0, 0)
        return

    # Wrap in UART protocol
    # Use first fuzz byte as command if available, otherwise default
    cmd = fuzz_payload[0] if len(fuzz_payload) > 0 else 0x01
    payload = fuzz_payload[1:] if len(fuzz_payload) > 1 else b''

    uart_packet = _wrap_fuzz_as_uart_packet(payload, cmd=cmd)

    # Write to buffer (truncate if needed)
    write_len = min(len(uart_packet), max_count)
    uc.mem_write(buffer_ptr, uart_packet[:write_len])

    _log(f"[UART] Injected {write_len} bytes: {uart_packet[:write_len].hex()}\n")

    # Log UART RX packet to file with formatting
    _log_uart_packet("RX", uart_packet[:write_len], "Fuzz input via UARTDRV_Receive")

    # Return ECODE_EMDRV_UARTDRV_OK (0)
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
    _log(f"[EUSART] RX byte: 0x{fuzz_byte[0]:02x}\n")


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
    _log("[HEIMAN] Skipping txCurrentPacket (radio TX spin-wait)\n")
    uc.reg_write(UC_ARM_REG_R0, 0)  # Return success


def efr32RadioProcess(uc):
    """
    Skip efr32RadioProcess @ 0x08023108
    Main radio processing function that could block on hardware.
    """
    _log("[HEIMAN] Skipping efr32RadioProcess\n")
    uc.reg_write(UC_ARM_REG_R0, 0)


def otPlatRadioTransmit(uc):
    """
    Skip otPlatRadioTransmit @ 0x08022e14
    OpenThread radio transmit - skip hardware interaction.
    Returns OT_ERROR_NONE (0).
    """
    _log("[HEIMAN] Skipping otPlatRadioTransmit\n")
    uc.reg_write(UC_ARM_REG_R0, 0)  # OT_ERROR_NONE


def otPlatRadioReceive(uc):
    """
    Skip otPlatRadioReceive @ 0x08022d0c
    OpenThread radio receive - skip hardware interaction.
    Returns OT_ERROR_NONE (0).
    """
    _log("[HEIMAN] Skipping otPlatRadioReceive\n")
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
    _log("[HEIMAN] Skipping radioSetIdle\n")
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
    _log("[HEIMAN] Skipping txFailedCallback\n")


def RAILCb_Generic(uc):
    """
    Skip RAILCb_Generic @ 0x080224e0
    Generic RAIL callback - skip hardware interaction.
    """
    _log("[HEIMAN] Skipping RAILCb_Generic\n")


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
    _log("[HEIMAN] Skipping GPIO_EVEN_IRQHandler\n")


def GPIO_ODD_IRQHandler(uc):
    """
    Skip GPIO_ODD_IRQHandler @ 0x08009938
    Prevents GPIO handlers from consuming fuzz input.
    """
    _log("[HEIMAN] Skipping GPIO_ODD_IRQHandler\n")


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
    direction = 0x01  # To sensor
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

    _log(f"[UART_FUZZ] Injected {len(uart_packet)} bytes: {uart_packet.hex()}\n")

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
    direction = 0x01
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

    _log(f"[UART_HARNESS] Called UART_ParsePackets with {len(uart_packet)} bytes\n")


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
        direction = 0x01
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

        _log(f"[UART_IRQ] Injected {len(uart_packet)} bytes, calling UART_ParsePackets\n")

    except Exception as e:
        pass  # Silently ignore errors in interrupt context


def start_uart_fuzzing(uc):
    """
    Hook for sl_kernel_start - instead of starting the kernel,
    redirect execution to UART_ParsePackets with fuzz data.

    This bypasses FreeRTOS and goes straight to fuzzing the UART parser.

    IMPORTANT: We MUST always attempt to consume fuzz (even if empty) so that
    fuzzware's discovery phase can detect the fuzz consumption point and set
    the fork server location correctly.
    """
    import sys
    import ctypes

    print("[UART_FUZZ] Hook entry", file=sys.stderr, flush=True)
    _log("[UART_FUZZ] Intercepted sl_kernel_start, redirecting to UART parsing\n")

    from fuzzware_harness import native

    try:
        # Get the raw Unicorn handle
        uc_handle = uc._uch

        print("[UART_FUZZ] Calling get_fuzz_ptr", file=sys.stderr, flush=True)

        # First, check if there's any fuzz available
        remaining_before = native.fuzz_remaining()
        print(f"[UART_FUZZ] Remaining before: {remaining_before}", file=sys.stderr, flush=True)

        # Request 1 byte to trigger input loading
        ptr_addr = native.native_lib.get_fuzz_ptr(uc_handle, 1)

        # Check what's available after loading
        remaining_after = native.fuzz_remaining()
        consumed = native.fuzz_consumed()
        print(f"[UART_FUZZ] After trigger: remaining={remaining_after}, consumed={consumed}", file=sys.stderr, flush=True)

        if ptr_addr is None or ptr_addr == 0:
            print("[UART_FUZZ] No fuzz available (empty input)", file=sys.stderr, flush=True)
            raw_fuzz = b'\x01'  # Default command byte
        else:
            # Read the first byte
            first_byte = (ctypes.c_char * 1).from_address(ptr_addr).raw

            # Get remaining bytes (up to 64 total)
            bytes_to_get = min(remaining_after, 63)  # Already got 1
            if bytes_to_get > 0:
                ptr_addr2 = native.native_lib.get_fuzz_ptr(uc_handle, bytes_to_get)
                if ptr_addr2 and ptr_addr2 != 0:
                    rest_bytes = (ctypes.c_char * bytes_to_get).from_address(ptr_addr2).raw
                    raw_fuzz = first_byte + rest_bytes
                else:
                    raw_fuzz = first_byte
            else:
                raw_fuzz = first_byte

            print(f"[UART_FUZZ] Got {len(raw_fuzz)} bytes", file=sys.stderr, flush=True)

    except Exception as e:
        import traceback
        print(f"[UART_FUZZ] Error: {e}\n{traceback.format_exc()}", file=sys.stderr, flush=True)
        raw_fuzz = b'\x01'  # Use default on error

    # Build UART packet
    cmd = raw_fuzz[0] if len(raw_fuzz) > 0 else 0x01
    payload = raw_fuzz[1:] if len(raw_fuzz) > 1 else b''

    # Limit payload size so packet_len fits in one byte (max 255)
    # Header is 5 bytes (devtype, proto, seq, dir, cmd), so max payload is 250
    MAX_PAYLOAD = 250
    if len(payload) > MAX_PAYLOAD:
        payload = payload[:MAX_PAYLOAD]

    seq = 0
    direction = 0x01
    header = bytes([UART_DEV_TYPE, UART_PROTO_VER, seq, direction, cmd])
    packet_len = len(header) + len(payload)
    packet_body = bytes([packet_len]) + header + payload

    crc = 0
    for b in packet_body:
        crc ^= b

    uart_packet = b'\xAA\x55' + packet_body + bytes([crc])

    # Write to buffer
    uc.mem_write(FUZZ_BUFFER_ADDR, uart_packet)

    _log(f"[UART_FUZZ] Prepared {len(uart_packet)} byte packet: {uart_packet.hex()}\n")

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

    _log(f"[UART_FUZZ] Set up call to UART_ParsePackets({FUZZ_BUFFER_ADDR:#x}, {len(uart_packet)})\n")
    _log(f"[UART_FUZZ] LR={LOOP_ADDR | 1:#x}, PC=0x0800803d\n")

    # Return False to let execution continue at new PC (not the patched bx lr)
    return False
