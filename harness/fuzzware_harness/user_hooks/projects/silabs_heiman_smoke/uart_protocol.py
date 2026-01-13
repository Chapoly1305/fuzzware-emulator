"""
Heiman Smoke Detector - UART Protocol Constants and Helpers

Protocol: AA 55 <len> <devtype> <proto> <seq> <dir> <cmd> <payload...> <crc>

Direction field (verified from IDA analysis):
  0x01 = Sensor -> MCU (request TO firmware) - checked at 0x8008072
  0x02 = MCU -> Sensor (response FROM firmware) - set at 0x800824e

For fuzzing, we send packets with direction=0x01 (pretending to be the sensor)
"""

# Protocol constants
UART_MAGIC = b'\xAA\x55'
UART_DEV_TYPE = 0x60      # Smoke detector device type
UART_PROTO_VER = 0x06     # Protocol version (firmware checks for 0x06)
UART_DIR_SENSOR_TO_MCU = 0x01  # Sensor -> MCU (incoming request)
UART_DIR_MCU_TO_SENSOR = 0x02  # MCU -> Sensor (outgoing response)

# UART RX buffer address in RAM (found from firmware analysis)
UART_RX_BUFFER_ADDR = 0x200187EC
UART_RX_BUFFER_SIZE = 256

# Aliases for convenience
FUZZ_BUFFER_ADDR = UART_RX_BUFFER_ADDR
FUZZ_BUFFER_SIZE = UART_RX_BUFFER_SIZE

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


def build_uart_packet(cmd, payload, seq=None, direction=UART_DIR_SENSOR_TO_MCU):
    """
    Build a UART packet with specified command and payload.

    Args:
        cmd: Command byte
        payload: Payload bytes
        seq: Sequence number (auto-incremented if None)
        direction: Direction field (default: Sensor -> MCU)

    Returns:
        Complete packet bytes: AA 55 <len> <devtype> <proto> <seq> <dir> <cmd> <payload> <crc>
    """
    global _uart_seq

    if seq is None:
        seq = _uart_seq
        _uart_seq += 1

    header = bytes([UART_DEV_TYPE, UART_PROTO_VER, seq & 0xFF, direction, cmd])
    packet_len = len(header) + len(payload)
    packet_body = bytes([packet_len]) + header + payload

    crc = _calc_uart_crc(packet_body)
    return UART_MAGIC + packet_body + bytes([crc])


def reset_uart_seq():
    """Reset the UART sequence counter"""
    global _uart_seq
    _uart_seq = 0


def get_uart_seq():
    """Get current UART sequence number"""
    return _uart_seq
