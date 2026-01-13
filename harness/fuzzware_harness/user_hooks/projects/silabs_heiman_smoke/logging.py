"""
Heiman Smoke Detector - Logging Utilities

Log files (shared with silabs.py):
- /tmp/firmware.log  - Firmware output (UART TX/RX, prints)
- /tmp/emulator.log  - Emulator debug (hooks, NVM3 traces)
"""
import os

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

    # Also write UART_TX to stderr for console capture
    if '[UART_TX]' in msg:
        import sys
        sys.stderr.write(msg)
        sys.stderr.flush()


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
