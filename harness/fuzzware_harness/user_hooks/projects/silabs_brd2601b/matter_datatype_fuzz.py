"""
Matter Datatype-Aware Fuzzing Hook

This module implements datatype-aware fuzzing for Matter attributes.
Instead of random mutation, it selects from predefined value sets
based on Matter specification constraints.

Test values are imported from matter-constraint-fuzzer submodule to
ensure consistency between SDK testing and firmware emulation.

Approach:
- Fuzz bytes are used as selectors into predefined value arrays
- Each attribute type has boundary/invalid/physically-impossible values
- Tests SDK validation by calling emberAfWriteAttribute directly
"""

import sys
import os
import struct
from unicorn.arm_const import (
    UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
    UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_SP
)

from ...fuzz import get_fuzz

# =============================================================================
# Add matter-constraint-fuzzer submodule to path
# =============================================================================
# Find fuzzware root (where the submodule lives)
_this_dir = os.path.dirname(os.path.abspath(__file__))
_fuzzware_root = os.path.abspath(os.path.join(_this_dir, '..', '..', '..', '..', '..', '..', '..'))
_submodule_path = os.path.join(_fuzzware_root, 'matter-constraint-fuzzer')

if os.path.exists(_submodule_path) and _submodule_path not in sys.path:
    sys.path.insert(0, _submodule_path)

# Import shared test definitions from matter_constraints package
try:
    from matter_constraints.test_cases import TEST_CASES, is_invalid_value
    from matter_constraints.clusters import ZCL_INT8S_TYPE, ZCL_INT16S_TYPE
    _IMPORTS_OK = True
except ImportError as e:
    print(f"[WARN] Could not import matter_constraints: {e}")
    print(f"[WARN] Looked in: {_submodule_path}")
    print("[WARN] Falling back to built-in definitions")
    _IMPORTS_OK = False

# =============================================================================
# Fallback definitions (if submodule not available)
# =============================================================================
if not _IMPORTS_OK:
    # Minimal fallback - should not be used in normal operation
    ZCL_INT8S_TYPE = 0x28
    ZCL_INT16S_TYPE = 0x29
    ZCL_UINT8_TYPE = 0x20
    ZCL_UINT16_TYPE = 0x21
    ZCL_BOOL_TYPE = 0x10
    ZCL_ENUM8_TYPE = 0x30

    TEMPERATURE_VALUES = [-32768, -27316, -27315, 0, 2500, 32767]
    HUMIDITY_VALUES = [0, 5000, 10000, 10001, 65535]
    BOOL_VALUES = [0, 1, 2, 0xFF]
    ALARM_STATE_VALUES = [0, 1, 2, 3, 255]
    EXPRESSED_STATE_VALUES = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 255]
    LEVEL_VALUES = [0, 1, 127, 254, 255]

    CLUSTER_TEMPERATURE = 0x0402
    CLUSTER_HUMIDITY = 0x0405
    CLUSTER_ONOFF = 0x0006
    CLUSTER_LEVEL = 0x0008
    CLUSTER_SMOKECO = 0x005C

    ATTR_TEMP_MEASURED = 0x0000
    ATTR_TEMP_MIN = 0x0001
    ATTR_TEMP_MAX = 0x0002
    ATTR_HUMIDITY_MEASURED = 0x0000
    ATTR_ONOFF = 0x0000
    ATTR_CURRENT_LEVEL = 0x0000
    ATTR_EXPRESSED_STATE = 0x0000
    ATTR_SMOKE_STATE = 0x0001
    ATTR_CO_STATE = 0x0002

    TEST_CASES = [
        (CLUSTER_TEMPERATURE, ATTR_TEMP_MEASURED, TEMPERATURE_VALUES, ZCL_INT16S_TYPE, 2, "Temperature MeasuredValue"),
        (CLUSTER_TEMPERATURE, ATTR_TEMP_MIN, TEMPERATURE_VALUES, ZCL_INT16S_TYPE, 2, "Temperature MinMeasuredValue"),
        (CLUSTER_TEMPERATURE, ATTR_TEMP_MAX, TEMPERATURE_VALUES, ZCL_INT16S_TYPE, 2, "Temperature MaxMeasuredValue"),
        (CLUSTER_HUMIDITY, ATTR_HUMIDITY_MEASURED, HUMIDITY_VALUES, ZCL_UINT16_TYPE, 2, "Humidity MeasuredValue"),
        (CLUSTER_ONOFF, ATTR_ONOFF, BOOL_VALUES, ZCL_BOOL_TYPE, 1, "OnOff"),
        (CLUSTER_LEVEL, ATTR_CURRENT_LEVEL, LEVEL_VALUES, ZCL_UINT8_TYPE, 1, "Level CurrentLevel"),
        (CLUSTER_SMOKECO, ATTR_EXPRESSED_STATE, EXPRESSED_STATE_VALUES, ZCL_ENUM8_TYPE, 1, "SmokeCO ExpressedState"),
        (CLUSTER_SMOKECO, ATTR_SMOKE_STATE, ALARM_STATE_VALUES, ZCL_ENUM8_TYPE, 1, "SmokeCO SmokeState"),
        (CLUSTER_SMOKECO, ATTR_CO_STATE, ALARM_STATE_VALUES, ZCL_ENUM8_TYPE, 1, "SmokeCO COState"),
    ]

    def is_invalid_value(desc, value):
        if 'Temperature' in desc and value < -27315:
            return True
        if 'Humidity' in desc and (value > 10000 and value != 65535):
            return True
        if 'OnOff' in desc and value not in [0, 1]:
            return True
        if 'State' in desc and value > 8:
            return True
        return False


# =============================================================================
# Firmware-Specific Addresses (from symbols)
# =============================================================================
# emberAfWriteAttribute(endpoint, clusterId, attributeId, dataPtr, dataType)
EMBER_AF_WRITE_ATTRIBUTE = 0x080825cb

# Test buffer in RAM for attribute data
ATTR_DATA_BUFFER = 0x20018200
RETURN_LOOP = 0x20018000


# =============================================================================
# Logging
# =============================================================================
LOG_FILE = None

def _log(msg):
    """Write log message"""
    global LOG_FILE
    sys.stdout.write(msg)
    sys.stdout.flush()
    try:
        if LOG_FILE is None:
            LOG_FILE = open('/tmp/matter_datatype_fuzz.log', 'a')
        LOG_FILE.write(msg)
        LOG_FILE.flush()
    except:
        pass


# =============================================================================
# Fuzzing Hooks
# =============================================================================
_test_index = 0
_value_index = 0
_results = []


def datatype_fuzz_entry(uc):
    """
    Entry point for datatype-aware attribute fuzzing.
    Uses fuzz bytes to select test case and value.
    """
    global _test_index, _value_index, _results

    from fuzzware_harness import native

    _log("[DATATYPE_FUZZ] Starting Matter datatype-aware fuzzing\n")
    _log(f"[DATATYPE_FUZZ] Using {'submodule' if _IMPORTS_OK else 'fallback'} definitions\n")

    try:
        # Get 2 fuzz bytes: test selector, value selector
        fuzz_data = get_fuzz(uc, 2)

        if fuzz_data is None or len(fuzz_data) < 2:
            _log("[DATATYPE_FUZZ] No fuzz input - using defaults\n")
            fuzz_data = b'\x00\x00'

        # Use fuzz bytes to select test case and value
        _test_index = fuzz_data[0] % len(TEST_CASES)
        test_case = TEST_CASES[_test_index]

        cluster_id, attr_id, value_set, attr_type, attr_size, desc = test_case
        _value_index = fuzz_data[1] % len(value_set)
        test_value = value_set[_value_index]

        _log(f"[DATATYPE_FUZZ] Test: {desc}\n")
        _log(f"[DATATYPE_FUZZ] Cluster: 0x{cluster_id:04X}, Attr: 0x{attr_id:04X}\n")
        _log(f"[DATATYPE_FUZZ] Value: {test_value} (index {_value_index}/{len(value_set)})\n")

        _call_write_attribute(uc, cluster_id, attr_id, test_value, attr_type, attr_size)
        return False

    except Exception as e:
        import traceback
        _log(f"[DATATYPE_FUZZ] Error: {e}\n{traceback.format_exc()}\n")
        native.do_exit(uc, 1)
        return True


def datatype_fuzz_loop(uc):
    """
    Persistent loop for datatype fuzzing.
    Called when emberAfWriteAttribute returns.
    """
    global _test_index, _value_index, _results

    from fuzzware_harness import native

    ret = uc.reg_read(UC_ARM_REG_R0)
    test_case = TEST_CASES[_test_index]
    cluster_id, attr_id, value_set, attr_type, attr_size, desc = test_case
    test_value = value_set[_value_index]

    result = "ACCEPTED" if ret == 0 else f"REJECTED (0x{ret:08X})"
    _log(f"[DATATYPE_FUZZ] Result: {result}\n")

    _results.append({
        'test': desc,
        'value': test_value,
        'result': ret,
        'accepted': ret == 0
    })

    # Check for bugs
    if is_invalid_value(desc, test_value) and ret == 0:
        _log(f"[BUG FOUND] Invalid value {test_value} was ACCEPTED for {desc}!\n")

    # Check if more fuzz available
    remaining = native.fuzz_remaining()

    if remaining < 2:
        _print_summary()
        native.do_exit(uc, 0)
        return True

    # Get next fuzz for next test
    fuzz_data = get_fuzz(uc, 2)
    if fuzz_data is None or len(fuzz_data) < 2:
        native.do_exit(uc, 0)
        return True

    _test_index = fuzz_data[0] % len(TEST_CASES)
    test_case = TEST_CASES[_test_index]
    cluster_id, attr_id, value_set, attr_type, attr_size, desc = test_case
    _value_index = fuzz_data[1] % len(value_set)
    test_value = value_set[_value_index]

    _log(f"\n[DATATYPE_FUZZ] Next test: {desc}\n")
    _log(f"[DATATYPE_FUZZ] Value: {test_value}\n")

    _call_write_attribute(uc, cluster_id, attr_id, test_value, attr_type, attr_size)
    return False


# =============================================================================
# Sequential Test Mode (deterministic)
# =============================================================================
_sequential_test_idx = 0
_sequential_value_idx = 0


def datatype_fuzz_sequential(uc):
    """
    Run tests sequentially through all predefined values.
    This is deterministic (not fuzz-guided) for comprehensive coverage.
    """
    global _sequential_test_idx, _sequential_value_idx, _results

    from fuzzware_harness import native

    _log("[DATATYPE_SEQ] Starting sequential Matter datatype testing\n")
    _log(f"[DATATYPE_SEQ] Using {'submodule' if _IMPORTS_OK else 'fallback'} definitions\n")
    _log(f"[DATATYPE_SEQ] Total test cases: {len(TEST_CASES)}\n")

    _sequential_test_idx = 0
    _sequential_value_idx = 0

    test_case = TEST_CASES[_sequential_test_idx]
    cluster_id, attr_id, value_set, attr_type, attr_size, desc = test_case
    test_value = value_set[_sequential_value_idx]

    _log(f"[DATATYPE_SEQ] Test 1: {desc} = {test_value}\n")

    _call_write_attribute(uc, cluster_id, attr_id, test_value, attr_type, attr_size)
    return False


def datatype_sequential_loop(uc):
    """
    Loop handler for sequential testing.
    """
    global _sequential_test_idx, _sequential_value_idx, _results

    from fuzzware_harness import native

    ret = uc.reg_read(UC_ARM_REG_R0)
    test_case = TEST_CASES[_sequential_test_idx]
    cluster_id, attr_id, value_set, attr_type, attr_size, desc = test_case
    test_value = value_set[_sequential_value_idx]

    result_str = "ACCEPTED" if ret == 0 else "REJECTED"
    _log(f"[DATATYPE_SEQ] {desc} = {test_value}: {result_str}\n")

    _results.append({
        'test': desc,
        'value': test_value,
        'result': ret,
        'accepted': ret == 0
    })

    if is_invalid_value(desc, test_value) and ret == 0:
        _log(f"[BUG FOUND] Invalid value {test_value} was ACCEPTED for {desc}!\n")

    # Advance to next value or test
    _sequential_value_idx += 1
    if _sequential_value_idx >= len(value_set):
        _sequential_value_idx = 0
        _sequential_test_idx += 1

        if _sequential_test_idx >= len(TEST_CASES):
            _print_summary()
            native.do_exit(uc, 0)
            return True

    test_case = TEST_CASES[_sequential_test_idx]
    cluster_id, attr_id, value_set, attr_type, attr_size, desc = test_case
    test_value = value_set[_sequential_value_idx]

    _call_write_attribute(uc, cluster_id, attr_id, test_value, attr_type, attr_size)
    return False


# =============================================================================
# Helper Functions
# =============================================================================

def _call_write_attribute(uc, cluster_id, attr_id, test_value, attr_type, attr_size):
    """Set up and call emberAfWriteAttribute."""
    # Encode value
    if attr_size == 1:
        if attr_type == ZCL_INT8S_TYPE:
            value_bytes = struct.pack('<b', test_value & 0xFF)
        else:
            value_bytes = struct.pack('<B', test_value & 0xFF)
    elif attr_size == 2:
        if attr_type == ZCL_INT16S_TYPE:
            value_bytes = struct.pack('<h', test_value & 0xFFFF)
        else:
            value_bytes = struct.pack('<H', test_value & 0xFFFF)
    else:
        value_bytes = struct.pack('<I', test_value & 0xFFFFFFFF)

    uc.mem_write(ATTR_DATA_BUFFER, value_bytes)
    uc.mem_write(RETURN_LOOP, b'\xfe\xe7')  # Infinite loop (b .)

    # Set up call
    uc.reg_write(UC_ARM_REG_R0, 1)  # endpoint
    uc.reg_write(UC_ARM_REG_R1, cluster_id)
    uc.reg_write(UC_ARM_REG_R2, attr_id)
    uc.reg_write(UC_ARM_REG_R3, ATTR_DATA_BUFFER)

    sp = uc.reg_read(UC_ARM_REG_SP)
    sp -= 4
    uc.mem_write(sp, struct.pack('<I', attr_type))
    uc.reg_write(UC_ARM_REG_SP, sp)

    uc.reg_write(UC_ARM_REG_LR, RETURN_LOOP | 1)
    uc.reg_write(UC_ARM_REG_PC, EMBER_AF_WRITE_ATTRIBUTE | 1)


def _print_summary():
    """Print test summary."""
    global _results

    _log("\n" + "=" * 60 + "\n")
    _log("DATATYPE TEST COMPLETE\n")
    _log("=" * 60 + "\n")

    bugs = [r for r in _results if r['accepted'] and is_invalid_value(r['test'], r['value'])]
    _log(f"Total tests: {len(_results)}\n")
    _log(f"BUGS (invalid accepted): {len(bugs)}\n")

    if bugs:
        _log("\nBugs found:\n")
        for bug in bugs:
            _log(f"  - {bug['test']}: {bug['value']} was ACCEPTED\n")

    _log("=" * 60 + "\n")
