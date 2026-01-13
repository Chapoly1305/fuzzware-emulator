"""
Heiman Smoke Detector - FreeRTOS Trace and Bypass Hooks

Contains hooks for tracing FreeRTOS boot sequence and bypassing problematic
FreeRTOS operations.
"""
import sys
import time

from unicorn.arm_const import (
    UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_SP
)

from .logging import _emu_log, _emu_debug_log, _fw_log, _save_input_log

# Global state
_boot_count = 0
_trace_counter = 0
_mainInit_seen = False
_app_user_init_seen = False
_blocking_count = 0
_fuzz_event_injected = False
_assert_count = 0


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


def trace_blocking_call(uc):
    """Trace blocking FreeRTOS calls and return timeout to allow progress."""
    global _blocking_count
    _blocking_count += 1

    # Only log first 3 blocking calls to reduce overhead
    if _blocking_count <= 3:
        pc = uc.reg_read(UC_ARM_REG_PC)
        lr = uc.reg_read(UC_ARM_REG_LR)
        _emu_log(f"[BLOCKING #{_blocking_count}] PC=0x{pc:08x} LR=0x{lr:08x}\n")

    # Return pdFALSE (0) = timeout/no message
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
    import os
    os._exit(0)


def println_with_uart_redirect(uc):
    """
    println hook that detects applicationUserInit and redirects to UART fuzzing.
    This bypasses FreeRTOS entirely and goes straight to UART parsing.
    """
    global _app_user_init_seen

    # Import here to avoid circular import
    from .uart_fuzzing import start_uart_fuzzing

    # Read the string pointer from R0
    str_ptr = uc.reg_read(UC_ARM_REG_R0)
    lr = uc.reg_read(UC_ARM_REG_LR)
    pc = uc.reg_read(UC_ARM_REG_PC)

    if str_ptr == 0:
        return

    try:
        raw_bytes = uc.mem_read(str_ptr, 100)
        null_idx = raw_bytes.find(b'\x00')
        if null_idx != -1:
            raw_bytes = raw_bytes[:null_idx]
        msg = raw_bytes.decode('utf-8', errors='replace')
    except:
        msg = "<error reading string>"

    # Check for applicationUserInit
    if "applicationUserInit" in msg and not _app_user_init_seen:
        _app_user_init_seen = True
        start_uart_fuzzing(uc)
        return True


def println_mainInit_redirect(uc):
    """
    println hook that detects mainInit and redirects to UART fuzzing.
    """
    global _mainInit_seen

    # Import here to avoid circular import
    from .uart_fuzzing import start_uart_fuzzing

    str_ptr = uc.reg_read(UC_ARM_REG_R0)
    lr = uc.reg_read(UC_ARM_REG_LR)

    if str_ptr == 0:
        return

    try:
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

        start_uart_fuzzing(uc)
        return True


def println_with_direct_cmd41_redirect(uc):
    """
    println hook that detects applicationUserInit and redirects to direct cmd 0x41 fuzzing.
    Bypasses UART dispatcher and calls HandleCmd_SensorStatusAlt directly.
    """
    global _app_user_init_seen

    # Import here to avoid circular import
    from .uart_fuzzing import fuzz_cmd_0x41

    # Read the string pointer from R0
    str_ptr = uc.reg_read(UC_ARM_REG_R0)

    if str_ptr == 0:
        return

    try:
        raw_bytes = uc.mem_read(str_ptr, 100)
        null_idx = raw_bytes.find(b'\x00')
        if null_idx != -1:
            raw_bytes = raw_bytes[:null_idx]
        msg = raw_bytes.decode('utf-8', errors='replace')
    except:
        msg = "<error reading string>"

    # Check for applicationUserInit - trigger direct handler fuzzing
    if "applicationUserInit" in msg and not _app_user_init_seen:
        _app_user_init_seen = True
        _emu_log(f"[DIRECT_FUZZ] Detected applicationUserInit - redirecting to cmd 0x41 handler\n")
        fuzz_cmd_0x41(uc)
        return True


def debug_trace(uc):
    """Generic trace hook."""
    global _trace_counter
    _trace_counter += 1
    pc = uc.reg_read(UC_ARM_REG_PC)
    if _trace_counter <= 20:
        _emu_debug_log(f"[TRACE {_trace_counter}] PC=0x{pc:08x}")


def debug_kernel_start(uc):
    """Debug hook to trace when kernel start is called."""
    global _boot_count
    _boot_count += 1
    pc = uc.reg_read(UC_ARM_REG_PC)
    _emu_debug_log(f"[DEBUG BOOT {_boot_count}] _start called at PC=0x{pc:08x}")


def debug_scheduler_start(uc):
    """Debug hook to trace when vTaskStartScheduler is called."""
    global _boot_count
    pc = uc.reg_read(UC_ARM_REG_PC)
    _emu_debug_log(f"[DEBUG BOOT {_boot_count}] start() called at PC=0x{pc:08x}")


def debug_idle_hook(uc):
    """Debug hook to trace idle task execution."""
    global _boot_count
    _emu_debug_log(f"[DEBUG BOOT {_boot_count}] sl_platform_init called")


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


def bypass_stackoverflow_hook(uc):
    """Bypass vApplicationStackOverflowHook - prevent ASSERT message and loop."""
    pc = uc.reg_read(UC_ARM_REG_PC)
    lr = uc.reg_read(UC_ARM_REG_LR)
    _emu_debug_log(f"[STACKOVERFLOW_BYPASS] Hook triggered at PC=0x{pc:08x} LR=0x{lr:08x}")
    _emu_log(f"[STACKOVERFLOW_BYPASS] vApplicationStackOverflowHook bypassed, caller=0x{lr:08x}\n")
    uc.reg_write(UC_ARM_REG_R0, 0)


def force_return_from_assert_loop(uc):
    """
    Force return from ASSERT infinite loop by setting PC to LR.
    After first assertion, exit cleanly since the system is broken.
    """
    global _assert_count
    _assert_count += 1

    if _assert_count == 1:
        pc = uc.reg_read(UC_ARM_REG_PC)
        lr = uc.reg_read(UC_ARM_REG_LR)
        _emu_log(f"[ASSERT] First assert at PC=0x{pc:08x}, LR=0x{lr:08x} - exiting\n")
        _save_input_log("assert_crash")

    # Exit immediately on any assert
    uc.reg_write(UC_ARM_REG_PC, 0)
    return True


def trace_vStartFirstTask(uc):
    """Trace hook for vStartFirstTask - starts the first FreeRTOS task."""
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
    try:
        code = uc.mem_read(0x20002cb0, 8)
        _emu_debug_log(f"[RAM_CALLBACK] Code at 0x20002cb0: {code.hex()}")
    except:
        _emu_debug_log(f"[RAM_CALLBACK] Could not read code at 0x20002cb0")


def skip_ram_callback(uc):
    """Skip execution at uninitialized RAM callback - return to caller."""
    lr = uc.reg_read(UC_ARM_REG_LR)
    uc.reg_write(UC_ARM_REG_PC, lr)
    return False


def sl_sleeptimer_get_timer_frequency_high(uc):
    """
    Return high frequency for FreeRTOS configTICK_RATE_HZ check.
    Some firmware uses tick rates > 32768 Hz, so return 1MHz.
    """
    uc.reg_write(UC_ARM_REG_R0, 1000000)
