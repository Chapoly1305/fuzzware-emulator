"""
Generic Silicon Labs Platform Hooks

Platform-level hooks for Silicon Labs EFR32 devices (reusable across projects).
Provides logging, timers, crypto bypass, and other common platform services.

For device-specific hooks (provisioning, protocols, hardware bypass), see:
- user_hooks/projects/silabs_brd2601b/ - Matter provisioning hooks
- user_hooks/projects/silabs_heiman_smoke/ - Heiman device-specific hooks
- user_hooks/projects/README.md - Guide for creating project-specific hooks
"""
import sys
import os
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_SP

# Log levels
LOG_LEVEL_DEBUG = 0
LOG_LEVEL_INFO = 1
LOG_LEVEL_WARN = 2
LOG_LEVEL_ERROR = 3

# Current log level - default to INFO
_log_level = LOG_LEVEL_INFO

# Parse log level from environment variable
_env_log_level = os.environ.get('FUZZWARE_LOG_LEVEL', 'INFO').upper()
if _env_log_level == 'DEBUG':
    _log_level = LOG_LEVEL_DEBUG
elif _env_log_level == 'INFO':
    _log_level = LOG_LEVEL_INFO
elif _env_log_level == 'WARN':
    _log_level = LOG_LEVEL_WARN
elif _env_log_level == 'ERROR':
    _log_level = LOG_LEVEL_ERROR

# Log file path - can be overridden via environment variable
LOG_FILE_PATH = os.environ.get('FUZZWARE_LOG_FILE', '/tmp/fuzzware_console.log')
_log_file = None

# Simulated time tracking for timestamps
_sim_time_ms = 0

def _get_log_file():
    """Get or create the log file handle"""
    global _log_file
    if _log_file is None:
        _log_file = open(LOG_FILE_PATH, 'a')
    return _log_file

def _write_log(msg):
    """Write message to both stdout and log file"""
    # Write to stdout
    sys.stdout.write(msg)
    sys.stdout.flush()
    # Write to file
    f = _get_log_file()
    f.write(msg)
    f.flush()


def _log_debug(msg):
    """Write debug message if log level is DEBUG"""
    if _log_level <= LOG_LEVEL_DEBUG:
        _write_log(msg)


def _log_info(msg):
    """Write info message if log level is INFO or lower"""
    if _log_level <= LOG_LEVEL_INFO:
        _write_log(msg)


def _log_warn(msg):
    """Write warning message if log level is WARN or lower"""
    if _log_level <= LOG_LEVEL_WARN:
        _write_log(msg)


def _log_error(msg):
    """Write error message if log level is ERROR or lower"""
    if _log_level <= LOG_LEVEL_ERROR:
        _write_log(msg)


def _get_timestamp():
    """Get formatted timestamp like [00:00:00.000]"""
    global _sim_time_ms
    ms = _sim_time_ms % 1000
    total_secs = _sim_time_ms // 1000
    secs = total_secs % 60
    mins = (total_secs // 60) % 60
    hours = (total_secs // 3600) % 24
    return f"[{hours:02d}:{mins:02d}:{secs:02d}.{ms:03d}]"


def _format_va_string(uc, fmt_bytes, va_list_ptr):
    """
    Parse format string and substitute arguments from va_list.

    ARM EABI: va_list is a pointer to the argument area.
    Arguments are 4-byte aligned (for 32-bit values).

    Supported format specifiers:
    - %s: string pointer
    - %d, %i: signed decimal
    - %u: unsigned decimal
    - %x, %X: hex
    - %p: pointer (hex)
    - %c: character
    - %%: literal %
    """
    if va_list_ptr == 0:
        return fmt_bytes.decode('latin1', errors='replace')

    output = b''
    arg_offset = 0  # Offset into va_list

    i = 0
    while i < len(fmt_bytes):
        if fmt_bytes[i] != ord('%'):
            output += bytes([fmt_bytes[i]])
            i += 1
            continue

        i += 1
        if i >= len(fmt_bytes):
            output += b'%'
            break

        # Handle %%
        if fmt_bytes[i] == ord('%'):
            output += b'%'
            i += 1
            continue

        # Capture the full format specifier for width/precision handling
        fmt_start = i - 1  # Include the %

        # Skip flags: -, +, space, #, 0
        while i < len(fmt_bytes) and chr(fmt_bytes[i]) in '-+ #0':
            i += 1

        # Parse width (could be * for argument-based width)
        width = 0
        if i < len(fmt_bytes) and fmt_bytes[i] == ord('*'):
            # Width from argument
            try:
                arg_bytes = uc.mem_read(va_list_ptr + arg_offset, 4)
                width = int.from_bytes(arg_bytes, 'little')
                arg_offset += 4
            except:
                pass
            i += 1
        else:
            while i < len(fmt_bytes) and chr(fmt_bytes[i]).isdigit():
                width = width * 10 + (fmt_bytes[i] - ord('0'))
                i += 1

        # Parse precision
        precision = -1
        if i < len(fmt_bytes) and fmt_bytes[i] == ord('.'):
            i += 1
            precision = 0
            if i < len(fmt_bytes) and fmt_bytes[i] == ord('*'):
                # Precision from argument
                try:
                    arg_bytes = uc.mem_read(va_list_ptr + arg_offset, 4)
                    precision = int.from_bytes(arg_bytes, 'little')
                    arg_offset += 4
                except:
                    pass
                i += 1
            else:
                while i < len(fmt_bytes) and chr(fmt_bytes[i]).isdigit():
                    precision = precision * 10 + (fmt_bytes[i] - ord('0'))
                    i += 1

        # Skip length modifiers: h, hh, l, ll, L, z, j, t
        while i < len(fmt_bytes) and chr(fmt_bytes[i]) in 'hlLzjt':
            i += 1

        if i >= len(fmt_bytes):
            break

        spec = chr(fmt_bytes[i])
        i += 1

        try:
            # Read 4-byte argument from va_list
            arg_bytes = uc.mem_read(va_list_ptr + arg_offset, 4)
            arg_val = int.from_bytes(arg_bytes, 'little')
            arg_offset += 4

            if spec == 's':
                # String pointer
                if arg_val == 0:
                    output += b'(null)'
                else:
                    s = uc.mem_read(arg_val, 256)
                    if b'\0' in s:
                        s = s[:s.find(b'\0')]
                    output += s
            elif spec in 'di':
                # Signed decimal
                if arg_val & 0x80000000:
                    arg_val = arg_val - 0x100000000
                output += str(arg_val).encode()
            elif spec == 'u':
                # Unsigned decimal
                output += str(arg_val).encode()
            elif spec == 'x':
                output += f'{arg_val:x}'.encode()
            elif spec == 'X':
                output += f'{arg_val:X}'.encode()
            elif spec == 'p':
                output += f'0x{arg_val:08x}'.encode()
            elif spec == 'c':
                output += bytes([arg_val & 0xff])
            else:
                # Unknown specifier, just output as-is
                output += f'%{spec}'.encode()
                arg_offset -= 4  # Don't consume arg for unknown spec
        except Exception:
            output += f'%{spec}'.encode()

    return output.decode('latin1', errors='replace')


def _format_variadic_string(uc, fmt_bytes, arg_regs, stack_ptr):
    """
    Parse format string with variadic arguments from registers and stack.

    ARM EABI: First 4 args in R0-R3, rest on stack.
    For silabsLog: R0=tag, R1=fmt, so variadic args start at R2, R3, then stack.

    arg_regs: list of register values for variadic args (e.g., [R2, R3])
    stack_ptr: SP value for reading additional args from stack
    """
    output = b''
    arg_idx = 0
    stack_offset = 0

    def get_next_arg():
        nonlocal arg_idx, stack_offset
        if arg_idx < len(arg_regs):
            val = arg_regs[arg_idx]
            arg_idx += 1
            return val
        else:
            # Read from stack
            try:
                arg_bytes = uc.mem_read(stack_ptr + stack_offset, 4)
                stack_offset += 4
                return int.from_bytes(arg_bytes, 'little')
            except:
                return 0

    i = 0
    while i < len(fmt_bytes):
        if fmt_bytes[i] != ord('%'):
            output += bytes([fmt_bytes[i]])
            i += 1
            continue

        i += 1
        if i >= len(fmt_bytes):
            output += b'%'
            break

        # Handle %%
        if fmt_bytes[i] == ord('%'):
            output += b'%'
            i += 1
            continue

        # Skip flags
        while i < len(fmt_bytes) and chr(fmt_bytes[i]) in '-+ #0':
            i += 1

        # Skip width
        while i < len(fmt_bytes) and chr(fmt_bytes[i]).isdigit():
            i += 1

        # Skip precision
        if i < len(fmt_bytes) and fmt_bytes[i] == ord('.'):
            i += 1
            while i < len(fmt_bytes) and chr(fmt_bytes[i]).isdigit():
                i += 1

        # Skip length modifiers
        while i < len(fmt_bytes) and chr(fmt_bytes[i]) in 'hlLzjt':
            i += 1

        if i >= len(fmt_bytes):
            break

        spec = chr(fmt_bytes[i])
        i += 1

        try:
            arg_val = get_next_arg()

            if spec == 's':
                if arg_val == 0:
                    output += b'(null)'
                else:
                    s = uc.mem_read(arg_val, 256)
                    if b'\0' in s:
                        s = s[:s.find(b'\0')]
                    output += s
            elif spec in 'di':
                if arg_val & 0x80000000:
                    arg_val = arg_val - 0x100000000
                output += str(arg_val).encode()
            elif spec == 'u':
                output += str(arg_val).encode()
            elif spec == 'x':
                output += f'{arg_val:x}'.encode()
            elif spec == 'X':
                output += f'{arg_val:X}'.encode()
            elif spec == 'p':
                output += f'0x{arg_val:08x}'.encode()
            elif spec == 'c':
                output += bytes([arg_val & 0xff])
            else:
                output += f'%{spec}'.encode()
        except:
            output += f'%{spec}'.encode()

    return output.decode('latin1', errors='replace')


def silabsLog(uc):
    """
    Silicon Labs log function handler.
    silabsLog typically takes: (const char* tag, const char* fmt, ...)
    R0 = tag (or module), R1 = format string, R2, R3 = first variadic args, then stack
    """
    global _sim_time_ms
    _sim_time_ms += 1

    # Read the format string from R1 (or R0 if single arg)
    fmt_ptr = uc.reg_read(UC_ARM_REG_R1)
    if fmt_ptr == 0:
        fmt_ptr = uc.reg_read(UC_ARM_REG_R0)

    if fmt_ptr == 0:
        return

    try:
        # Read the format/message string
        msg = uc.mem_read(fmt_ptr, 256)
        if b'\0' in msg:
            msg = msg[:msg.find(b'\0')]

        # Try to get a tag from R0 if R1 has the fmt
        tag_ptr = uc.reg_read(UC_ARM_REG_R0)
        tag = b""
        if tag_ptr != fmt_ptr and tag_ptr != 0:
            try:
                tag = uc.mem_read(tag_ptr, 32)
                if b'\0' in tag:
                    tag = tag[:tag.find(b'\0')]
            except:
                pass

        # Get variadic args from R2, R3 and stack
        arg_regs = [uc.reg_read(UC_ARM_REG_R2), uc.reg_read(UC_ARM_REG_R3)]
        stack_ptr = uc.reg_read(UC_ARM_REG_SP)

        # Format the message with variadic arguments
        formatted_msg = _format_variadic_string(uc, msg, arg_regs, stack_ptr)

        # Print with timestamp and [LOG] prefix
        timestamp = _get_timestamp()
        if tag:
            _log_info(f"{timestamp}[silabs][{tag.decode('latin1', errors='replace')}] {formatted_msg}\n")
        else:
            _log_info(f"{timestamp}[silabs] {formatted_msg}\n")
    except Exception as e:
        _log_info(f"[LOG] (error reading log: {e})\n")


def chip_log(uc):
    """
    Generic CHIP/Matter log handler
    """
    silabsLog(uc)


def SEGGER_RTT_Write(uc):
    """
    SEGGER RTT Write handler.
    unsigned SEGGER_RTT_Write(unsigned BufferIndex, const void* pBuffer, unsigned NumBytes);
    R0 = BufferIndex (0 = Terminal), R1 = pBuffer, R2 = NumBytes
    """
    buffer_index = uc.reg_read(UC_ARM_REG_R0)
    buffer_ptr = uc.reg_read(UC_ARM_REG_R1)
    num_bytes = uc.reg_read(UC_ARM_REG_R2)

    if buffer_ptr == 0 or num_bytes == 0:
        return

    # Only capture terminal output (buffer 0)
    if buffer_index != 0:
        return

    try:
        # Limit read size
        num_bytes = min(num_bytes, 1024)
        msg = uc.mem_read(buffer_ptr, num_bytes)

        # Print RTT output to stdout and file
        _log_info(msg.decode('latin1', errors='replace'))
    except Exception as e:
        _log_info(f"[RTT] (error: {e})\n")


def SEGGER_RTT_WriteNoLock(uc):
    """
    Same as SEGGER_RTT_Write but without locking
    """
    SEGGER_RTT_Write(uc)


def rtt_write(uc):
    """
    Low-level RTT write function used by sl_iostream_rtt
    Signature: sl_status_t rtt_write(void *context, const void *buffer, size_t buffer_length)
    R0 = context, R1 = buffer, R2 = buffer_length
    """
    buffer_ptr = uc.reg_read(UC_ARM_REG_R1)
    buffer_len = uc.reg_read(UC_ARM_REG_R2)

    if buffer_ptr == 0 or buffer_len == 0:
        return

    try:
        buffer_len = min(buffer_len, 1024)
        msg = uc.mem_read(buffer_ptr, buffer_len)
        _log_info(msg.decode('latin1', errors='replace'))
    except Exception as e:
        _log_info(f"[RTT] (error: {e})\n")


def chip_LogV(uc):
    """
    chip::Logging::Platform::LogV - Matter SDK logging function
    void LogV(const char* module, uint8_t category, const char* msg, va_list args)
    R0 = module, R1 = category, R2 = msg, R3 = va_list pointer
    """
    global _sim_time_ms
    _sim_time_ms += 1  # Advance simulated time

    module_ptr = uc.reg_read(UC_ARM_REG_R0)
    category = uc.reg_read(UC_ARM_REG_R1)
    msg_ptr = uc.reg_read(UC_ARM_REG_R2)
    va_list_ptr = uc.reg_read(UC_ARM_REG_R3)

    try:
        module = b""
        if module_ptr != 0:
            module = uc.mem_read(module_ptr, 32)
            if b'\0' in module:
                module = module[:module.find(b'\0')]

        msg = b""
        if msg_ptr != 0:
            msg = uc.mem_read(msg_ptr, 256)
            if b'\0' in msg:
                msg = msg[:msg.find(b'\0')]

        # Format the message with va_list arguments
        formatted_msg = _format_va_string(uc, msg, va_list_ptr)

        # Category: 0=Error, 1=Progress, 2=Detail, 3=Automation
        # Match real device format: [timestamp][level ][module] message
        cat_names = {0: "error ", 1: "info  ", 2: "detail", 3: "auto  "}
        cat_name = cat_names.get(category, f"{category:6}")

        timestamp = _get_timestamp()
        module_str = module.decode('latin1', errors='replace')
        _log_info(f"{timestamp}[{cat_name}][{module_str}] {formatted_msg}\n")
    except Exception as e:
        _log_info(f"[CHIP] (error: {e})\n")


def ot_LogVarArgs(uc):
    """
    ot::Logger::LogVarArgs - OpenThread logging function
    void LogVarArgs(const char* aModuleName, LogLevel aLogLevel, const char* aFormat, va_list aArgs)
    R0 = module, R1 = log level, R2 = format, R3 = va_list pointer
    """
    global _sim_time_ms
    _sim_time_ms += 1  # Advance simulated time

    module_ptr = uc.reg_read(UC_ARM_REG_R0)
    log_level = uc.reg_read(UC_ARM_REG_R1)
    fmt_ptr = uc.reg_read(UC_ARM_REG_R2)
    va_list_ptr = uc.reg_read(UC_ARM_REG_R3)

    try:
        module = b""
        if module_ptr != 0:
            module = uc.mem_read(module_ptr, 32)
            if b'\0' in module:
                module = module[:module.find(b'\0')]

        fmt = b""
        if fmt_ptr != 0:
            fmt = uc.mem_read(fmt_ptr, 256)
            if b'\0' in fmt:
                fmt = fmt[:fmt.find(b'\0')]

        # Format the message with va_list arguments
        formatted_msg = _format_va_string(uc, fmt, va_list_ptr)

        # Log levels: 0=None, 1=Crit, 2=Warn, 3=Note, 4=Info, 5=Debg
        # Match real device format: [timestamp][level ][module] message
        level_names = {0: "none  ", 1: "crit  ", 2: "warn  ", 3: "note  ", 4: "info  ", 5: "debug "}
        level_name = level_names.get(log_level, f"{log_level:6}")

        timestamp = _get_timestamp()
        module_str = module.decode('latin1', errors='replace')
        _log_info(f"{timestamp}[{level_name}][OT-{module_str}] {formatted_msg}\n")
    except Exception as e:
        _log_info(f"[OT] (error: {e})\n")


# Tick counter for sleeptimer emulation
_tick_counter = 0

def sl_sleeptimer_get_tick_count(uc):
    """
    uint32_t sl_sleeptimer_get_tick_count(void)
    Returns current tick count. We return an increasing value.
    """
    global _tick_counter
    _tick_counter += 1000  # Increment by 1000 ticks each call (~1 sec at 1kHz)
    uc.reg_write(UC_ARM_REG_R0, _tick_counter & 0xFFFFFFFF)


def sl_sleeptimer_get_timer_frequency(uc):
    """
    uint32_t sl_sleeptimer_get_timer_frequency(void)
    Returns the sleeptimer frequency (typically 32768 Hz for 32kHz RTC).
    FreeRTOS configTICK_RATE_HZ must be <= this value.
    """
    uc.reg_write(UC_ARM_REG_R0, 32768)  # 32kHz typical RTC frequency


def sl_sleeptimer_get_tick_count64(uc):
    """
    uint64_t sl_sleeptimer_get_tick_count64(void)
    Returns current tick count as 64-bit. R0=low, R1=high
    """
    global _tick_counter
    _tick_counter += 1000
    uc.reg_write(UC_ARM_REG_R0, _tick_counter & 0xFFFFFFFF)
    uc.reg_write(UC_ARM_REG_R1, (_tick_counter >> 32) & 0xFFFFFFFF)


def otPlatAlarmMilliGetNow(uc):
    """
    uint32_t otPlatAlarmMilliGetNow(void)
    Returns current millisecond time for OpenThread alarm.
    """
    global _tick_counter
    _tick_counter += 10  # Increment by 10ms each call
    uc.reg_write(UC_ARM_REG_R0, _tick_counter & 0xFFFFFFFF)


def otLogPlat(uc, level_name="INF"):
    """
    OpenThread platform log handler.
    These platform logs are typically duplicates of ot_LogVarArgs logs,
    and have complex variadic signatures. Skip silently.
    """
    # Platform logs are low-level and already captured via ot_LogVarArgs
    pass


def otLogInfoPlat(uc):
    """OpenThread Info level platform log"""
    otLogPlat(uc, "INF")


def otLogWarnPlat(uc):
    """OpenThread Warning level platform log"""
    otLogPlat(uc, "WRN")


def otLogDebgPlat(uc):
    """OpenThread Debug level platform log"""
    otLogPlat(uc, "DBG")


# OpenThread crypto skip functions (return OT_ERROR_NONE = 0)
def otPlatCryptoHmacSha256Init(uc):
    """Skip HMAC-SHA256 init"""
    uc.reg_write(UC_ARM_REG_R0, 0)

def otPlatCryptoHmacSha256Start(uc):
    """Skip HMAC-SHA256 start"""
    uc.reg_write(UC_ARM_REG_R0, 0)

def otPlatCryptoHmacSha256Update(uc):
    """Skip HMAC-SHA256 update"""
    uc.reg_write(UC_ARM_REG_R0, 0)

def otPlatCryptoHmacSha256Finish(uc):
    """Skip HMAC-SHA256 finish"""
    uc.reg_write(UC_ARM_REG_R0, 0)

def otPlatCryptoHmacSha256Deinit(uc):
    """Skip HMAC-SHA256 deinit"""
    uc.reg_write(UC_ARM_REG_R0, 0)

def otPlatCryptoAesInit(uc):
    """Skip AES init"""
    uc.reg_write(UC_ARM_REG_R0, 0)

def otPlatCryptoAesSetKey(uc):
    """Skip AES set key"""
    uc.reg_write(UC_ARM_REG_R0, 0)

def otPlatCryptoAesEncrypt(uc):
    """Skip AES encrypt"""
    uc.reg_write(UC_ARM_REG_R0, 0)

def otPlatCryptoAesFree(uc):
    """Skip AES free"""
    uc.reg_write(UC_ARM_REG_R0, 0)


def appError(uc):
    """
    void appError(chip::ChipError err)
    R0 = ChipError value (32-bit error code)

    This handler logs the error but allows execution to continue
    instead of aborting.
    """
    err_code = uc.reg_read(UC_ARM_REG_R0)
    _log_error(f"[APP] appError called with error code {err_code} (0x{err_code:08x})\n")
    # Don't abort - let the app continue


def UARTDRV_Transmit(uc):
    """
    UART transmit hook to capture UART output.
    Ecode_t UARTDRV_Transmit(UARTDRV_Handle_t handle, uint8_t *data, UARTDRV_Count_t count, ...)
    R0 = handle, R1 = data buffer, R2 = count
    """
    buffer_ptr = uc.reg_read(UC_ARM_REG_R1)
    count = uc.reg_read(UC_ARM_REG_R2)

    if buffer_ptr == 0 or count == 0:
        uc.reg_write(UC_ARM_REG_R0, 0)  # Return success
        return

    try:
        count = min(count, 1024)
        data = uc.mem_read(buffer_ptr, count)
        _log_info(data.decode('latin1', errors='replace'))
    except Exception as e:
        _log_info(f"[UART] (error: {e})\n")

    uc.reg_write(UC_ARM_REG_R0, 0)  # Return ECODE_EMDRV_UARTDRV_OK


# ============================================================================
# Project-Specific Hooks
# ============================================================================
#
# Matter Provision::Storage hooks and other device-specific functions have been
# moved to project-specific directories:
#
# - BRD2601B Matter provisioning:
#   fuzzware_harness.user_hooks.projects.silabs_brd2601b.hooks
#
# - Heiman Smoke Detector (Zigbee, UART protocol, hardware bypass):
#   fuzzware_harness.user_hooks.projects.silabs_heiman_smoke.hooks
#
# See user_hooks/projects/README.md for documentation on creating project-specific hooks.
# ============================================================================
