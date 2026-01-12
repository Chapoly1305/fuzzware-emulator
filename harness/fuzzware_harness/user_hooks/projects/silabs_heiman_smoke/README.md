# Heiman Smoke Detector Hooks

Project-specific hooks for the Heiman smoke detector firmware (Silicon Labs EFR32MG1x Zigbee).

## Overview

This module provides device-specific hooks for fuzzing Heiman smoke detector firmware, including:
- Custom UART protocol implementation with packet wrapping
- Radio/RAIL/Zigbee hardware bypass hooks
- Crypto, flash, and GPIO hooks
- Interrupt injection for UART fuzzing

## Firmware Details

- **Device**: Heiman Smoke Detector
- **MCU**: EFR32MG1x (ARM Cortex-M4)
- **Protocol**: Zigbee (IEEE 802.15.4)
- **Communication**: Custom UART protocol

## UART Protocol

The Heiman smoke detector uses a custom UART protocol with the following format:

```
[Magic] [Length] [DevType] [ProtoVer] [Payload...] [CRC]
 AA 55    2B      1B         1B         Variable      2B
```

### Protocol Constants

```python
UART_MAGIC = b'\xAA\x55'     # Packet start marker
UART_DEV_TYPE = 0x60          # Device type: smoke detector
UART_PROTO_VER = 0x06         # Protocol version
```

### CRC Calculation

CRC-16 is calculated over length, device type, protocol version, and payload:
- Polynomial: 0x8005
- Initial value: 0xFFFF
- Final XOR: 0x0000

## Fuzzing Modes

### 1. Full Initialization Mode

Fuzz input injected after full firmware initialization.

**Config**: `config.yml`

### 2. Direct UART Fuzzing Mode

Bypasses initialization, directly enters UART parsing loop.

**Config**: `config_uart_direct.yml`

**Entry point**: `uart_fuzz_entry` hook jumps directly to UART RX handling

## Provided Hooks

### UART Fuzzing Hooks

| Function | Purpose |
|----------|---------|
| `UARTDRV_Receive` | Wraps fuzz input as UART packets with proper protocol header/CRC |
| `EUSART_Rx` | Alternative UART RX hook for direct register access |
| `uart_fuzz_entry` | Direct entry point for bypassing initialization |
| `uart_interrupt_inject` | Injects UART RX interrupt on SysTick |

### Radio/RAIL Bypass Hooks

Skip hardware operations for:
- `txCurrentPacket`, `efr32RadioProcess` - Radio TX/RX processing
- `otPlatRadioTransmit/Receive/Sleep/Enable/Disable` - OpenThread radio
- `radioSetIdle`, `efr32RailConfigLoad` - RAIL configuration
- `RAIL_InitTxPowerCurvesAlt`, `RAIL_CalibrateIrAlt` - Calibration
- `RAIL_IsInitialized` - Returns true without hardware

### Crypto Hooks

Skip crypto hardware operations:
- `sli_radioaes_acquire/release` - Radio AES lock
- `aes_ccm_radio`, `sli_aes_crypt_ctr_radio` - AES operations
- `psa_generate_random`, `sl_se_get_random` - Random generation
- `sli_se_mailbox_execute_command` - Secure Element commands

### Flash/MSC Hooks

Skip flash operations:
- `mscStatusWait` - Skip MSC status polling (infinite loop bypass)
- `MSC_ErasePage`, `MSC_WriteWord` - Skip flash write operations

### Timer/Alarm Hooks

- `otPlatAlarmMilliGetNow` - Returns fake timestamp
- `otPlatAlarmMilliStartAt/Stop` - Skip alarm configuration
- `efr32AlarmInit` - Skip alarm initialization

### Debug Interceptors

- `xQueueGenericSend_intercept` - Captures UART response queue entries
- `QueuePutWrapper_intercept` - Logs queued UART responses

## Usage in config.yml

### Full Initialization Config

```yaml
handlers:
  # UART fuzzing
  UARTDRV_Receive:
    handler: fuzzware_harness.user_hooks.projects.silabs_heiman_smoke.hooks.UARTDRV_Receive

  # Radio bypass (35+ functions)
  txCurrentPacket:
    handler: fuzzware_harness.user_hooks.projects.silabs_heiman_smoke.hooks.txCurrentPacket
  efr32RadioProcess:
    handler: fuzzware_harness.user_hooks.projects.silabs_heiman_smoke.hooks.efr32RadioProcess
  # ... (see config.yml for full list)

  # Crypto bypass
  sli_radioaes_acquire:
    handler: fuzzware_harness.user_hooks.projects.silabs_heiman_smoke.hooks.sli_radioaes_acquire
  aes_ccm_radio:
    handler: fuzzware_harness.user_hooks.projects.silabs_heiman_smoke.hooks.aes_ccm_radio
  # ... (see config.yml for full list)

  # Flash bypass
  mscStatusWait:
    handler: fuzzware_harness.user_hooks.projects.silabs_heiman_smoke.hooks.mscStatusWait
  MSC_ErasePage:
    handler: fuzzware_harness.user_hooks.projects.silabs_heiman_smoke.hooks.MSC_ErasePage

  # Interrupt injection
  uart_interrupt_inject:
    handler: fuzzware_harness.user_hooks.projects.silabs_heiman_smoke.hooks.uart_interrupt_inject

# Interrupt configuration
interrupt_triggers:
  - addr: -0x1  # SysTick
    every_nth_tick: 500
    fuzz_mode: fuzzed
```

### Direct UART Fuzzing Config

```yaml
handlers:
  # Direct entry to UART parsing
  uart_fuzz_entry:
    handler: fuzzware_harness.user_hooks.projects.silabs_heiman_smoke.hooks.uart_fuzz_entry
    do_return: false  # Jump directly to UART handler

  # Same radio/crypto/flash bypass as above...
```

## Platform-Level Hooks

This project uses platform-level hooks from `generic/silabs.py`:
- Timers: `sl_sleeptimer_get_tick_count`, `sl_sleeptimer_get_timer_frequency`
- Logging: `SEGGER_RTT_Write`, `rtt_write`

## Base Inputs

The example includes seed inputs for UART commands:
- `base_inputs_raw/cmd_01.bin` - Command 0x01 (1 byte)
- `base_inputs_raw/cmd_02.bin` - Command 0x02 (1 byte)
- `base_inputs_raw/cmd_01_payload.bin` - Command 0x01 with payload (5 bytes)
- `base_inputs_raw/cmd_02_payload.bin` - Command 0x02 with payload (8 bytes)

Fuzzware automatically wraps these with UART protocol (magic, length, CRC).

## Logging

Logs are written to:
- **stdout**: When `FUZZWARE_LOG_LEVEL` is DEBUG or INFO
- **File**: `/tmp/fuzzware_heiman.log` (default, override with `FUZZWARE_LOG_FILE` env var)

Log level controlled by `FUZZWARE_LOG_LEVEL` environment variable:
- `DEBUG`: Verbose logging including packet parsing details
- `INFO`: Standard logging
- `WARN`: Warnings only (default)

## Hardware Addresses

Key addresses referenced by hooks:
- `UART_RX_BUFFER_ADDR = 0x200187EC` - UART receive buffer location

## Example

See `/workspaces/fuzzware/examples/siliconlabs/heiman-smoke-detector/` for complete working examples:
- `config.yml` - Full initialization fuzzing

## Known Issues

The firmware contains 274+ infinite loop patterns for radio operations. This module bypasses all of them by hooking radio functions before they enter spin-wait loops.

## Related Hooks

- **Generic Silicon Labs hooks**: `fuzzware_harness.user_hooks.generic.silabs`
- **Other projects**: See `../README.md`
