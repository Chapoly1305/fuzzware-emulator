# Silicon Labs BRD2601B Matter Lighting Hooks

Project-specific hooks for the BRD2601B (EFR32MG24) Matter lighting example firmware.

## Overview

This module provides Matter Provision::Storage hooks that return device-specific configuration values. These values would normally be stored in NVM3 flash memory, but are hardcoded here for fuzzing purposes.

## Firmware Details

- **Board**: BRD2601B (Silicon Labs Wireless Starter Kit)
- **MCU**: EFR32MG24 (ARM Cortex-M33)
- **Protocol**: Matter over Thread
- **Example**: Matter lighting application

## Configuration Values

The following provisioning values are defined in `hooks.py`:

```python
PROVISION_VENDOR_ID = 0xFFF1          # Test Vendor ID
PROVISION_PRODUCT_ID = 0x8005         # Lighting example
PROVISION_PRODUCT_NAME = b"SL_Sample"
PROVISION_VENDOR_NAME = b"Silabs"
PROVISION_SERIAL_NUMBER = b"FUZZ0001"
PROVISION_DISCRIMINATOR = 0xF00       # 3840
PROVISION_PASSCODE = 20202021         # Default Matter test passcode
PROVISION_HW_VERSION = 0
PROVISION_HW_VERSION_STRING = b"1.0"
PROVISION_SW_VERSION_STRING = b"v1.0"
```

### Customizing Values

To customize provisioning values for your device:

1. Edit `hooks.py`
2. Modify the `PROVISION_*` constants at the top of the file
3. Common values to customize:
   - **Vendor ID**: Your company's Matter vendor ID (get from CSA)
   - **Product ID**: Your product's unique ID
   - **Serial Number**: Device serial number
   - **Passcode**: Matter setup passcode (6-8 digits, not all same/sequential)
   - **Discriminator**: 12-bit value for Matter commissioning

## Provided Hooks

### Matter Provision::Storage Functions

| Function | Purpose | Returns |
|----------|---------|---------|
| `ProvisionStorage_GetVendorId` | Matter vendor ID | `PROVISION_VENDOR_ID` (0xFFF1) |
| `ProvisionStorage_GetProductId` | Matter product ID | `PROVISION_PRODUCT_ID` (0x8005) |
| `ProvisionStorage_GetProductName` | Product name string | `PROVISION_PRODUCT_NAME` ("SL_Sample") |
| `ProvisionStorage_GetVendorName` | Vendor name string | `PROVISION_VENDOR_NAME` ("Silabs") |
| `ProvisionStorage_GetSerialNumber` | Device serial number | `PROVISION_SERIAL_NUMBER` ("FUZZ0001") |
| `ProvisionStorage_GetSetupDiscriminator` | Matter discriminator | `PROVISION_DISCRIMINATOR` (0xF00) |
| `ProvisionStorage_GetSetupPasscode` | Matter passcode | `PROVISION_PASSCODE` (20202021) |
| `ProvisionStorage_GetHardwareVersion` | Hardware version | `PROVISION_HW_VERSION` (0) |
| `ProvisionStorage_GetHardwareVersionString` | HW version string | `PROVISION_HW_VERSION_STRING` ("1.0") |
| `ProvisionStorage_GetSoftwareVersionString` | SW version string | `PROVISION_SW_VERSION_STRING` ("v1.0") |
| `ProvisionStorage_GetProductLabel` | Product label | Reuses product name |
| `ProvisionStorage_GetProductURL` | Product URL | "https://silabs.com" |
| `ProvisionStorage_GetPartNumber` | Part number | "BRD2601B" |

### NVM3 Debug Hooks

| Function | Purpose |
|----------|---------|
| `nvm3_readData_debug` | Logs NVM3 key accesses, returns KEY_NOT_FOUND |
| `nvm3_getObjectInfo_debug` | Logs NVM3 queries, returns KEY_NOT_FOUND |

### Catch-All

| Function | Purpose |
|----------|---------|
| `ProvisionStorage_Unimplemented` | Catch-all for unhooked provision functions, returns NOT_IMPLEMENTED |

## Usage in config.yml

Add these handlers to your Fuzzware configuration file:

```yaml
handlers:
  # Matter Provision::Storage hooks (C++ mangled names)
  _ZN4chip11DeviceLayer6Silabs9Provision7Storage11GetVendorIdERt:
    handler: fuzzware_harness.user_hooks.projects.silabs_brd2601b.hooks.ProvisionStorage_GetVendorId

  _ZN4chip11DeviceLayer6Silabs9Provision7Storage12GetProductIdERt:
    handler: fuzzware_harness.user_hooks.projects.silabs_brd2601b.hooks.ProvisionStorage_GetProductId

  _ZN4chip11DeviceLayer6Silabs9Provision7Storage14GetProductNameEPcm:
    handler: fuzzware_harness.user_hooks.projects.silabs_brd2601b.hooks.ProvisionStorage_GetProductName

  _ZN4chip11DeviceLayer6Silabs9Provision7Storage13GetVendorNameEPcm:
    handler: fuzzware_harness.user_hooks.projects.silabs_brd2601b.hooks.ProvisionStorage_GetVendorName

  _ZN4chip11DeviceLayer6Silabs9Provision7Storage15GetSerialNumberEPcm:
    handler: fuzzware_harness.user_hooks.projects.silabs_brd2601b.hooks.ProvisionStorage_GetSerialNumber

  _ZN4chip11DeviceLayer6Silabs9Provision7Storage21GetSetupDiscriminatorERt:
    handler: fuzzware_harness.user_hooks.projects.silabs_brd2601b.hooks.ProvisionStorage_GetSetupDiscriminator

  _ZN4chip11DeviceLayer6Silabs9Provision7Storage17GetSetupPasscodeERj:
    handler: fuzzware_harness.user_hooks.projects.silabs_brd2601b.hooks.ProvisionStorage_GetSetupPasscode

  _ZN4chip11DeviceLayer6Silabs9Provision7Storage18GetHardwareVersionERt:
    handler: fuzzware_harness.user_hooks.projects.silabs_brd2601b.hooks.ProvisionStorage_GetHardwareVersion

  _ZN4chip11DeviceLayer6Silabs9Provision7Storage24GetHardwareVersionStringEPcm:
    handler: fuzzware_harness.user_hooks.projects.silabs_brd2601b.hooks.ProvisionStorage_GetHardwareVersionString

  _ZN4chip11DeviceLayer6Silabs9Provision7Storage24GetSoftwareVersionStringEPcm:
    handler: fuzzware_harness.user_hooks.projects.silabs_brd2601b.hooks.ProvisionStorage_GetSoftwareVersionString

  _ZN4chip11DeviceLayer6Silabs9Provision7Storage15GetProductLabelEPcm:
    handler: fuzzware_harness.user_hooks.projects.silabs_brd2601b.hooks.ProvisionStorage_GetProductLabel

  _ZN4chip11DeviceLayer6Silabs9Provision7Storage13GetProductURLEPcm:
    handler: fuzzware_harness.user_hooks.projects.silabs_brd2601b.hooks.ProvisionStorage_GetProductURL

  _ZN4chip11DeviceLayer6Silabs9Provision7Storage13GetPartNumberEPcm:
    handler: fuzzware_harness.user_hooks.projects.silabs_brd2601b.hooks.ProvisionStorage_GetPartNumber

  # NVM3 debug hooks (optional)
  nvm3_readData:
    handler: fuzzware_harness.user_hooks.projects.silabs_brd2601b.hooks.nvm3_readData_debug

  nvm3_getObjectInfo:
    handler: fuzzware_harness.user_hooks.projects.silabs_brd2601b.hooks.nvm3_getObjectInfo_debug
```

## Platform-Level Hooks

This project uses platform-level hooks from `generic/silabs.py`:
- Logging: `silabsLog`, `SEGGER_RTT_Write`, `chip_LogV`, `ot_LogVarArgs`
- Timers: `sl_sleeptimer_get_tick_count`, `otPlatAlarmMilliGetNow`
- Crypto bypass: `otPlatCryptoHmacSha256*`, `otPlatCryptoAes*`
- Utilities: `appError`

## Logging

Logs are written to:
- **stdout**: Always
- **File**: `/tmp/fuzzware_console.log` (default, override with `FUZZWARE_LOG_FILE` env var)

Log level controlled by `FUZZWARE_LOG_LEVEL` environment variable:
- `DEBUG`: Verbose NVM3 key access logs
- `INFO`: Standard logging (default)
- `WARN`: Warnings and errors only

## Example

See `/workspaces/fuzzware/examples/siliconlabs/BRD2601B/` for a complete working example.

## Related Hooks

- **Generic Silicon Labs hooks**: `fuzzware_harness.user_hooks.generic.silabs`
- **Other projects**: See `../README.md`
