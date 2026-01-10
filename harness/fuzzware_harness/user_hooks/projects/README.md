# Fuzzware User Hooks - Project-Specific Hooks

This directory contains project-specific hooks for different firmware/devices. Each subdirectory represents a specific project with device-specific logic, configuration values, and protocols.

## Structure

```
projects/
├── README.md                    # This file
├── silabs_brd2601b/            # Matter lighting example
│   ├── hooks.py                # Provisioning hooks
│   ├── __init__.py
│   └── README.md
└── silabs_heiman_smoke/        # Heiman smoke detector
    ├── hooks.py                # UART protocol and hardware hooks
    ├── __init__.py
    └── README.md
```

## Available Projects

### Silicon Labs BRD2601B
- **Firmware**: Matter lighting example (EFR32MG24)
- **Purpose**: Provides Matter Provision::Storage hooks with device-specific configuration
- **Use case**: Matter/Thread firmware with hardcoded provisioning data

### Heiman Smoke Detector
- **Firmware**: Zigbee smoke detector (EFR32MG1x)
- **Purpose**: UART protocol fuzzing, radio hardware bypass, device-specific hooks
- **Use case**: Zigbee firmware with custom UART protocol

## Creating a New Project

To add a new project-specific hook collection:

### 1. Create Project Directory

```bash
mkdir -p emulator/harness/fuzzware_harness/user_hooks/projects/your_project_name
```

### 2. Create hooks.py

Create `your_project_name/hooks.py` with your project-specific hooks:

```python
"""
Your Project Name - Project-Specific Hooks

Description of what this project is and what hooks it provides.
"""

import sys
import os
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1

# Configuration constants specific to this project
YOUR_CONFIG_VALUE = 0x1234

def your_hook_function(uc):
    """Your hook function"""
    # Implementation here
    pass
```

### 3. Create __init__.py

Create `your_project_name/__init__.py`:

```python
"""
Your Project Name Hooks

Brief description and usage example.
"""

from .hooks import *
```

### 4. Create README.md

Document your project's:
- Firmware description
- Configuration values and how to customize them
- Available hooks and their purpose
- Usage examples in config.yml

### 5. Update config.yml

Reference your hooks in your Fuzzware configuration:

```yaml
handlers:
  your_function_name:
    handler: fuzzware_harness.user_hooks.projects.your_project_name.hooks.your_hook_function
```

## When to Use Project-Specific vs Generic Hooks

### Use Project-Specific Hooks When:
- Hooks contain firmware-specific configuration values (IDs, serial numbers, passwords)
- Implementing custom protocols specific to one device
- Hardware-specific bypass logic tied to particular firmware
- Function offsets or structures unique to this firmware

### Use Generic Hooks When:
- Hooks work across multiple devices/firmwares (platform-level)
- Standard protocol implementations (UART, I2C, SPI)
- Common library functions (timers, logging, crypto abstraction)
- No hardcoded firmware-specific values

## Examples

### Generic Hook (reusable)
```python
# generic/silabs.py
def sl_sleeptimer_get_tick_count(uc):
    """Silicon Labs sleeptimer - works for all EFR32 devices"""
    global _tick_counter
    _tick_counter += 1000
    uc.reg_write(UC_ARM_REG_R0, _tick_counter)
```

### Project-Specific Hook (firmware-specific)
```python
# projects/silabs_brd2601b/hooks.py
PROVISION_VENDOR_ID = 0xFFF1  # Specific to this Matter device

def ProvisionStorage_GetVendorId(uc):
    """Returns THIS device's vendor ID"""
    out_ptr = uc.reg_read(UC_ARM_REG_R1)
    if out_ptr != 0:
        uc.mem_write(out_ptr, PROVISION_VENDOR_ID.to_bytes(2, 'little'))
    uc.reg_write(UC_ARM_REG_R0, 0)
```

## Benefits of Project-Specific Hooks

1. **Isolation**: Changes to one project don't affect others
2. **Customization**: Each project can have unique configuration
3. **Clarity**: Easy to identify which hooks are device-specific
4. **Scalability**: Add new projects without modifying existing code
5. **Maintainability**: Clear ownership and organization

## See Also

- Generic hooks: `../generic/`
- Zephyr RTOS hooks: `../zephyr/`
- Hook infrastructure: `../__init__.py`
