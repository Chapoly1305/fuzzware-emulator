"""
Silicon Labs BRD2601B Matter Lighting Example Hooks

Project-specific hooks for BRD2601B (EFR32MG24) Matter lighting firmware.
Provides Matter Provision::Storage hooks with device-specific configuration.

Usage in config.yml:
    handlers:
      _ZN4chip11DeviceLayer6Silabs9Provision7Storage11GetVendorIdERt:
        handler: fuzzware_harness.user_hooks.projects.silabs_brd2601b.hooks.ProvisionStorage_GetVendorId
"""

# Import all hooks for convenience
from .hooks import *
