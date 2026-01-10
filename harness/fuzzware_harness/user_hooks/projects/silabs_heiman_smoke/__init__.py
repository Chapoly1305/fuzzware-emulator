"""
Heiman Smoke Detector Hooks

Project-specific hooks for Heiman smoke detector (EFR32MG1x Zigbee).
Provides UART protocol fuzzing, radio hardware bypass, and device-specific hooks.

Usage in config.yml:
    handlers:
      UARTDRV_Receive:
        handler: fuzzware_harness.user_hooks.projects.silabs_heiman_smoke.hooks.UARTDRV_Receive
"""

# Import all hooks for convenience
from .hooks import *
