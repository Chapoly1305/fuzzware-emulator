"""
Fuzzware User Hooks - Project-Specific Hooks

This directory contains project-specific hooks for different firmware/devices.
Each subdirectory represents a specific project with device-specific logic.

Available projects:
- silabs_brd2601b: Silicon Labs BRD2601B Matter lighting example (EFR32MG24)
- silabs_heiman_smoke: Heiman Smoke Detector Zigbee firmware (EFR32MG1x)

Creating a new project:
1. Create a new directory: projects/your_project_name/
2. Add hooks.py with your project-specific hooks
3. Add __init__.py to export hooks
4. Add README.md documenting configuration and usage
5. Update your config.yml to reference:
   fuzzware_harness.user_hooks.projects.your_project_name.hooks.your_function
"""
