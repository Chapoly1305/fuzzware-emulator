"""
Heiman Smoke Detector - Radio/RAIL/OpenThread Hooks

Contains hooks for skipping radio spin-waits and bypassing hardware operations.
The firmware has 274 infinite loop patterns (fee7 = B .-2) that poll
hardware registers. These hooks skip the functions containing them.
"""
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1

from .logging import _emu_log


# ============================================================================
# Radio Spin-Wait Skip Hooks
# ============================================================================

def txCurrentPacket(uc):
    """
    Skip txCurrentPacket @ 0x080067f0
    This function contains a spin-wait loop at 0x080069cc that blocks indefinitely
    waiting for radio TX completion. Skip and return 0 (success).
    """
    _emu_log("[HEIMAN] Skipping txCurrentPacket (radio TX spin-wait)\n")
    uc.reg_write(UC_ARM_REG_R0, 0)


def efr32RadioProcess(uc):
    """
    Skip efr32RadioProcess @ 0x08023108
    Main radio processing function that could block on hardware.
    """
    _emu_log("[HEIMAN] Skipping efr32RadioProcess\n")
    uc.reg_write(UC_ARM_REG_R0, 0)


def otPlatRadioTransmit(uc):
    """
    Skip otPlatRadioTransmit @ 0x08022e14
    OpenThread radio transmit - skip hardware interaction.
    Returns OT_ERROR_NONE (0).
    """
    _emu_log("[HEIMAN] Skipping otPlatRadioTransmit\n")
    uc.reg_write(UC_ARM_REG_R0, 0)


def otPlatRadioReceive(uc):
    """
    Skip otPlatRadioReceive @ 0x08022d0c
    OpenThread radio receive - skip hardware interaction.
    Returns OT_ERROR_NONE (0).
    """
    _emu_log("[HEIMAN] Skipping otPlatRadioReceive\n")
    uc.reg_write(UC_ARM_REG_R0, 0)


def otPlatRadioSleep(uc):
    """
    Skip otPlatRadioSleep @ 0x08022c94
    Returns OT_ERROR_NONE (0).
    """
    uc.reg_write(UC_ARM_REG_R0, 0)


def otPlatRadioEnable(uc):
    """
    Skip otPlatRadioEnable @ 0x08022c54
    Returns OT_ERROR_NONE (0).
    """
    uc.reg_write(UC_ARM_REG_R0, 0)


def otPlatRadioDisable(uc):
    """
    Skip otPlatRadioDisable @ 0x08022c6c
    Returns OT_ERROR_NONE (0).
    """
    uc.reg_write(UC_ARM_REG_R0, 0)


def radioSetIdle(uc):
    """
    Skip radioSetIdle @ 0x08022298
    Skip radio idle state setup.
    """
    _emu_log("[HEIMAN] Skipping radioSetIdle\n")
    uc.reg_write(UC_ARM_REG_R0, 0)


def efr32RailConfigLoad(uc):
    """
    Skip efr32RailConfigLoad @ 0x08022348
    Skip RAIL configuration loading.
    """
    uc.reg_write(UC_ARM_REG_R0, 0)


def efr32RadioLoadChannelConfig(uc):
    """
    Skip efr32RadioLoadChannelConfig @ 0x08022cc0
    Skip channel configuration loading.
    """
    uc.reg_write(UC_ARM_REG_R0, 0)


def txFailedCallback(uc):
    """
    Skip txFailedCallback @ 0x0802249c
    TX failure callback - skip to avoid recursion into radio code.
    """
    _emu_log("[HEIMAN] Skipping txFailedCallback\n")


def RAILCb_Generic(uc):
    """
    Skip RAILCb_Generic @ 0x080224e0
    Generic RAIL callback - skip hardware interaction.
    """
    _emu_log("[HEIMAN] Skipping RAILCb_Generic\n")


def otPlatRadioGetRssi(uc):
    """
    Skip otPlatRadioGetRssi @ 0x08022f28
    Return a fake RSSI value (-60 dBm = 0xFFFFFFC4 signed).
    """
    uc.reg_write(UC_ARM_REG_R0, 0xFFFFFFC4)


def otPlatRadioEnergyScan(uc):
    """
    Skip otPlatRadioEnergyScan @ 0x08022fa0
    Returns OT_ERROR_NOT_IMPLEMENTED (0x17).
    """
    uc.reg_write(UC_ARM_REG_R0, 0x17)


def radioProcessTransmitSecurity(uc):
    """
    Skip radioProcessTransmitSecurity @ 0x080221c8
    Skip security processing for TX.
    Returns OT_ERROR_NONE (0).
    """
    uc.reg_write(UC_ARM_REG_R0, 0)


# ============================================================================
# RAIL (Radio Abstraction Interface Layer) hooks
# ============================================================================

def RAIL_InitTxPowerCurvesAlt(uc):
    """
    Skip RAIL_InitTxPowerCurvesAlt @ 0x0800b898
    Returns RAIL_STATUS_NO_ERROR (0).
    """
    uc.reg_write(UC_ARM_REG_R0, 0)


def RAIL_ConvertDbmToRaw(uc):
    """
    RAIL_ConvertDbmToRaw @ 0x0800b8b8
    Return the input value as-is (identity mapping).
    R0 = railHandle, R1 = power (dBm * 10)
    """
    power = uc.reg_read(UC_ARM_REG_R1)
    uc.reg_write(UC_ARM_REG_R0, power)


def RAIL_ConvertRawToDbm(uc):
    """
    RAIL_ConvertRawToDbm @ 0x0800b9b4
    Return the input value as-is (identity mapping).
    """
    power = uc.reg_read(UC_ARM_REG_R1)
    uc.reg_write(UC_ARM_REG_R0, power)


def sl_rail_util_pa_init(uc):
    """
    Skip sl_rail_util_pa_init @ 0x0800ba78
    """
    uc.reg_write(UC_ARM_REG_R0, 0)


def RAIL_IsInitialized(uc):
    """
    RAIL_IsInitialized @ 0x0804dde0
    Return true (1) to indicate RAIL is "initialized".
    """
    uc.reg_write(UC_ARM_REG_R0, 1)


def RAIL_CalibrateIrAlt(uc):
    """
    Skip RAIL_CalibrateIrAlt @ 0x0804df28
    Returns RAIL_STATUS_NO_ERROR (0).
    """
    uc.reg_write(UC_ARM_REG_R0, 0)
