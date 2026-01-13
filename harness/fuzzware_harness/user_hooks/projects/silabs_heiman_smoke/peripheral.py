"""
Heiman Smoke Detector - Peripheral Hooks

Contains hooks for MSC (Flash), GPIO, and timer/alarm operations.
"""
from unicorn.arm_const import UC_ARM_REG_R0

from .logging import _emu_log

# ============================================================================
# MSC (Flash) wait hooks - skip spin-wait on flash operations
# ============================================================================

def mscStatusWait(uc):
    """
    Skip mscStatusWait @ 0x08006170
    This function spin-waits on flash controller status.
    Returns 0 (no error).
    """
    uc.reg_write(UC_ARM_REG_R0, 0)


def MSC_ErasePage(uc):
    """
    Skip MSC_ErasePage @ 0x08006200
    Returns 0 (success).
    """
    uc.reg_write(UC_ARM_REG_R0, 0)


def MSC_WriteWord(uc):
    """
    Skip MSC_WriteWord @ 0x080062a4
    Returns 0 (success).
    """
    uc.reg_write(UC_ARM_REG_R0, 0)


# ============================================================================
# GPIO IRQ handlers - skip to avoid consuming fuzz input
# ============================================================================

def GPIO_EVEN_IRQHandler(uc):
    """
    Skip GPIO_EVEN_IRQHandler @ 0x08009914
    Prevents GPIO handlers from consuming fuzz input.
    """
    _emu_log("[HEIMAN] Skipping GPIO_EVEN_IRQHandler\n")


def GPIO_ODD_IRQHandler(uc):
    """
    Skip GPIO_ODD_IRQHandler @ 0x08009938
    Prevents GPIO handlers from consuming fuzz input.
    """
    _emu_log("[HEIMAN] Skipping GPIO_ODD_IRQHandler\n")


# ============================================================================
# Alarm/Timer hooks for OpenThread
# ============================================================================

_alarm_time_ms = 0


def otPlatAlarmMilliGetNow(uc):
    """
    uint32_t otPlatAlarmMilliGetNow(void)
    Returns current millisecond time for OpenThread alarm.
    """
    global _alarm_time_ms
    _alarm_time_ms += 10  # Increment by 10ms each call
    uc.reg_write(UC_ARM_REG_R0, _alarm_time_ms & 0xFFFFFFFF)


def otPlatAlarmMilliStartAt(uc):
    """
    void otPlatAlarmMilliStartAt(otInstance*, uint32_t t0, uint32_t dt)
    Skip timer setup.
    """
    pass


def otPlatAlarmMilliStop(uc):
    """
    void otPlatAlarmMilliStop(otInstance*)
    Skip timer stop.
    """
    pass


def efr32AlarmInit(uc):
    """
    Skip efr32AlarmInit @ 0x08006708
    Skip alarm initialization.
    """
    pass
