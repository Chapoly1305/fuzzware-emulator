"""
Heiman Smoke Detector - Project-Specific Hooks

Log files (shared with silabs.py):
- /tmp/firmware.log  - Firmware output (UART TX/RX, prints)
- /tmp/emulator.log  - Emulator debug (hooks, NVM3 traces)

This module re-exports all hooks from submodules for backward compatibility.
"""
import sys
import os
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_SP

from ...fuzz import get_fuzz

# =============================================================================
# Re-export logging utilities
# =============================================================================
from .logging import (
    DEBUG_MODE,
    FIRMWARE_LOG,
    EMULATOR_LOG,
    _fw_log,
    _emu_log,
    _emu_debug_log,
    INPUT_LOG_DIR,
    get_tx_rx_stats,
    reset_tx_rx_stats,
    increment_tx_count,
    increment_rx_count,
    _log_input,
    _save_input_log,
    _clear_input_log,
    _log_uart_packet,
)

# =============================================================================
# Re-export UART protocol utilities
# =============================================================================
from .uart_protocol import (
    UART_MAGIC,
    UART_DEV_TYPE,
    UART_PROTO_VER,
    UART_DIR_SENSOR_TO_MCU,
    UART_DIR_MCU_TO_SENSOR,
    UART_RX_BUFFER_ADDR,
    UART_RX_BUFFER_SIZE,
    FUZZ_BUFFER_ADDR,
    FUZZ_BUFFER_SIZE,
    _calc_uart_crc,
    _wrap_fuzz_as_uart_packet,
    build_uart_packet,
    reset_uart_seq,
    get_uart_seq,
)

# =============================================================================
# Re-export UART TX capture hooks
# =============================================================================
from .uart_capture import (
    xQueueGenericSend_intercept,
    QueuePutWrapper_intercept,
    UART_BuildAndSendTx,
    UART_DoTransmit,
    TxCmd_Status,
    EUSART_Tx,
    UARTDRV_ForceTransmit_hook,
)

# =============================================================================
# Re-export UART fuzzing hooks
# =============================================================================
from .uart_fuzzing import (
    UARTDRV_Receive,
    EUSART_Rx,
    uart_fuzz_entry,
    uart_fuzz_harness,
    uart_interrupt_inject,
    start_uart_fuzzing,
    uart_persistent_loop,
    DIRECT_FUZZ_BUFFER,
    HANDLER_RETURN_LOOP,
    fuzz_cmd_0x41,
    direct_handler_loop,
)

# =============================================================================
# Re-export Radio/RAIL hooks
# =============================================================================
from .radio import (
    txCurrentPacket,
    efr32RadioProcess,
    otPlatRadioTransmit,
    otPlatRadioReceive,
    otPlatRadioSleep,
    otPlatRadioEnable,
    otPlatRadioDisable,
    radioSetIdle,
    efr32RailConfigLoad,
    efr32RadioLoadChannelConfig,
    txFailedCallback,
    RAILCb_Generic,
    otPlatRadioGetRssi,
    otPlatRadioEnergyScan,
    radioProcessTransmitSecurity,
    RAIL_InitTxPowerCurvesAlt,
    RAIL_ConvertDbmToRaw,
    RAIL_ConvertRawToDbm,
    sl_rail_util_pa_init,
    RAIL_IsInitialized,
    RAIL_CalibrateIrAlt,
)

# =============================================================================
# Re-export Crypto/SE hooks
# =============================================================================
from .crypto import (
    sli_radioaes_acquire,
    sli_radioaes_release,
    aes_ccm_radio,
    sli_aes_crypt_ctr_radio,
    psa_generate_random,
    sli_se_mailbox_execute_command,
    sli_se_execute_and_wait,
    sli_se_lock_acquire,
    sli_se_lock_release,
    sl_se_init,
    sl_se_get_random,
)

# =============================================================================
# Re-export NVM3 hooks
# =============================================================================
from .nvm3 import (
    NVM3_OK,
    NVM3_ERR_KEY_NOT_FOUND,
    NVM3_ERR_NOT_OPENED,
    NVM3_ERR_NULL_HANDLE,
    NVM3_ERR_KEY_INVALID,
    nvm3_readData_bypass,
    nvm3_readPartialData_bypass,
    nvm3_readCounter_bypass,
    nvm3_writeData_bypass,
    nvm3_writeCounter_bypass,
    nvm3_incrementCounter_bypass,
    nvm3_deleteObject_bypass,
    nvm3_getObjectInfo_bypass,
    nvm3_enumObjects_bypass,
    nvm3_enumDeletedObjects_bypass,
    nvm3_open_bypass,
    nvm3_initDefault_bypass,
    nvm3_close_bypass,
    nvm3_async_operation_bypass,
    nvm3_halFlashReadWords_trace,
    nvm3_enumObjects_trace,
    nvm3_open_trace,
    nvm3_halFlashGetInfo,
)

# =============================================================================
# Re-export FreeRTOS/debug hooks
# =============================================================================
from .freertos import (
    trigger_fuzz_consumption,
    trace_blocking_call,
    osMessageQueueGet_fuzz,
    debug_appinit_reached,
    println_with_uart_redirect,
    println_mainInit_redirect,
    println_with_direct_cmd41_redirect,
    debug_trace,
    debug_kernel_start,
    debug_scheduler_start,
    debug_idle_hook,
    debug_kernel_real,
    debug_abort,
    debug_assert,
    bypass_stackoverflow_hook,
    force_return_from_assert_loop,
    trace_vStartFirstTask,
    trace_osKernelStart,
    trace_vTaskStartScheduler,
    trace_AppTaskLoop,
    trace_StartJoinHandler,
    trace_xTaskCreateStatic,
    trace_ram_callback,
    skip_ram_callback,
    sl_sleeptimer_get_timer_frequency_high,
)

# =============================================================================
# Re-export peripheral hooks
# =============================================================================
from .peripheral import (
    mscStatusWait,
    MSC_ErasePage,
    MSC_WriteWord,
    GPIO_EVEN_IRQHandler,
    GPIO_ODD_IRQHandler,
    otPlatAlarmMilliGetNow,
    otPlatAlarmMilliStartAt,
    otPlatAlarmMilliStop,
    efr32AlarmInit,
)

# =============================================================================
# Re-export debug trace hooks
# =============================================================================
from .debug_trace import (
    UART_BUFFER_ADDR,
    UART_BUFFER_SIZE,
    install_oob_memory_hook,
    trace_handler_muting,
    trace_uart_parse_entry,
    trace_after_log,
    trace_beq_cmd5,
    trace_after_magic_check,
    trace_after_validation,
    trace_ldrb_length,
    trace_before_crc_calc,
    trace_validation_failed,
    trace_crc_check,
    trace_after_crc_read,
    trace_crc_read_oob,
)
