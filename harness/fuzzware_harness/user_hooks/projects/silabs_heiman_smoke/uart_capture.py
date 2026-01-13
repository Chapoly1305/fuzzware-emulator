"""
Heiman Smoke Detector - UART TX Capture Hooks

Contains hooks for capturing UART responses from the firmware.
"""
from unicorn.arm_const import (
    UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
    UC_ARM_REG_LR, UC_ARM_REG_PC
)

from .logging import _emu_log, _emu_debug_log, _log_uart_packet, increment_tx_count
from .uart_protocol import UART_RX_BUFFER_ADDR


def xQueueGenericSend_intercept(uc):
    """
    Intercept FreeRTOS queue sends to capture UART responses.
    When a response is queued, log it to emulator.log.
    """
    queue_handle = uc.reg_read(UC_ARM_REG_R0)
    item_ptr = uc.reg_read(UC_ARM_REG_R1)

    # Try to read the queued item
    if item_ptr != 0:
        try:
            # Read item data - structure unknown, dump first 64 bytes
            data = uc.mem_read(item_ptr, 64)

            # Check if this looks like a UART response (starts with AA 55 or contains it)
            if b'\xaa\x55' in data:
                idx = data.index(b'\xaa\x55')
                _emu_log(f"[UART_TX] {data[idx:idx+32].hex()}\n")
                increment_tx_count()
        except Exception as e:
            pass

    # Return pdPASS (1)
    uc.reg_write(UC_ARM_REG_R0, 1)


def QueuePutWrapper_intercept(uc):
    """
    Intercept QueuePutWrapper to capture UART response data.
    This is called when command handlers queue a response.
    """
    # Check UART RX buffer area where response might be built
    try:
        uart_area = uc.mem_read(UART_RX_BUFFER_ADDR, 64)
        if b'\xaa\x55' in uart_area:
            # Find the packet length
            aa55_idx = uart_area.find(b'\xaa\x55')
            if aa55_idx != -1 and aa55_idx + 3 < len(uart_area):
                packet_len = uart_area[aa55_idx + 2] + 4  # length + magic(2) + len(1) + crc
                if aa55_idx + packet_len <= len(uart_area):
                    uart_packet = bytes(uart_area[aa55_idx:aa55_idx + packet_len])
                    _emu_log(f"[UART_TX] {uart_packet.hex()}\n")
    except Exception as e:
        pass

    uc.reg_write(UC_ARM_REG_R0, 0)


def UART_BuildAndSendTx(uc):
    """
    Hook UART_BuildAndSendTx to capture TX packets.
    This is the main function that builds and sends UART responses.

    void UART_BuildAndSendTx(uint8_t cmd, uint8_t seq, uint16_t len, uint8_t *data)
    R0 = cmd, R1 = seq, R2 = len, R3 = data pointer
    """
    cmd = uc.reg_read(UC_ARM_REG_R0)
    seq = uc.reg_read(UC_ARM_REG_R1)
    length = uc.reg_read(UC_ARM_REG_R2)
    data_ptr = uc.reg_read(UC_ARM_REG_R3)

    _emu_debug_log(f"[UART_TX_HOOK] UART_BuildAndSendTx called: cmd=0x{cmd:02x}, seq=0x{seq:02x}, len={length}")
    _emu_log(f"[UART_TX] UART_BuildAndSendTx: cmd=0x{cmd:02x}, data_ptr=0x{data_ptr:08x}, len={length}\n")

    if data_ptr != 0 and length > 0 and length < 512:
        try:
            data = uc.mem_read(data_ptr, length)
            _emu_log(f"[UART_TX] Data: {data.hex()}\n")
        except Exception as e:
            _emu_log(f"[UART_TX] Error reading data: {e}\n")

    # Continue execution - don't skip the function
    return False


def UART_DoTransmit(uc):
    """
    Hook UART_DoTransmit to capture low-level TX.
    This hooks the BL UARTDRV_ForceTransmit at 0x80081f2 where:
    - R0 = UART handle
    - R1 = buffer pointer
    - R2 = length
    """
    buffer_ptr = uc.reg_read(UC_ARM_REG_R1)
    length = uc.reg_read(UC_ARM_REG_R2)

    _emu_log(f"[UART_TX] UART_DoTransmit: buffer=0x{buffer_ptr:08x}, len={length}\n")

    if buffer_ptr != 0 and length > 0 and length < 512:
        try:
            data = uc.mem_read(buffer_ptr, length)
            _emu_log(f"[UART_TX] TX packet: {data.hex()}\n")
            _log_uart_packet("TX", data, "Response from firmware")
            increment_tx_count()
        except Exception as e:
            _emu_log(f"[UART_TX] Error reading buffer: {e}\n")

    return False


def TxCmd_Status(uc):
    """
    Hook TxCmd_Status to capture status responses.
    void TxCmd_Status(void)
    """
    _emu_log("[UART_TX] TxCmd_Status - sending status response\n")
    return False


def EUSART_Tx(uc):
    """
    Hook low-level EUSART_Tx to capture individual bytes being sent.
    void EUSART_Tx(EUSART_TypeDef *eusart, uint8_t data)
    R0 = eusart peripheral, R1 = byte to send
    """
    byte_val = uc.reg_read(UC_ARM_REG_R1) & 0xFF
    _emu_log(f"[EUSART_TX] 0x{byte_val:02x}\n")
    return False


def UARTDRV_ForceTransmit_hook(uc):
    """
    Hook UARTDRV_ForceTransmit to capture TX data without hardware access.

    Ecode_t UARTDRV_ForceTransmit(UARTDRV_Handle_t handle, uint8_t *data, UARTDRV_Count_t count)
    R0 = UART handle, R1 = data buffer, R2 = count (length)
    Returns: ECODE_EMDRV_UARTDRV_OK (0)
    """
    handle = uc.reg_read(UC_ARM_REG_R0)
    buffer_ptr = uc.reg_read(UC_ARM_REG_R1)
    length = uc.reg_read(UC_ARM_REG_R2)

    _emu_log(f"[UARTDRV_ForceTransmit] handle=0x{handle:08x}, buffer=0x{buffer_ptr:08x}, len={length}\n")

    if buffer_ptr != 0 and length > 0 and length < 512:
        try:
            data = uc.mem_read(buffer_ptr, length)
            # Single UART_TX log for console capture
            _emu_log(f"[UART_TX] {data.hex()}\n")
            increment_tx_count()
        except Exception as e:
            _emu_log(f"[UARTDRV_ForceTransmit] Error reading buffer: {e}\n")

    # Return ECODE_EMDRV_UARTDRV_OK (0) - skip hardware access
    uc.reg_write(UC_ARM_REG_R0, 0)
