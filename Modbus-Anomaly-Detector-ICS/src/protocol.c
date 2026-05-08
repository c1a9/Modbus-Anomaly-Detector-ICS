#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "modbus_def.h"
#include "session_manager.h"

int parse_modbus_tcp_packet(const uint8_t *payload, int payload_len,
                            modbus_packet_t *pkt_out) {
    if (!payload || payload_len < 8) return -1;
    
    uint16_t transaction_id = (payload[0] << 8) | payload[1];
    uint16_t protocol_id   = (payload[2] << 8) | payload[3];
    uint16_t length        = (payload[4] << 8) | payload[5];
    uint8_t  unit_id       = payload[6];
    (void)transaction_id; (void)length; (void)unit_id;
    
    if (protocol_id != 0) return -1;
    
    int pdu_len = payload_len - 7;
    if (pdu_len < 1) return -1;
    
    pkt_out->func_code = payload[7];
    pkt_out->pdu_len = pdu_len;
    memcpy(pkt_out->raw_pdu, payload + 7, pdu_len > 253 ? 253 : pdu_len);
    
    switch (pkt_out->func_code) {
        case MODBUS_FC_READ_COILS:
        case MODBUS_FC_READ_DISCRETE_INPUTS:
        case MODBUS_FC_READ_HOLDING_REGISTERS:
        case MODBUS_FC_READ_INPUT_REGISTERS:
            if (pdu_len >= 5) {
                pkt_out->reg_addr = (payload[8] << 8) | payload[9];
                pkt_out->quantity = (payload[10] << 8) | payload[11];
                pkt_out->reg_value = 0;
            }
            break;
            
        case MODBUS_FC_WRITE_SINGLE_COIL:
        case MODBUS_FC_WRITE_SINGLE_REGISTER:
            if (pdu_len >= 5) {
                pkt_out->reg_addr = (payload[8] << 8) | payload[9];
                pkt_out->reg_value = (payload[10] << 8) | payload[11];
            }
            break;
            
        case MODBUS_FC_WRITE_MULTIPLE_REGISTERS:
            // 正确的 FC16 请求结构（从 payload[7] 功能码之后算起）：
            // 字节 0-1: 起始地址 (payload[8], payload[9])
            // 字节 2-3: 寄存器数量 (payload[10], payload[11])
            // 字节 4:   字节数 (payload[12])
            // 字节 5-6: 第一个寄存器的值 (payload[13], payload[14])
            if (payload_len >= 15) {  // 至少要有完整的头部 + 2字节数据
                pkt_out->reg_addr = (payload[8] << 8) | payload[9];
                pkt_out->quantity = (payload[10] << 8) | payload[11];
                // 第一个写入的值在偏移13、14处
                pkt_out->reg_value = (payload[13] << 8) | payload[14];
            }
            break;
            
        default:
            pkt_out->reg_addr = 0;
            pkt_out->reg_value = 0;
            break;
    }
    
    return 0;
}
