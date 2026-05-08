#ifndef MODBUS_DEF_H
#define MODBUS_DEF_H

#include <stdint.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define IP_STR_LEN      16
#define REASON_LEN      256
#define MODBUS_PORT     502

// Modbus 功能码（常用）
#define MODBUS_FC_READ_COILS              0x01
#define MODBUS_FC_READ_DISCRETE_INPUTS    0x02
#define MODBUS_FC_READ_HOLDING_REGISTERS  0x03
#define MODBUS_FC_READ_INPUT_REGISTERS    0x04
#define MODBUS_FC_WRITE_SINGLE_COIL       0x05
#define MODBUS_FC_WRITE_SINGLE_REGISTER   0x06
#define MODBUS_FC_WRITE_MULTIPLE_COILS    0x0F
#define MODBUS_FC_WRITE_MULTIPLE_REGISTERS 0x10

typedef struct session_state {
    uint32_t src_ip;
    uint32_t dst_ip;
    // uint16_t dst_port;   // 不再使用，可删除或保留但忽略
    
    int64_t last_timestamp_ms;
    uint16_t last_func_code;
    uint16_t last_reg_addr;
    uint16_t last_reg_value;
    
    uint64_t read_count;
    uint64_t write_count;
    uint64_t pkt_count;
    
    #define INTERVAL_WINDOW_SIZE 100
    int32_t intervals[INTERVAL_WINDOW_SIZE];
    int interval_idx;
    int interval_count;
    
    int baseline_ready;
    float baseline_interval_mean;
    float baseline_interval_std;
    int64_t baseline_established_time;
    
    float anomaly_score_ema;
    
    struct session_state *next;
} session_state_t;

// 解析后的Modbus包
typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  func_code;
    uint16_t reg_addr;
    uint16_t reg_value;
    uint16_t quantity;                // 对于批量操作
    int64_t  timestamp_ms;
    uint8_t  raw_pdu[253];            // 原始PDU（最大253字节）
    uint16_t pdu_len;
} modbus_packet_t;

// 特征向量（传递给检测引擎）
typedef struct {
    int32_t interval_ms;              // 与上一次同会话报文间隔
    float read_write_ratio;           // 读写比
    int32_t value_change;             // 寄存器值变化量
    uint16_t func_code;
    float pkt_freq_hz;                // 当前频率（基于最近间隔）
} feature_vector_t;

// 检测结果
typedef struct {
    int is_anomaly;
    float confidence;                 // 置信度 0.0~1.0
    char reason[REASON_LEN];
    int severity;                     // 0: info, 1: low, 2: medium, 3: high, 4: critical
} detection_result_t;

#endif
