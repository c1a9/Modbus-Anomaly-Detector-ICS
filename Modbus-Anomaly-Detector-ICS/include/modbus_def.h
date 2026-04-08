#ifndef MODBUS_DEF_H
#define MODBUS_DEF_H

#include <stdint.h>
#include <time.h>

#define IP_STR_LEN    16
#define REASON_LEN    128
#define MODBUS_FUNC_READ  0x03
#define MODBUS_FUNC_WRITE 0x06
#define MODBUS_PORT       502

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef int32_t  i32;
typedef float    f32;

typedef struct {
    u8  src_ip[IP_STR_LEN];
    u8  dst_ip[IP_STR_LEN];
    u8  func_code;
    u16 reg_addr;
    u16 reg_value;
    i32 timestamp;          // milliseconds
} ModbusPacket;

typedef struct {
    i32 interval_ms;
    f32 read_write_ratio;
    i32 value_change;
    f32 anomaly_score;
    u16 window_pkt_num;
    f32 avg_interval;
    f32 std_interval;
} Feature;

typedef struct {
    i32 is_anomaly;
    f32 score;
    u8  reason[REASON_LEN];
} AIResult;

#endif
