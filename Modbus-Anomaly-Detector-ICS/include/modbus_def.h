#ifndef MODBUS_DEF_H
#define MODBUS_DEF_H

#include <stdint.h>  // 引入标准固定位宽类型，避免跨平台问题

// 宏定义：避免魔法数字，便于维护
#define IP_STR_LEN    16  // IP地址字符串长度（xxx.xxx.xxx.xxx\0）
#define REASON_LEN    64  // 异常原因描述长度
#define MODBUS_FUNC_READ  0x03  // Modbus读功能码（常用）
#define MODBUS_FUNC_WRITE 0x06  // Modbus写功能码（常用）

// 类型别名：简化代码，提升可读性
typedef uint8_t  u8;
typedef uint16_t u16;
typedef int32_t  i32;
typedef float    f32;

// 抓包后得到的原始Modbus包（组员A填充）
typedef struct {
    u8  src_ip[IP_STR_LEN];   // 源IP地址
    u8  dst_ip[IP_STR_LEN];   // 目的IP地址
    u8  func_code;            // Modbus功能码
    u16 reg_addr;             // 寄存器地址
    u16 reg_value;            // 寄存器值
    i32 timestamp;            // 时间戳（秒级/毫秒级，统一用ms）
} ModbusPacket;

// 从协议里提取的特征（组员B填充）
typedef struct {
    i32 interval_ms;          // 指令间隔（ms）
    f32 read_write_ratio;     // 读写比例（读次数/写次数）
    i32 value_change;         // 数值变化幅度（|当前值-上一值|）
    f32 anomaly_score;        // 异常分数（0~1，分数越高越异常）
    // 拓展：新增赛项创新点-滑动窗口统计
    u16 window_pkt_num;       // 滑动窗口内数据包数量
} Feature;

// AI推理结果（组员C填充）
typedef struct {
    i32 is_anomaly;           // 0-正常 1-异常
    f32 score;                // 异常置信度（0~1）
    u8  reason[REASON_LEN];   // 异常原因描述（如"指令间隔过短"）
} AIResult;

#endif // MODBUS_DEF_H