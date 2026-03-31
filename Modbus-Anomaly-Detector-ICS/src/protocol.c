#include <stdio.h>
#include <math.h>
#include "../include/modbus_def.h"

// 全局变量：保存上一个包的信息（用于计算间隔/变化幅度）
static ModbusPacket last_pkt = { 0 };
static u32 read_count = 0;  // 读指令计数
static u32 write_count = 0; // 写指令计数

// 组员B实现：解析Modbus包，提取特征填充Feature
void parse_modbus(ModbusPacket* pkt, Feature* feat) {
    // TODO 1. 功能码判断：统计读写次数，计算读写比例
    if (pkt->func_code == MODBUS_FUNC_READ) {
        read_count++;
    }
    else if (pkt->func_code == MODBUS_FUNC_WRITE) {
        write_count++;
    }
    feat->read_write_ratio = (write_count == 0) ? (float)read_count : (float)read_count / write_count;

    // TODO 2. 计算指令间隔：当前时间戳 - 上一个包的时间戳
    if (last_pkt.timestamp != 0) {
        feat->interval_ms = pkt->timestamp - last_pkt.timestamp;
    }
    else {
        feat->interval_ms = 0; // 第一个包，间隔为0
    }

    // TODO 3. 计算寄存器值变化幅度：|当前值-上一值|
    feat->value_change = abs((int)pkt->reg_value - (int)last_pkt.reg_value);

    // TODO 4. 滑动窗口统计：统计窗口内数据包数量（如窗口大小100个）
    feat->window_pkt_num++;
    if (feat->window_pkt_num > 100) {
        feat->window_pkt_num = 1;
    }

    // TODO 5. 初步计算异常分数（基础版，可由AI模块再优化）
    feat->anomaly_score = 0.0f;
    if (feat->interval_ms < 10) { // 指令间隔过短，初步判定异常
        feat->anomaly_score += 0.5f;
    }
    if (feat->value_change > 100) { // 数值突变，初步判定异常
        feat->anomaly_score += 0.5f;
    }

    // 更新上一个包的信息
    last_pkt = *pkt;
}