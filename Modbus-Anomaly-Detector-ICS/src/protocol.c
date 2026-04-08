#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "../include/modbus_def.h"

static ModbusPacket last_pkt = {0};
static u32 read_count = 0, write_count = 0;
static i32 intervals[100] = {0};
static int interval_index = 0, interval_count = 0;

void parse_modbus(ModbusPacket *pkt, Feature *feat) {
    // read/write ratio
    if (pkt->func_code == MODBUS_FUNC_READ) read_count++;
    else if (pkt->func_code == MODBUS_FUNC_WRITE) write_count++;
    feat->read_write_ratio = (write_count == 0) ? (float)read_count : (float)read_count / write_count;

    // interval
    if (last_pkt.timestamp != 0) {
        feat->interval_ms = pkt->timestamp - last_pkt.timestamp;
        if (feat->interval_ms < 0) feat->interval_ms = 0;
    } else {
        feat->interval_ms = 0;
    }

    // value change
    feat->value_change = abs((int)pkt->reg_value - (int)last_pkt.reg_value);

    // sliding window
    static u16 window_counter = 0;
    window_counter = (window_counter % 100) + 1;
    feat->window_pkt_num = window_counter;

    if (feat->interval_ms > 0) {
        intervals[interval_index] = feat->interval_ms;
        interval_index = (interval_index + 1) % 100;
        if (interval_count < 100) interval_count++;
    }

    // avg and std of intervals
    if (interval_count >= 2) {
        double sum = 0;
        for (int i = 0; i < interval_count; i++) sum += intervals[i];
        feat->avg_interval = (float)(sum / interval_count);
        double var = 0;
        for (int i = 0; i < interval_count; i++) {
            double diff = intervals[i] - feat->avg_interval;
            var += diff * diff;
        }
        feat->std_interval = (float)sqrt(var / interval_count);
    } else {
        feat->avg_interval = 0;
        feat->std_interval = 0;
    }

    // simple anomaly score
    feat->anomaly_score = 0.0f;
    if (feat->interval_ms > 0 && feat->interval_ms < 10) feat->anomaly_score += 0.4f;
    if (feat->value_change > 1000) feat->anomaly_score += 0.4f;
    if (feat->read_write_ratio > 20.0f) feat->anomaly_score += 0.3f;
    if (feat->anomaly_score > 1.0f) feat->anomaly_score = 1.0f;

    last_pkt = *pkt;
}
