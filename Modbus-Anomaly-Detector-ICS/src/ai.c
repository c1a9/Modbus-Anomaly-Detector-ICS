#include <stdio.h>
#include <string.h>
#include <math.h>
#include "../include/modbus_def.h"

static float baseline_mean = 0.0f, baseline_std = 0.0f;
static int baseline_ready = 0;

void ai_detect(Feature *feat, AIResult *res) {
    res->is_anomaly = 0;
    res->score = 0.0f;
    snprintf((char*)res->reason, REASON_LEN, "normal");

    if (feat->avg_interval > 0 && feat->std_interval > 0) {
        if (!baseline_ready) {
            baseline_mean = feat->avg_interval;
            baseline_std = feat->std_interval;
            baseline_ready = 1;
        } else {
            baseline_mean = 0.9f * baseline_mean + 0.1f * feat->avg_interval;
            baseline_std  = 0.9f * baseline_std  + 0.1f * feat->std_interval;
        }
    }

    float anomaly_score = 0.0f;
    char reason_buf[REASON_LEN] = {0};

    if (baseline_ready && baseline_std > 1e-6) {
        float z_score = fabsf(feat->interval_ms - baseline_mean) / baseline_std;
        if (z_score > 3.0f) {
            anomaly_score += 0.6f;
            snprintf(reason_buf + strlen(reason_buf), REASON_LEN - strlen(reason_buf),
                     "interval_3sigma=%.2f ", z_score);
        } else if (z_score > 2.0f) {
            anomaly_score += 0.3f;
        }
    }

    if (feat->value_change > 500) {
        anomaly_score += 0.4f;
        strncat(reason_buf, "value_change>500 ", REASON_LEN - strlen(reason_buf) - 1);
    }

    if (feat->read_write_ratio > 10.0f) {
        anomaly_score += 0.4f;
        snprintf(reason_buf + strlen(reason_buf), REASON_LEN - strlen(reason_buf),
                 "read_write_ratio=%.1f ", feat->read_write_ratio);
    } else if (feat->read_write_ratio < 0.1f && feat->read_write_ratio > 0) {
        anomaly_score += 0.3f;
        strncat(reason_buf, "too_many_writes ", REASON_LEN - strlen(reason_buf) - 1);
    }

    if (feat->interval_ms > 0 && 1000 / feat->interval_ms > 50) {
        anomaly_score += 0.3f;
        strncat(reason_buf, "high_frequency ", REASON_LEN - strlen(reason_buf) - 1);
    }

    res->score = anomaly_score > 1.0f ? 1.0f : anomaly_score;
    if (res->score >= 0.55f) {
        res->is_anomaly = 1;
        snprintf((char*)res->reason, REASON_LEN, "anomaly_score=%.2f, %s", res->score, reason_buf);
    } else {
        snprintf((char*)res->reason, REASON_LEN, "normal (score=%.2f)", res->score);
    }
}
