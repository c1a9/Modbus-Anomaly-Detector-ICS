#include <stdio.h>
#include <string.h>
#include <math.h>
#include "modbus_def.h"
#include "session_manager.h"
#include "detector.h"

typedef struct detection_rule {
    char name[64];
    int enabled;
    float weight;
    float (*evaluate)(session_state_t *sess, feature_vector_t *feat, const modbus_packet_t *pkt);
} detection_rule_t;

static float rule_interval_anomaly(session_state_t *sess, feature_vector_t *feat, const modbus_packet_t *pkt) {
    (void)pkt;
    if (!sess->baseline_ready || sess->baseline_interval_std < 1.0f || feat->interval_ms <= 0)
        return 0.0f;
    float z = fabsf(feat->interval_ms - sess->baseline_interval_mean) / sess->baseline_interval_std;
    if (z > 4.0f) return 1.0f;
    if (z > 3.0f) return 0.7f;
    if (z > 2.0f) return 0.3f;
    return 0.0f;
}

static float rule_value_change_anomaly(session_state_t *sess, feature_vector_t *feat, const modbus_packet_t *pkt) {
    (void)sess;
	if ((pkt->func_code == MODBUS_FC_WRITE_SINGLE_REGISTER ||
     pkt->func_code == MODBUS_FC_WRITE_MULTIPLE_REGISTERS) &&
    feat->value_change > 5000)
    return 0.8f;
    if (feat->value_change > 10000) return 0.9f;
    return 0.0f;
}

static float rule_write_frequency(session_state_t *sess, feature_vector_t *feat, const modbus_packet_t *pkt) {
    (void)sess;
    if ((pkt->func_code == MODBUS_FC_WRITE_SINGLE_REGISTER ||
         pkt->func_code == MODBUS_FC_WRITE_MULTIPLE_REGISTERS) &&
        feat->pkt_freq_hz > 50.0f)
        return 0.85f;
    return 0.0f;
}

static float rule_suspicious_function_code(session_state_t *sess, feature_vector_t *feat, const modbus_packet_t *pkt) {
    (void)sess; (void)feat;
    if (pkt->func_code == 0x08) return 0.6f;
    return 0.0f;
}

static float rule_read_write_imbalance(session_state_t *sess, feature_vector_t *feat, const modbus_packet_t *pkt) {
    (void)pkt;
    if (sess->pkt_count > 100 && feat->read_write_ratio < 0.01f && sess->write_count > 200)
        return 0.7f;
    return 0.0f;
}

static detection_rule_t rules[] = {
    {"interval_3sigma",     1, 0.35f, rule_interval_anomaly},
    {"value_change_large",  1, 0.25f, rule_value_change_anomaly},
    {"high_freq_write",     1, 0.20f, rule_write_frequency},
    {"suspicious_func_code",1, 0.10f, rule_suspicious_function_code},
    {"rw_imbalance",        1, 0.10f, rule_read_write_imbalance},
    {"", 0, 0.0f, NULL}
};

void detect_anomaly(session_state_t *sess, const modbus_packet_t *pkt,
                    feature_vector_t *feat, detection_result_t *result) {
    memset(result, 0, sizeof(detection_result_t));
    strcpy(result->reason, "normal");
    float total_score = 0.0f, weight_sum = 0.0f;
    char reason_buf[REASON_LEN] = {0};
    for (int i = 0; rules[i].evaluate != NULL; i++) {
        if (!rules[i].enabled) continue;
        float score = rules[i].evaluate(sess, feat, pkt);
        if (score > 0.01f) {
            total_score += score * rules[i].weight;
            weight_sum += rules[i].weight;
            char tmp[256];
            // 限制规则名输出长度避免截断警告
            snprintf(tmp, sizeof(tmp), "%.60s:%.2f ", rules[i].name, score);
            strncat(reason_buf, tmp, REASON_LEN - strlen(reason_buf) - 1);
        }
    }
    if (weight_sum > 0)
        result->confidence = total_score / weight_sum;
    sess->anomaly_score_ema = 0.7f * sess->anomaly_score_ema + 0.3f * result->confidence;
    result->confidence = sess->anomaly_score_ema;
    if (result->confidence >= 0.75f) {
        result->is_anomaly = 1;
        result->severity = 3;
    } else if (result->confidence >= 0.55f) {
        result->is_anomaly = 1;
        result->severity = 2;
    } else if (result->confidence >= 0.35f) {
        result->severity = 1;
    }
    if (result->is_anomaly || result->severity >= 1)
        snprintf(result->reason, REASON_LEN, "score=%.2f %s", result->confidence, reason_buf);
}
