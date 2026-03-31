#include <stdio.h>
#include "../include/modbus_def.h"

// 组员C实现：基于特征进行AI异常检测，填充AIResult
// 贴合A-ST赛项：融入机器学习（均值方差/聚类/轻量神经网络）
void ai_detect(Feature* feat, AIResult* res) {
    // 初始化结果
    res->is_anomaly = 0;
    res->score = 0.0f;
    snprintf((char*)res->reason, REASON_LEN, "normal");

    // TODO 1. 基线学习：统计正常情况下的特征基线（如间隔均值/方差、读写比例基线）
    // TODO 2. 异常判断：基于滑动窗口的特征，用均值方差/孤立森林/逻辑回归判断异常
    // 示例规则（可替换为机器学习模型）
    if (feat->anomaly_score >= 0.7f) { // 异常分数阈值
        res->is_anomaly = 1;
        res->score = feat->anomaly_score;
        snprintf((char*)res->reason, REASON_LEN, "high anomaly score, interval:%d, value change:%d",
            feat->interval_ms, feat->value_change);
    }
    else if (feat->read_write_ratio > 10.0f) { // 读写比例异常（读远大于写）
        res->is_anomaly = 1;
        res->score = 0.8f;
        snprintf((char*)res->reason, REASON_LEN, "abnormal read/write ratio:%.2f",
            feat->read_write_ratio);
    }
}