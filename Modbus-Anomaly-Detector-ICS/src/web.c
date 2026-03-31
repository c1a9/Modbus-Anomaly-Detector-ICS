#include <stdio.h>
#include "../include/modbus_def.h"

// 组员F实现：网页状态更新，将检测数据推送到前端（贴合赛项展示效果）
// 方案：基于HTTP/WSGI，将数据写入JSON文件，前端页面轮询读取
void web_update_status(ModbusPacket* pkt, Feature* feat, AIResult* res) {
    // TODO 1. 拼接JSON数据：包含pkt/feat/res所有关键信息
    // TODO 2. 将JSON数据写入web目录下的status.json文件
    // TODO 3. 前端页面（HTML/JS）轮询读取status.json，实时展示检测结果
    // 测试占位
    FILE* web_fp = fopen("web/status.json", "w");
    if (web_fp != NULL) {
        fprintf(web_fp, "{\"src_ip\":\"%s\",\"func_code\":%d,\"is_anomaly\":%d,\"reason\":\"%s\"}",
            pkt->src_ip, pkt->func_code, res->is_anomaly, res->reason);
        fclose(web_fp);
    }
}