#include <stdio.h>
#include <stdlib.h>
#include "../include/modbus_def.h"

// 声明所有组员实现的函数（统一接口，禁止修改函数名/参数）
void capture_packet(ModbusPacket* pkt);
void parse_modbus(ModbusPacket* pkt, Feature* feat);
void ai_detect(Feature* feat, AIResult* res);
void execute_protect(AIResult* res);
// 公共工具/拓展函数声明
void init_log(void);       // 日志初始化（common.c）
void web_update_status(ModbusPacket* pkt, Feature* feat, AIResult* res); // 网页更新（web.c）

int main(int argc, char* argv[]) {
    // 初始化公共模块
    init_log();
    printf("Modbus Anomaly Detector for ICS - A-ST赛项版\n");
    printf("工程启动成功，开始抓包检测...\n\n");

    // 无限循环：流水线处理Modbus包
    while (1) {
        ModbusPacket pkt = { 0 };  // 初始化结构体，避免脏数据
        Feature feat = { 0 };
        AIResult res = { 0 };

        // 流水线1：组员A - 抓包（填充pkt）
        capture_packet(&pkt);
        // 空包校验：抓包失败则跳过本次循环
        if (pkt.func_code == 0 && pkt.timestamp == 0) {
            continue;
        }

        // 流水线2：组员B - 协议解析+特征提取（pkt→feat）
        parse_modbus(&pkt, &feat);

        // 流水线3：组员C - AI异常检测（feat→res）
        ai_detect(&feat, &res);

        // 流水线4：组员D - 防护执行（根据res动作）
        execute_protect(&res);

        // 拓展流水线：网页状态更新（可选，组员F）
        web_update_status(&pkt, &feat, &res);
    }

    return EXIT_SUCCESS;
}