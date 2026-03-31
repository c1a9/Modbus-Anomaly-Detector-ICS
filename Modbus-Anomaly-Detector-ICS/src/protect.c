#include <stdio.h>
#include <stdlib.h>
#include "../include/modbus_def.h"

// 组员D实现：根据AI结果执行防护动作（阻断/限流/告警/日志）
// 依赖：iptables（网络阻断）、syslog（系统日志）
void execute_protect(AIResult* res) {
    if (res->is_anomaly) {
        // TODO 1. 告警：打印控制台+写入系统日志（syslog）
        printf("[ANOMALY DETECTED] Score:%.2f, Reason:%s\n", res->score, res->reason);
        // TODO 2. 网络阻断：调用iptables命令，屏蔽异常IP（如system("iptables -A INPUT -s 192.168.1.100 -j DROP")）
        // TODO 3. 限流：限制异常IP的访问频率（如iptables限速）
        // TODO 4. 上报：将异常信息上报到态势感知平台（可选）
    }
    else {
        // 正常：打印日志（可选）
        // printf("[NORMAL] Reason:%s\n", res->reason);
    }
}