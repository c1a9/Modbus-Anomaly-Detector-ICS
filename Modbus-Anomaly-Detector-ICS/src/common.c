#include <stdio.h>
#include <syslog.h>
#include "../include/modbus_def.h"

// 组员E实现：公共工具函数-日志初始化（系统日志+文件日志）
void init_log(void) {
    // TODO 1. 初始化系统日志：openlog
    openlog("Modbus-IDS", LOG_PID | LOG_CONS, LOG_USER);
    // TODO 2. 创建文件日志：fopen打开日志文件，设置追加模式
    FILE* log_fp = fopen("modbus_ids.log", "a+");
    if (log_fp == NULL) {
        perror("fopen log file failed");
        exit(EXIT_FAILURE);
    }
    fprintf(log_fp, "Modbus IDS Log Start - A-ST赛项版\n");
    fclose(log_fp);
    // TODO 3. 其他公共工具：时间戳获取、IP合法性校验、数据转换等
}