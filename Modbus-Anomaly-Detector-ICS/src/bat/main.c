#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/select.h>
#include <termios.h>
#include "../include/modbus_def.h"

void capture_packet(ModbusPacket *pkt);
void parse_modbus(ModbusPacket *pkt, Feature *feat);
void ai_detect(Feature *feat, AIResult *res);
void execute_protect(AIResult *res, ModbusPacket *pkt);
void init_log(void);
void close_log(void);
void web_update_status(ModbusPacket *pkt, Feature *feat, AIResult *res);
void start_http_server(void);
void stop_http_server(void);
void init_web(void);

static volatile int keep_running = 1;

// 检查是否有键盘输入（非阻塞），返回输入的字符，如果没有输入则返回 0
static char check_keypress(void) {
    struct timeval tv = {0, 0};
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(STDIN_FILENO, &fds);
    if (select(STDIN_FILENO + 1, &fds, NULL, NULL, &tv) > 0) {
        char ch = getchar();
        // 清除缓冲区中的换行符
        while (getchar() != '\n' && !feof(stdin));
        return ch;
    }
    return 0;
}

int main(int argc, char *argv[]) {
    init_log();
    printf("Modbus Anomaly Detector for ICS - A-ST Edition\n");
    printf("Please run as root and ensure libpcap & iptables are installed.\n");

    init_web();
    start_http_server();

    printf("Starting packet capture, press 'q' and then Enter to quit...\n\n");

    while (keep_running) {
        ModbusPacket pkt = {0};
        Feature feat = {0};
        AIResult res = {0};

        // 非阻塞抓包（内部使用 select 超时 100ms）
        capture_packet(&pkt);

        // 检查用户是否输入了 'q'
        char ch = check_keypress();
        if (ch == 'q' || ch == 'Q') {
            printf("\nUser requested exit.\n");
            keep_running = 0;
            break;
        }

        // 空包或超时返回的包（timestamp 和 func_code 均为 0），跳过
        if (pkt.timestamp == 0 && pkt.func_code == 0) {
            usleep(10000);
            continue;
        }

        parse_modbus(&pkt, &feat);
        ai_detect(&feat, &res);
        execute_protect(&res, &pkt);
        web_update_status(&pkt, &feat, &res);

        if (res.is_anomaly) {
            printf("[!] ANOMALY: %s -> %s, reason: %s\n", pkt.src_ip, pkt.dst_ip, res.reason);
        } else {
            printf("[*] NORMAL: %s, interval=%dms, change=%d\n", pkt.src_ip, feat.interval_ms, feat.value_change);
        }
    }

    stop_http_server();
    close_log();
    printf("Program terminated.\n");
    return 0;
}
