#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <arpa/inet.h>
#include "../include/modbus_def.h"

static char blocked_ips[100][IP_STR_LEN];
static int blocked_count = 0;

static int is_ip_blocked(const char *ip) {
    for (int i = 0; i < blocked_count; i++)
        if (strcmp(blocked_ips[i], ip) == 0) return 1;
    return 0;
}

static void add_blocked_ip(const char *ip) {
    if (blocked_count < 100 && !is_ip_blocked(ip)) {
        strncpy(blocked_ips[blocked_count], ip, IP_STR_LEN);
        blocked_count++;
    }
}

static void iptables_command(const char *cmd) {
    if (system(cmd) != 0) {
        syslog(LOG_WARNING, "iptables command failed: %s", cmd);
    }
}

void execute_protect(AIResult *res, ModbusPacket *pkt) {
    if (!res->is_anomaly) return;
		
    if (strcmp((char*)pkt->src_ip, "127.0.0.1") == 0) {
        printf("[INFO] Skip blocking localhost\n");
        return;
    }

    printf("\033[31m[ALERT] Anomaly detected! Source IP: %s, reason: %s\033[0m\n", pkt->src_ip, res->reason);
    syslog(LOG_ALERT, "Modbus anomaly: IP=%s, score=%.2f, reason=%s", pkt->src_ip, res->score, res->reason);

    if (!is_ip_blocked((char*)pkt->src_ip)) {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "iptables -A INPUT -s %s -j DROP", pkt->src_ip);
        iptables_command(cmd);
        snprintf(cmd, sizeof(cmd), "iptables -A OUTPUT -d %s -j DROP", pkt->src_ip);
        iptables_command(cmd);
        add_blocked_ip((char*)pkt->src_ip);
        printf("[PROTECT] Blocked IP: %s\n", pkt->src_ip);
        syslog(LOG_NOTICE, "Blocked IP: %s", pkt->src_ip);
    }

    char limit_cmd[256];
    snprintf(limit_cmd, sizeof(limit_cmd), "iptables -A INPUT -s %s -m limit --limit 10/second -j ACCEPT", pkt->src_ip);
    iptables_command(limit_cmd);
    snprintf(limit_cmd, sizeof(limit_cmd), "iptables -A INPUT -s %s -j DROP", pkt->src_ip);
    iptables_command(limit_cmd);
    printf("[PROTECT] Rate limited IP: %s (10 packets/sec)\n", pkt->src_ip);
}
