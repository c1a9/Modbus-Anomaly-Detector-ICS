#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "config.h"
#include "logger.h"

config_t g_config = {
    .interface = "eth0",
    .daemonize = 0,
    .web_port = 8080,
    .log_file = "/var/log/modbus_ids.log",
    .anomaly_threshold_high = 0.75f,
    .anomaly_threshold_medium = 0.55f,
    .enable_tcp_rst = 1
};

static void trim(char *s) {
    char *p = s;
    while (*p == ' ' || *p == '\t') p++;
    char *end = p + strlen(p) - 1;
    while (end > p && (*end == ' ' || *end == '\t' || *end == '\n')) end--;
    *(end + 1) = '\0';
    if (p != s) memmove(s, p, strlen(p) + 1);
}

int load_config(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) return -1;
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key = line;
        char *value = eq + 1;
        trim(key);
        trim(value);
        if (strcmp(key, "interface") == 0) {
            strncpy(g_config.interface, value, sizeof(g_config.interface)-1);
        } else if (strcmp(key, "daemonize") == 0) {
            g_config.daemonize = atoi(value);
        } else if (strcmp(key, "web_port") == 0) {
            g_config.web_port = atoi(value);
        } else if (strcmp(key, "log_file") == 0) {
            strncpy(g_config.log_file, value, sizeof(g_config.log_file)-1);
        } else if (strcmp(key, "anomaly_threshold_high") == 0) {
            g_config.anomaly_threshold_high = atof(value);
        } else if (strcmp(key, "anomaly_threshold_medium") == 0) {
            g_config.anomaly_threshold_medium = atof(value);
        } else if (strcmp(key, "enable_tcp_rst") == 0) {
            g_config.enable_tcp_rst = atoi(value);
        }
    }
    fclose(fp);
    return 0;
}
