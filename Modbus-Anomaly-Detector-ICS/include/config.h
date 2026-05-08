#ifndef CONFIG_H
#define CONFIG_H

typedef struct {
    char interface[32];
    int daemonize;
    int web_port;
    char log_file[256];
    float anomaly_threshold_high;
    float anomaly_threshold_medium;
    int enable_tcp_rst;
} config_t;

extern config_t g_config;

int load_config(const char *filename);

#endif
