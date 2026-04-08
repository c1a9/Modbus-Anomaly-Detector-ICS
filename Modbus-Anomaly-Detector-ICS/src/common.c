#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <time.h>
#include <stdarg.h>
#include "../include/modbus_def.h"

static FILE *log_fp = NULL;

void init_log(void) {
    openlog("Modbus-IDS", LOG_PID | LOG_CONS, LOG_USER);
    log_fp = fopen("modbus_ids.log", "a");
    if (log_fp == NULL) {
        perror("fopen modbus_ids.log");
        exit(EXIT_FAILURE);
    }
    time_t now = time(NULL);
    fprintf(log_fp, "[%s] Modbus IDS started\n", ctime(&now));
    fflush(log_fp);
    syslog(LOG_INFO, "Modbus IDS started");
}

void close_log(void) {
    if (log_fp) {
        time_t now = time(NULL);
        fprintf(log_fp, "[%s] Modbus IDS stopped\n", ctime(&now));
        fclose(log_fp);
    }
    closelog();
}

void log_message(int level, const char *format, ...) {
    if (!log_fp) return;
    va_list args;
    va_start(args, format);
    time_t now = time(NULL);
    fprintf(log_fp, "[%s] ", ctime(&now));
    vfprintf(log_fp, format, args);
    fprintf(log_fp, "\n");
    fflush(log_fp);
    va_end(args);

    int syslog_priority;
    switch (level) {
        case 0: syslog_priority = LOG_INFO; break;
        case 1: syslog_priority = LOG_WARNING; break;
        case 2: syslog_priority = LOG_ERR; break;
        default: syslog_priority = LOG_INFO;
    }
    va_start(args, format);
    vsyslog(syslog_priority, format, args);
    va_end(args);
}
