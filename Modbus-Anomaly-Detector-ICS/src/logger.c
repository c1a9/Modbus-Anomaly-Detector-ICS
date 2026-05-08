#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <syslog.h>
#include "logger.h"
#include "config.h"

static FILE *log_fp = NULL;

void log_init(const char *ident, int facility) {
    openlog(ident, LOG_PID | LOG_CONS, facility);
    if (g_config.log_file[0]) {
        log_fp = fopen(g_config.log_file, "a");
        if (!log_fp) {
            syslog(LOG_ERR, "Failed to open log file %s", g_config.log_file);
        }
    }
    log_write(LOG_INFO, "Logger initialized");
}

void log_write(int priority, const char *format, ...) {
    va_list args;
    va_start(args, format);
    // syslog
    vsyslog(priority, format, args);
    va_end(args);
    // file log
    if (log_fp) {
        time_t now = time(NULL);
        char timebuf[32];
        strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", localtime(&now));
        fprintf(log_fp, "[%s] ", timebuf);
        va_start(args, format);
        vfprintf(log_fp, format, args);
        va_end(args);
        fprintf(log_fp, "\n");
        fflush(log_fp);
    }
}

void log_close(void) {
    if (log_fp) fclose(log_fp);
    closelog();
}
