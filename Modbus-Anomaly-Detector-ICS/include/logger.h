#ifndef LOGGER_H
#define LOGGER_H

#include <syslog.h>

void log_init(const char *ident, int facility);
void log_write(int priority, const char *format, ...);
void log_close(void);

#endif
