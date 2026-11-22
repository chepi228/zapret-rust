/* MIT. Preserve the upstream diagnostic interface using Windows event logging. */
#pragma once
#define LOG_EMERG 0
#define LOG_ALERT 1
#define LOG_CRIT 2
#define LOG_ERR 3
#define LOG_WARNING 4
#define LOG_NOTICE 5
#define LOG_INFO 6
#define LOG_DEBUG 7
#define LOG_PID 1
#define LOG_USER 8
void openlog(const char *name,int options,int facility);
void syslog(int priority,const char *format,...);
void closelog(void);
