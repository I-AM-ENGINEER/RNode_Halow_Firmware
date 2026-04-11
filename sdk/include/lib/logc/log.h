#ifndef LOG_H
#define LOG_H

#include <stdarg.h>
#include <stdbool.h>

#define LOG_VERSION "0.1.0"

typedef void (*log_LockFn)( bool lock, void *udata );

#define LOG_TRACE 0
#define LOG_DEBUG 1
#define LOG_INFO  2
#define LOG_WARN  3
#define LOG_ERROR 4
#define LOG_FATAL 5

#define LOG_USE_COLOR

#ifndef LOG_BUF_SIZE
#define LOG_BUF_SIZE 256
#endif

#define LOG_NONE 100

#ifndef LOG_ENABLE_LEVEL
#define LOG_ENABLE_LEVEL LOG_NONE
#endif

#ifndef LOG_LOCAL_LEVEL
#define LOG_LOCAL_LEVEL LOG_ENABLE_LEVEL
#endif

#if defined(__FILE_NAME__)
#define LOG_FILE __FILE_NAME__
#else
#define LOG_FILE __FILE__
#endif

#if (LOG_LOCAL_LEVEL <= LOG_TRACE)
#define log_trace(...) log_log(LOG_TRACE, LOG_FILE, __LINE__, __VA_ARGS__)
#else
#define log_trace(...) ((void)0)
#endif

#if (LOG_LOCAL_LEVEL <= LOG_DEBUG)
#define log_debug(...) log_log(LOG_DEBUG, LOG_FILE, __LINE__, __VA_ARGS__)
#else
#define log_debug(...) ((void)0)
#endif

#if (LOG_LOCAL_LEVEL <= LOG_INFO)
#define log_info(...)  log_log(LOG_INFO,  LOG_FILE, __LINE__, __VA_ARGS__)
#else
#define log_info(...)  ((void)0)
#endif

#if (LOG_LOCAL_LEVEL <= LOG_WARN)
#define log_warn(...)  log_log(LOG_WARN,  LOG_FILE, __LINE__, __VA_ARGS__)
#else
#define log_warn(...)  ((void)0)
#endif

#if (LOG_LOCAL_LEVEL <= LOG_ERROR)
#define log_error(...) log_log(LOG_ERROR, LOG_FILE, __LINE__, __VA_ARGS__)
#else
#define log_error(...) ((void)0)
#endif

#if (LOG_LOCAL_LEVEL <= LOG_FATAL)
#define log_fatal(...) log_log(LOG_FATAL, LOG_FILE, __LINE__, __VA_ARGS__)
#else
#define log_fatal(...) ((void)0)
#endif

const char *log_level_string( int level );
void log_set_lock( log_LockFn fn, void *udata );
void log_log( int level, const char *file, int line, const char *fmt, ... );

#endif
