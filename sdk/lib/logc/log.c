#define NANOPRINTF_IMPLEMENTATION

#define NANOPRINTF_USE_FIELD_WIDTH_FORMAT_SPECIFIERS 1
#define NANOPRINTF_USE_PRECISION_FORMAT_SPECIFIERS 0
#define NANOPRINTF_USE_FLOAT_FORMAT_SPECIFIERS 0
#define NANOPRINTF_USE_LARGE_FORMAT_SPECIFIERS 1
#define NANOPRINTF_USE_SMALL_FORMAT_SPECIFIERS 1
#define NANOPRINTF_USE_BINARY_FORMAT_SPECIFIERS 0
#define NANOPRINTF_USE_WRITEBACK_FORMAT_SPECIFIERS 0
#define NANOPRINTF_USE_ALT_FORM_FLAG 0
#define NANOPRINTF_USE_FLOAT_SINGLE_PRECISION 0

#include "lib/logc/log.h"
#include "lib/logc/nanoprintf.h"
#include "net_log.h"

#include <stdarg.h>
#include <stdint.h>
#include <stddef.h>

extern int64_t get_time_ms( void );

static struct {
    void *udata;
    log_LockFn lock;
} L;

static const char *level_strings[] = {
    "TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"
};

#ifdef LOG_USE_COLOR
static const char *level_colors[] = {
    "\x1b[94m", "\x1b[36m", "\x1b[32m", "\x1b[33m", "\x1b[31m", "\x1b[35m"
};
#endif

static void lock( void ){
    if( L.lock ){
        L.lock(true, L.udata);
    }
}

static void unlock( void ){
    if( L.lock ){
        L.lock(false, L.udata);
    }
}

const char *log_level_string( int level ){
    return level_strings[level];
}

void log_set_lock( log_LockFn fn, void *udata ){
    L.lock = fn;
    L.udata = udata;
}

void log_log( int level, const char *file, int line, const char *fmt, ... ){
    char buf[LOG_BUF_SIZE];
    int n;
    int m;
    va_list ap;
    int64_t time_ms;

    lock();

    time_ms = get_time_ms();

#ifdef LOG_USE_COLOR
    n = npf_snprintf(buf, sizeof(buf),
                     "[%lld] %s%-5s\x1b[0m \x1b[90m%s:%d:\x1b[0m ",
                     (long long)time_ms,
                     level_colors[level],
                     level_strings[level],
                     file,
                     line);
#else
    n = npf_snprintf(buf, sizeof(buf),
                     "[%lld] %-5s %s:%d: ",
                     (long long)time_ms,
                     level_strings[level],
                     file,
                     line);
#endif

    if( n < 0 ){
        unlock();
        return;
    }

    if( n >= (int)sizeof(buf) ){
        n = (int)sizeof(buf) - 1;
    }

    va_start(ap, fmt);

    if( n < (int)sizeof(buf) - 1 ){
        m = npf_vsnprintf(buf + n, sizeof(buf) - (size_t)n, fmt, ap);
        if( m > 0 ){
            n += m;
            if( n >= (int)sizeof(buf) ){
                n = (int)sizeof(buf) - 1;
            }
        }
    }

    va_end(ap);

    if( n < (int)sizeof(buf) - 1 ){
        buf[n++] = '\n';
        buf[n] = 0;
    } else {
        buf[sizeof(buf) - 2] = '\n';
        buf[sizeof(buf) - 1] = 0;
        n = (int)sizeof(buf) - 1;
    }

    net_log_send(buf, (uint16_t)n);

    unlock();
}
