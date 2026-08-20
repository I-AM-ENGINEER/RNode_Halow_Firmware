#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>
#include <time.h>

#define UART_BASE 0x40015000u
#define EXIT_BASE 0x10002000u

extern int main(void);
extern char __bss_start, __bss_end;

void sim_exit( int code ){
    *(volatile uint32_t *)EXIT_BASE = (uint32_t)code;
    for( ;; ){}
}

static void uart_putc( char c ){
    *(volatile uint32_t *)UART_BASE = (uint32_t)(uint8_t)c;
}

static void puts_n( const char *s ){
    while( *s ) uart_putc(*s++);
}

static void emit_pad( int n ){
    while( n-- > 0 ) uart_putc(' ');
}

static void emit_u32( uint32_t v, uint32_t base, int width, char pad, int left ){
    char buf[12];
    int n = 0;
    do{
        uint32_t d = v % base;
        buf[n++] = (char)( d < 10 ? '0' + d : 'a' + d - 10 );
        v /= base;
    }while( v != 0 );
    for( int i = n; i < width && !left; i++ ) uart_putc(pad);
    while( n > 0 ) uart_putc(buf[--n]);
    for( int i = n ? ( n > width ? n : width ) : width; left && i < width; i++ ) uart_putc(' ');
}

int printf( const char *fmt, ... ){
    va_list ap;
    va_start(ap, fmt);

    for( const char *p = fmt; *p; p++ ){
        if( *p != '%' ){
            uart_putc(*p);
            continue;
        }
        p++;
        int left = 0, width = 0;
        char pad = ' ';
        if( *p == '-' ){ left = 1; p++; }
        if( *p == '0' ){ pad = '0'; p++; }
        while( *p >= '0' && *p <= '9' ){ width = width * 10 + (*p - '0'); p++; }
        while( *p == 'l' || *p == 'z' ) p++;

        if( *p == 'd' ){
            int32_t v = va_arg(ap, int32_t);
            int neg = ( v < 0 );
            if( neg ){ uart_putc('-'); width--; v = -v; }
            emit_u32((uint32_t)v, 10, width, pad, left);
        }else if( *p == 'u' ){
            emit_u32(va_arg(ap, uint32_t), 10, width, pad, left);
        }else if( *p == 'x' ){
            emit_u32(va_arg(ap, uint32_t), 16, width, pad, left);
        }else if( *p == 's' ){
            const char *s = va_arg(ap, const char *);
            if( s == NULL ) s = "(null)";
            int n = 0;
            while( s[n] ) n++;
            if( !left ) emit_pad(width - n);
            puts_n(s);
            if( left ) emit_pad(width - n);
        }else if( *p == 'c' ){
            uart_putc((char)va_arg(ap, int));
        }else if( *p == '%' ){
            uart_putc('%');
        }
    }

    va_end(ap);
    return 0;
}

int puts( const char *s ){
    puts_n(s);
    uart_putc('\n');
    return 0;
}

int putchar( int c ){
    uart_putc((char)c);
    return c;
}

void *memcpy( void *dst, const void *src, size_t n ){
    uint8_t *d = dst;
    const uint8_t *s = src;
    while( n-- ) *d++ = *s++;
    return dst;
}

void *memset( void *dst, int c, size_t n ){
    uint8_t *d = dst;
    while( n-- ) *d++ = (uint8_t)c;
    return dst;
}

int memcmp( const void *a, const void *b, size_t n ){
    const uint8_t *x = a, *y = b;
    while( n-- ){
        if( *x != *y ) return ( *x < *y ) ? -1 : 1;
        x++; y++;
    }
    return 0;
}

size_t strlen( const char *s ){
    size_t n = 0;
    while( s[n] ) n++;
    return n;
}

int strcmp( const char *a, const char *b ){
    while( *a && *a == *b ){ a++; b++; }
    return (uint8_t)*a - (uint8_t)*b;
}

char *strncpy( char *dst, const char *src, size_t n ){
    char *d = dst;
    while( n > 0 && *src ){ *d++ = *src++; n--; }
    while( n > 0 ){ *d++ = 0; n--; }
    return dst;
}

time_t time( time_t *t ){ if( t ) *t = 0; return 0; }

static uint8_t g_heap[4096];
static uint32_t g_heap_used;

void *malloc( size_t n ){
    n = ( n + 7u ) & ~7u;
    if( g_heap_used + n > sizeof(g_heap) ) return NULL;
    void *p = &g_heap[g_heap_used];
    g_heap_used += n;
    return p;
}

void free( void *p ){
    (void)p;
}

void c_start( void ){
    uint32_t *p = (uint32_t *)&__bss_start;
    uint32_t *e = (uint32_t *)&__bss_end;
    while( p < e ) *p++ = 0;
    sim_exit(main());
}
