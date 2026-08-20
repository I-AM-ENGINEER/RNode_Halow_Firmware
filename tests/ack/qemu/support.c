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

/* First-fit free-list heap: ACK frame buffers live here and are freed on
 * ACK/drop, so a bump allocator would run the 16 MB RAM dry in soaks. */
#define HEAP_ARENA_SIZE (512u * 1024u)

struct blk {
    uint32_t size;   /* payload bytes, header excluded */
    uint32_t used;
};

static uint8_t g_heap[HEAP_ARENA_SIZE] __attribute__((aligned(8)));
static int g_heap_init;

static void heap_init( void ){
    struct blk *b = (struct blk *)(void *)g_heap;
    b->size = sizeof(g_heap) - sizeof(struct blk);
    b->used = 0;
    g_heap_init = 1;
}

void *malloc( size_t n ){
    if( !g_heap_init ) heap_init();
    n = ( n + 7u ) & ~7u;

    struct blk *b = (struct blk *)(void *)g_heap;
    for( ;; ){
        uint8_t *base = (uint8_t *)b;
        if( base >= g_heap + sizeof(g_heap) ) return NULL;

        if( !b->used ){
            for( ;; ){
                struct blk *nxt =
                    (struct blk *)(void *)(base + sizeof(struct blk) + b->size);
                if( (uint8_t *)nxt >= g_heap + sizeof(g_heap) || nxt->used ) break;
                b->size += sizeof(struct blk) + nxt->size;
            }
            if( b->size >= n ) break;
        }
        b = (struct blk *)(void *)(base + sizeof(struct blk) + b->size);
    }

    if( b->size >= n + sizeof(struct blk) + 16u ){
        struct blk *rest = (struct blk *)(void *)((uint8_t *)b + sizeof(struct blk) + n);
        rest->size = b->size - n - sizeof(struct blk);
        rest->used = 0;
        b->size    = n;
    }
    b->used = 1;
    return (uint8_t *)b + sizeof(struct blk);
}

void free( void *p ){
    if( p == NULL ) return;
    struct blk *b = (struct blk *)(void *)((uint8_t *)p - sizeof(struct blk));
    if( b->used ) b->used = 0;
}

void c_start( void ){
    uint32_t *p = (uint32_t *)&__bss_start;
    uint32_t *e = (uint32_t *)&__bss_end;
    while( p < e ) *p++ = 0;
    sim_exit(main());
}
