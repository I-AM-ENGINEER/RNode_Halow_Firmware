/* One-off probe: which sim timer advances under -icount?
 *  - csky_coret @ 0xe000e000 (CMPR/CNT/CTR/CSR guesses)
 *  - csky_timer @ 0x40011000 (DW APB layout: LD/CV/CTL/EOI)
 * Also calibrates ticks per loop iteration for instruction mapping. */
#include <stdint.h>

#define UART_BASE 0x40015000u
#define EXIT_BASE 0x10002000u

static volatile uint32_t *const CORET = (volatile uint32_t *)0xe000e000u;
static volatile uint32_t *const APT   = (volatile uint32_t *)0x40011000u;

static void putc_( char c ){ *(volatile uint32_t *)UART_BASE = (uint32_t)(uint8_t)c; }
static void puts_( const char *s ){ while( *s ) putc_(*s++); }
static void putu( uint32_t v ){
    char b[12]; int n = 0;
    do{ b[n++] = (char)('0' + v % 10u); v /= 10u; }while( v );
    while( n ) putc_(b[--n]);
}
static void puth( uint32_t v ){
    puts_("0x");
    for( int i = 7; i >= 0; i-- ){
        uint32_t d = (v >> (i * 4)) & 0xFu;
        putc_((char)( d < 10 ? '0' + d : 'a' + d - 10 ));
    }
}

volatile uint32_t g_sink;

static void spin( uint32_t n ){
    for( uint32_t i = 0; i < n; i++ ) g_sink = i;
}

static uint32_t apt_cv( void ){ return APT[1]; }

int main( void ){
    /* ---- coret with a non-zero compare, then enable ---- */
    CORET[0] = 0xFFFFFFFFu;   /* CMPR */
    CORET[2] |= 1u;           /* CTR.EN */

    /* ---- DW APB timer: LD=0xFFFFFFFF, CTL = EN | periodic ---- */
    APT[2] = 0u;              /* stop */
    APT[0] = 0xFFFFFFFFu;     /* LD   */
    APT[2] = 3u;              /* CTL: EN | periodic */
    (void)APT[3];             /* EOI  */

    puts_("probe: coret:");
    for( int i = 0; i < 4; i++ ){ putc_(' '); puth(CORET[i]); }
    puts_(" | apt:");
    for( int i = 0; i < 4; i++ ){ putc_(' '); puth(APT[i]); }
    putc_('\n');

    uint32_t a0 = apt_cv();
    uint32_t c0 = CORET[1];
    spin(100000u);
    uint32_t a1 = apt_cv();
    uint32_t c1 = CORET[1];
    spin(300000u);
    uint32_t a2 = apt_cv();
    uint32_t c2 = CORET[1];

    puts_("probe: apt ticks 100k= "); putu(a0 - a1);
    puts_(" ("); putu((a0 - a1) / 100000u); puts_(" /iter), 300k= ");
    putu(a1 - a2); puts_(" ("); putu((a1 - a2) / 300000u); puts_(" /iter)\r\n");
    puts_("probe: coret delta 100k= "); putu(c1 - c0);
    puts_(" 300k= "); putu(c2 - c1); putc_('\n');
    puts_("probe: regs now: coret:");
    for( int i = 0; i < 4; i++ ){ putc_(' '); puth(CORET[i]); }
    puts_(" | apt:");
    for( int i = 0; i < 4; i++ ){ putc_(' '); puth(APT[i]); }
    putc_('\n');

    *(volatile uint32_t *)EXIT_BASE = 0;
    for( ;; ){}
}
