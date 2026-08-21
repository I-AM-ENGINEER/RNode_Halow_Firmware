#include <stdio.h>
#include "test_fw.h"

static int g_pass, g_fail;

void test_check( int cond, const char *expr, const char *file, int line, const char *fn ){
    if( cond ){
        g_pass++;
    }else{
        g_fail++;
        printf( "    FAIL %s:%d (%s): %s\n", file, line, fn, expr );
    }
}

int test_pass_count( void ){ return g_pass; }
int test_fail_count( void ){ return g_fail; }
