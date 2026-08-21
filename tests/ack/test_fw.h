#ifndef TEST_FW_H
#define TEST_FW_H

/* Minimal shared assertion layer: soft-fail (the scenario keeps running so one
 * run reports every violation), global counters, source location on failure. */
#ifdef __cplusplus
extern "C" {
#endif

void test_check( int cond, const char *expr, const char *file, int line, const char *fn );
int  test_pass_count( void );
int  test_fail_count( void );

#define CHECK(cond) test_check( (cond) ? 1 : 0, #cond, __FILE__, __LINE__, __func__ )

#ifdef __cplusplus
}
#endif

#endif /* TEST_FW_H */
