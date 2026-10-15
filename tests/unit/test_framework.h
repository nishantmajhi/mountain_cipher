/* ===========================================================================
 * test_framework.h - a minimal, dependency-free unit test helper.
 *
 * Each test .c file defines its own main() and includes this header.
 * Use MC_CHECK(condition, description) for individual assertions and
 * MC_TEST_EXIT() at the end of main() to print a summary and return the
 * correct process exit code (0 = all passed, 1 = at least one failure).
 * ===========================================================================
 */

#ifndef MC_TEST_FRAMEWORK_H
#define MC_TEST_FRAMEWORK_H

#include <stdio.h>

static int mc_test_pass_count = 0;
static int mc_test_fail_count = 0;

#define MC_CHECK(cond, description)                                          \
    do {                                                                     \
        if (cond) {                                                         \
            mc_test_pass_count++;                                           \
        } else {                                                            \
            mc_test_fail_count++;                                           \
            fprintf(stderr, "  FAIL: %s (%s:%d)\n", description, __FILE__, __LINE__); \
        }                                                                    \
    } while (0)

#define MC_TEST_EXIT()                                                       \
    do {                                                                     \
        fprintf(stderr, "\n%d passed, %d failed\n",                          \
                mc_test_pass_count, mc_test_fail_count);                     \
        return mc_test_fail_count > 0 ? 1 : 0;                               \
    } while (0)

#endif /* MC_TEST_FRAMEWORK_H */
