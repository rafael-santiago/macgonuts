#include "macgonuts_ipconv_tests.h"
#include <macgonuts_ipconv.h>
#include <string.h>

CUTE_TEST_CASE(macgonuts_get_ip_version_tests)
    struct test_ctx {
        const char *addr;
        const int version;
    } test_vector[] = {
        { "127.0.0.1", 4 },
        { "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99", 6 },
        { "192.30.70.3", 4 },
        { "8.8.8.8", 4 },
        { "111.111.111.1", 4 },
        { "::1", 6 },
        { "2001:db8:0:f101::2", 6 },
        { "jabulani", -1 },
        { "bozovtnc", -1 },
        { "127.0.0.", -1 },
        { "endereco apipa subiu subiu", -1 },
        { "169.254.0.1", 4 },
        { "YA::1", -1 },
        { "AB::1", 6 },
        { ":1", -1 },
    }, *test = &test_vector[0], *test_end = test + sizeof(test_vector) / sizeof(test_vector[0]);
    while (test != test_end) {
        CUTE_ASSERT(macgonuts_get_ip_version(test->addr, strlen(test->addr)) == test->version);
        test++;
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(macgonuts_check_ip_addr_tests)
    struct test_ctx {
        const char *addr;
        const int is_valid;
    } test_vector[] = {
        { "127.0.0.1", 1 },
        { "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99", 1 },
        { "192.30.70.3", 1 },
        { "8.8.8.8", 1 },
        { "111.111.111.1", 1 },
        { "::1", 1 },
        { "2001:db8:0:f101::2", 1 },
    }, *test = &test_vector[0], *test_end = test + sizeof(test_vector) / sizeof(test_vector[0]);
    while (test != test_end) {
        CUTE_ASSERT(macgonuts_check_ip_addr(test->addr, strlen(test->addr)) == test->is_valid);
        test++;
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(macgonuts_check_ip_cidr_tests)
    struct test_ctx {
        const char *addr;
        const int is_valid;
    } test_vector[] = {
        { "127.0.0.1/8", 1 },
        { "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99/64", 1 },
        { "192.30.70.3/24", 1 },
        { "8.8.8.8/12", 1 },
        { "111.111.111.1/24", 1 },
        { "::1/72", 1 },
        { "2001:db8:0:f101::2/28", 1 },
    }, *test = &test_vector[0], *test_end = test + sizeof(test_vector) / sizeof(test_vector[0]);
    while (test != test_end) {
        CUTE_ASSERT(macgonuts_check_ip_cidr(test->addr, strlen(test->addr)) == test->is_valid);
        test++;
    }

CUTE_TEST_CASE_END
