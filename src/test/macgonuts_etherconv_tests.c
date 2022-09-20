#include "macgonuts_etherconv_tests.h"
#include <macgonuts_etherconv.h>
#include <string.h>

CUTE_TEST_CASE(macgonuts_check_ether_addr_tests)
    struct test_ctx {
        const char *mac;
        const int valid;
    } test_vector[] = {
        { "00:DE:AD:BE:EF:00", 1 },
        { "0:DE:AD:BE:EF:00", 0 },
        { "DE:AD:BE:EF:00", 0 },
        { "AD:BE:EF:00", 0 },
        { "BE:EF:00", 0 },
        { "EF:00", 0 },
        { "00", 0 },
        { "00:de:ad:be:ef:00", 1 },
        { "0:de:ad:be:ef:00", 0 },
        { "de:ad:be:ef:00", 0 },
        { "ad:be:ef:00", 0 },
        { "be:ef:00", 0 },
        { "ef:00", 0 },
        { "mean greeens", 0 },
        { "AA:BB:CC:DD:EE:FF", 1 },
        { "BB:CC:DD:EE:FF:GG", 0 },
        { "aa:bb:cc:dd:ee:ff", 1 },
        { "bb:cc:dd:ee:ff:gg", 0 },
        { "aA:bB:cC:dD:eE:fF", 1 },
        { "bB:cC:dD:eE:fF:gG", 0 },
        { "Aa:Bb:Cc:Dd:Ee:Ff", 1 },
        { "Bb:Cc:Dd:Ee:Ff:Gg", 0 },
    }, *test = &test_vector[0], *test_end = test + sizeof(test_vector) / sizeof(test_vector[0]);
    while (test != test_end) {
        CUTE_ASSERT(macgonuts_check_ether_addr(test->mac, strlen(test->mac)) == test->valid);
        test++;
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(macgonuts_getrandom_ether_addr_tests)
    size_t c = 10;
    char eth_addr[18] = { 0 };
    for (c = 0; c < 18; c++) {
        CUTE_ASSERT(macgonuts_getrandom_ether_addr(eth_addr, c) == EXIT_FAILURE);
    }
    while (c-- > 0) {
        CUTE_ASSERT(macgonuts_getrandom_ether_addr(eth_addr, sizeof(eth_addr)) == EXIT_SUCCESS);
        CUTE_ASSERT(macgonuts_check_ether_addr(eth_addr, strlen(eth_addr)) == 1);
    }
CUTE_TEST_CASE_END
