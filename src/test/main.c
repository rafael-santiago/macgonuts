#include <cutest.h>
#include "macgonuts_etherconv_tests.h"
#include "macgonuts_socket_tests.h"

CUTE_TEST_CASE(macgonuts_static_lib_tests)
    CUTE_RUN_TEST(macgonuts_check_ether_addr_tests);
    CUTE_RUN_TEST(macgonuts_getrandom_ether_addr_tests);
    CUTE_RUN_TEST(macgonuts_create_release_socket_tests);
    CUTE_RUN_TEST(macgonuts_sendpkt_tests);
    CUTE_RUN_TEST(macgonuts_recvpkt_tests);
CUTE_TEST_CASE_END

CUTE_MAIN(macgonuts_static_lib_tests);
