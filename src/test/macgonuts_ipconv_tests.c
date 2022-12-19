/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include "macgonuts_ipconv_tests.h"
#include <macgonuts_ipconv.h>
#include <string.h>

CUTE_TEST_CASE(macgonuts_get_ip_version_tests)
    struct test_ctx {
        const char *addr;
        const int version;
    } test_vector[] = {
        { "127.0.0.1", 4                                       },
        { "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99", 6 },
        { "192.30.70.3", 4                                     },
        { "8.8.8.8", 4                                         },
        { "111.111.111.1", 4                                   },
        { "::1", 6                                             },
        { "2001:db8:0:f101::2", 6                              },
        { "jabulani", -1                                       },
        { "bozovtnc", -1                                       },
        { "127.0.0.", -1                                       },
        { "endereco apipa subiu subiu", -1                     },
        { "169.254.0.1", 4                                     },
        { "YA::1", -1                                          },
        { "AB::1", 6                                           },
        { ":1", -1                                             },
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
        { "127.0.0.1", 1                                           },
        { "256.0.0.1", 0                                           },
        { "192.", 0                                                },
        { "192.168.", 0                                            },
        { "192.168.10.", 0                                         },
        { "192", 0                                                 },
        { "192.168", 0                                             },
        { "192.168.10", 0                                          },
        { "192.168.10.256", 0                                      },
        { "192.168.10.1", 1                                        },
        { "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99", 1     },
        { "aabbcc:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99", 0 },
        { "192.30.70.3", 1                                         },
        { "8.8.8.8", 1                                             },
        { "111.111.111.1", 1                                       },
        { "::1", 1                                                 },
        { ":1", 0                                                  },
        { ":", 0                                                   },
        { "::deadbeef", 0                                          },
        { "::10000", 0                                             },
        { "2001:db8:0:f101::2", 1                                  },
        { "2001:db8827:0:f101::2", 0                               },
        { "2001::cafe:0:3", 1                                      },
        { "DEAD:BEEF::7E:1D", 1                                    },
        { "2001:db8:0::f101::2", 0                                 },
        { "::2001:db8:0:f101::2", 0                                },
        { "2001::xafe:0:3", 0                                      },
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
        { "127.0.0.1/8", 1                                         },
        { "127.0.0.1/33", 0                                        },
        { "127.0.0.1/32", 0                                        },
        { "127.0.0.1/0", 0                                         },
        { "127.0.0.1/1", 1                                         },
        { "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99/64", 1  },
        { "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99/129", 0 },
        { "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99/128", 0 },
        { "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99/0", 0   },
        { "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99/1", 1   },
        { "192.30.70.3/24", 1                                      },
        { "192.30.70.3/331", 0                                     },
        { "8.8.8.8/12", 1                                          },
        { "8.8.8.8/-12", 0                                         },
        { "111.111.111.1/24", 1                                    },
        { "111.111.111.1/70000", 0                                 },
        { "::1/72", 1                                              },
        { "::1/1172", 0                                            },
        { "2001:db8:0:f101::2/28", 1                               },
        { "2001:db8:0:f101::2/vinte e oito", 0                     },
        { "2001:db8:0:f101::2/f0r4_b0ls0n4r0", 0                   },
        { "192.30.70.9/b0z0VTNC", 0                                },
        { "127.0.0.1/MILICOsOUT", 0                                },
        { "192.30.5.1/B0Z0VAIDESCOLARALINGUATALKEY", 0             },
    }, *test = &test_vector[0], *test_end = test + sizeof(test_vector) / sizeof(test_vector[0]);
    while (test != test_end) {
        CUTE_ASSERT(macgonuts_check_ip_cidr(test->addr, strlen(test->addr)) == test->is_valid);
        test++;
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(macgonuts_get_raw_ip_addr_tests)
    struct test_ctx {
        const char *addr;
        const uint8_t *expected;
        const size_t expected_size;
    } test_vector[] = {
        { "127.0.0.1", (uint8_t *)"\x7F\x00\x00\x01", 4 },
        { "192.30.70.3", (uint8_t *)"\xC0\x1E\x46\x03", 4 },
        { "255.255.255.255", (uint8_t *) "\xFF\xFF\xFF\xFF", 4 },
        { "10.0.2.15", (uint8_t *)"\x0A\x00\x02\x0F", 4 },
        { "1.2.1.2", (uint8_t *) "\x01\x02\x01\x02", 4 },
        { "CA:FE:CA:FE:CA:FE:CA:FE:"
          "CA:FE:CA:FE:CA:FE:CA:FE", (uint8_t *)"\xCA\xFE\xCA\xFE\xCA\xFE\xCA\xFE"
                                                "\xCA\xFE\xCA\xFE\xCA\xFE\xCA\xFE", 16 },
        { "CAFE:CAFE:CAFE:CAFE:"
          "CAFE:CAFE:CAFE:CAFE", (uint8_t *)"\xCA\xFE\xCA\xFE\xCA\xFE\xCA\xFE"
                                            "\xCA\xFE\xCA\xFE\xCA\xFE\xCA\xFE", 16 },
        { "2001::CAFE:0:3", (uint8_t *)"\x20\x01\x00\x00\x00\x00\x00\x00\x00\x00\xCA\xFE\x00\x00\x00\x03", 16 },
        { "2001:db8:0:f101::3", (uint8_t *)"\x20\x01\x0D\xB8\x00\x00\xF1\x01\x00\x00\x00\x00\x00\x00\x00\x03", 16 },
        { "2001:d:0:f101::3", (uint8_t *)"\x20\x01\x00\x0D\x00\x00\xF1\x01\x00\x00\x00\x00\x00\x00\x00\x03", 16 },
    }, *test = &test_vector[0], *test_end = test + sizeof(test_vector) / sizeof(test_vector[0]);
    uint8_t raw[16] = { 0 };
    CUTE_ASSERT(macgonuts_get_raw_ip_addr(NULL, 4, test->addr, strlen(test->addr)) == EINVAL);
    CUTE_ASSERT(macgonuts_get_raw_ip_addr(raw, 0, test->addr, strlen(test->addr)) == EINVAL);
    CUTE_ASSERT(macgonuts_get_raw_ip_addr(raw, 4, NULL, strlen(test->addr)) == EINVAL);
    CUTE_ASSERT(macgonuts_get_raw_ip_addr(raw, 4, test->addr, 0) == EINVAL);
    while (test != test_end) {
        CUTE_ASSERT(macgonuts_get_raw_ip_addr(raw, test->expected_size, test->addr, strlen(test->addr)) == EXIT_SUCCESS);
        CUTE_ASSERT(memcmp(raw, test->expected, test->expected_size) == 0);
        test++;
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(macgonuts_get_raw_cidr_tests)
    struct test_ctx {
        const char *cidr;
        const uint8_t *expected_first;
        const uint8_t *expected_last;
        const size_t expected_size;
    } test_vector[] = {
        { "192.0.0.0/24", (uint8_t *)"\xC0\x00\x00\x00", (uint8_t *)"\xC0\x00\x00\xFF", 4 },
        { "10.0.0.0/23", (uint8_t *)"\x0A\x00\x00\x00", (uint8_t *)"\x0A\x00\x01\xFF", 4 },
        { "192.30.70.10/16", (uint8_t *)"\xC0\x1E\x00\x00", (uint8_t *)"\xC0\x1E\xFF\xFF", 4 },
        { "192.30.70.0/8", (uint8_t *)"\xC0\x00\x00\x00", (uint8_t *)"\xC0\xFF\xFF\xFF", 4 },
        { "192.30.70.0/28", (uint8_t *)"\xC0\x1E\x46\x00", (uint8_t *)"\xC0\x1E\x46\x0F", 4 },
        { "192.30.70.10/28", (uint8_t *)"\xC0\x1E\x46\x00", (uint8_t *)"\xC0\x1E\x46\x0F", 4 },
        { "200.30.70.10/29", (uint8_t *)"\xC8\x1E\x46\x08", (uint8_t *)"\xC8\x1E\x46\x0F", 4 },
        { "200.95.61.88/14", (uint8_t *)"\xC8\x5C\x00\x00", (uint8_t *)"\xC8\x5F\xFF\xFF", 4 },
        { "2001::1/64", (uint8_t *)"\x20\x01\x00\x00\x00\x00"
                                   "\x00\x00\x00\x00\x00\x00"
                                   "\x00\x00\x00\x00", (uint8_t *)"\x20\x01\x00\x00\x00\x00"
                                                                  "\x00\x00\xFF\xFF\xFF\xFF"
                                                                  "\xFF\xFF\xFF\xFF", 16 },
        { "2001::1/24", (uint8_t *)"\x20\x01\x00\x00\x00\x00"
                                   "\x00\x00\x00\x00\x00\x00"
                                   "\x00\x00\x00\x00", (uint8_t *)"\x20\x01\x00\xFF\xFF\xFF"
                                                                  "\xFF\xFF\xFF\xFF\xFF\xFF"
                                                                  "\xFF\xFF\xFF\xFF" },
        { "2001::1/37", (uint8_t *)"\x20\x01\x00\x00\x00\x00"
                                   "\x00\x00\x00\x00\x00\x00"
                                   "\x00\x00\x00\x00", (uint8_t *)"\x20\x01\x00\x00\x07\xFF"
                                                                  "\xFF\xFF\xFF\xFF\xFF\xFF"
                                                                  "\xFF\xFF\xFF\xFF" },
        { "DEAD:BEEF::7E:1D/72", (uint8_t *)"\xDE\xAD\xBE\xEF"
                                            "\x00\x00\x00\x00\x00"
                                            "\x00\x00\x00\x00\x00"
                                            "\x00\x00", (uint8_t *)"\xDE\xAD\xBE\xEF\x00\x00"
                                                                   "\x00\x00\x00\xFF\xFF\xFF"
                                                                   "\xFF\xFF\xFF\xFF" },
    }, *test = &test_vector[0], *test_end = test + sizeof(test_vector) / sizeof(test_vector[0]);
    uint8_t first[16] = { 0 };
    uint8_t last[16] = { 0 };
    while (test != test_end) {
        CUTE_ASSERT(macgonuts_get_raw_cidr(first, last, test->cidr, strlen(test->cidr)) == EXIT_SUCCESS);
        CUTE_ASSERT(memcmp(first, test->expected_first, test->expected_size) == 0);
        CUTE_ASSERT(memcmp(last, test->expected_last, test->expected_size) == 0);
        test++;
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(macgonuts_raw_ip2literal_tests)
    struct test_ctx {
        const uint8_t *raw;
        const size_t raw_size;
        const char *expected;
    } test_vector[] = {
        { (uint8_t *)"\x7F\x00\x00\x01", 4, "127.0.0.1" },
        { (uint8_t *)"\xFF\xFF\xFF\xFF", 4, "255.255.255.255" },
        { (uint8_t *)"\xC0\x1E\x46\x0A", 4, "192.30.70.10" },
        { (uint8_t *)"\xC8\x5F\x3D\x58", 4, "200.95.61.88" },
        { (uint8_t *)"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01", 16, "::1" },
        { (uint8_t *)"\xDE\xAD\xBE\xEF\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x7E\x1D", 16, "dead:beef::7e1d" },
        { (uint8_t *)"\x20\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01", 16, "2001::1" },
        { (uint8_t *)"\x20\x01\x09\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01", 16, "2001:900::1" },
        { (uint8_t *)"\x20\x01\x09\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x01", 16, "2001:900::2:0:0:1" },
    }, *test = &test_vector[0], *test_end = test + sizeof(test_vector) / sizeof(test_vector[0]);
    char out[256] = "";
    while (test != test_end) {
        CUTE_ASSERT(macgonuts_raw_ip2literal(out, sizeof(out), test->raw, test->raw_size) == EXIT_SUCCESS);
        CUTE_ASSERT(strcmp(out, test->expected) == 0);
        test++;
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(macgonuts_inc_raw_ip_tests)
    struct test_ctx {
        uint8_t *raw;
        size_t raw_size;
        uint8_t *expected;
    } test_vector[] = {
        { (uint8_t *)"\xDE\xAD\xBE\xEF", 4, (uint8_t *)"\xDE\xAD\xBE\xF0" },
        { (uint8_t *)"\xFF\xFF\xFF\xFF", 4, (uint8_t *)"\x00\x00\x00\x00" },
        { (uint8_t *)"\xC8\x5F\x3D\x58", 4, (uint8_t *)"\xC8\x5F\x3D\x59" },
        { (uint8_t *)"\x7F\x00\x00\x01", 4, (uint8_t *)"\x7F\x00\x00\x02" },
        { (uint8_t *)"\x20\x01\x09\x00\x00\x00\x00\x00"
                     "\x00\x02\x00\x00\x00\x00\x00\x01", 16,
          (uint8_t *)"\x20\x01\x09\x00\x00\x00\x00\x00"
                     "\x00\x02\x00\x00\x00\x00\x00\x02" },
        { (uint8_t *)"\x20\x01\x09\xFF\xFF\xFF\xFF\xFF"
                     "\xFF\x02\xFF\xFF\xFF\xFF\xFF\xFF", 16,
          (uint8_t *)"\x20\x01\x09\xFF\xFF\xFF\xFF\xFF"
                     "\xFF\x03\x00\x00\x00\x00\x00\x00" },
        { (uint8_t *)"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
                     "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 16,
          (uint8_t *)"\x00\x00\x00\x00\x00\x00\x00\x00"
                     "\x00\x00\x00\x00\x00\x00\x00\x00" },
    }, *test = &test_vector[0], *test_end = test + sizeof(test_vector) / sizeof(test_vector[0]);
    uint8_t raw[16] = { 0 };
    while (test != test_end) {
        memcpy(&raw[0], &test->raw[0], test->raw_size);
        macgonuts_inc_raw_ip(raw, test->raw_size);
        CUTE_ASSERT(memcmp(&raw[0], &test->expected[0], test->raw_size) == 0);
        test++;
    }
CUTE_TEST_CASE_END
