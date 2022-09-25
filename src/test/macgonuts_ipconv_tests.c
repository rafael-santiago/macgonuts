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