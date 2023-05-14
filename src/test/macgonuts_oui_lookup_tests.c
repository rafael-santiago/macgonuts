/*
 * Copyright (c) 2023, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include "macgonuts_oui_lookup_tests.h"
#include <macgonuts_oui_lookup.h>
#include <string.h>

CUTE_TEST_CASE(macgonuts_oui_lookup_tests)
    struct test_ctx {
        uint8_t hw_addr[6];
        const char *expected_vendor_ident;
    } test_vector[] = {
        {
            { 0x00, 0x00, 0x6A, 0x01, 0x02, 0x03 }, "COMPUTER CONSOLES INC."
        },
        {
            { 0x00, 0x0C, 0x7A, 0xBE, 0xEF, 0x00 }, "DaTARIUS Technologies GmbH"
        },
        {
            { 0x00, 0x0C, 0x85, 0xBE, 0xEF, 0x00 },  "Cisco Systems, Inc"
        },
        {
            { 0x00, 0x0C, 0x86, 0xBE, 0xEF, 0x00 },  "Cisco Systems, Inc"
        },
        {
            { 0x00, 0x03, 0xFF, 0xBE, 0xEF, 0x00 }, "Microsoft Corporation"
        },
        {
            { 0x00, 0x1D, 0x4F, 0xBE, 0xEF, 0x00 }, "Apple, Inc."
        },
        {
            { 0x00, 0x50, 0x56, 0xBE, 0xEF, 0x00 }, "VMware, Inc."
        },
    }, *test = &test_vector[0], *test_end = test + sizeof(test_vector) / sizeof(test_vector[0]);
    char vendor_ident[256] = "";
    uint8_t hw_addr_404[6] = { 0xFF, 0xFF, 0xFF, 0xBE, 0xEF, 0x00 };
    CUTE_ASSERT(macgonuts_oui_lookup(NULL,
                                     sizeof(vendor_ident) - 1,
                                     &test->hw_addr[0],
                                     sizeof(test->hw_addr),
                                     "../../etc/oui") == EINVAL);
    CUTE_ASSERT(macgonuts_oui_lookup(vendor_ident,
                                     0,
                                     &test->hw_addr[0],
                                     sizeof(test->hw_addr),
                                     "../../etc/oui") == EINVAL);
    CUTE_ASSERT(macgonuts_oui_lookup(vendor_ident,
                                     sizeof(vendor_ident) - 1,
                                     NULL,
                                     sizeof(test->hw_addr),
                                     "../../etc/oui") == EINVAL);
    CUTE_ASSERT(macgonuts_oui_lookup(vendor_ident,
                                     sizeof(vendor_ident) - 1,
                                     &test->hw_addr[0],
                                     2,
                                     "../../etc/oui") == EINVAL);
    CUTE_ASSERT(macgonuts_oui_lookup(vendor_ident,
                                     sizeof(vendor_ident) - 1,
                                     &test->hw_addr[0],
                                     sizeof(test->hw_addr),
                                     NULL) == EINVAL);
    CUTE_ASSERT(macgonuts_oui_lookup(vendor_ident,
                                     10,
                                     &test->hw_addr[0],
                                     sizeof(test->hw_addr),
                                     "../../etc/oui") == ENOBUFS);
    while (test != test_end) {
        CUTE_ASSERT(macgonuts_oui_lookup(vendor_ident,
                                         sizeof(vendor_ident) - 1,
                                         &test->hw_addr[0],
                                         sizeof(test->hw_addr),
                                         "../../etc/oui") == EXIT_SUCCESS);
        CUTE_ASSERT(strcmp(vendor_ident, test->expected_vendor_ident) == 0);
        test++;
    }
    CUTE_ASSERT(macgonuts_oui_lookup(vendor_ident,
                                     sizeof(vendor_ident) - 1,
                                     &hw_addr_404[0],
                                     sizeof(hw_addr_404),
                                     "../../etc/oui") == ENOENT);
CUTE_TEST_CASE_END
