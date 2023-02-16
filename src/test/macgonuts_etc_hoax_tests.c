/*
 * Copyright (c) 2023, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include "macgonuts_etc_hoax_tests.h"
#include <macgonuts_etc_hoax.h>
#include <string.h>

CUTE_TEST_CASE(macgonuts_etc_hoax_tests)
    macgonuts_etc_hoax_handle *etc_hoax_handle = NULL;
    const char *etc_hoax_data = "# this is one etc/hoax file...\n"
                                "#\n"
                                "#\n"
                                "192.30.70.2\t*.local.io\n"
                                "192.30.70.7\t\t\t\t    \t www.404.com ftp.yyz.org\twww.the-[123456789].blau\n"
                                "\n\n\n\n\n\n\n\n\n"
                                "cafe::fed1:d000\tkizmiaz\n"
                                "# 192.30.70.1 commented.io\n";
    FILE *fp = NULL;
    uint8_t in_addr[16] = { 0 };
    size_t in_addr_size = 0;
    struct test_ctx {
        const char *name;
        size_t expected_in_addr_size;
        uint8_t expected_in_addr[16];
    } test_vector[] = {
        { "myspot.local.io", 4, { 0xC0, 0x1E, 0x46, 0x02, 0x00, 0x00, 0x00, 0x00,
                                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
        { "www.404.com", 4, { 0xC0, 0x1E, 0x46, 0x07, 0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
        { "ftp.yyz.org", 4, { 0xC0, 0x1E, 0x46, 0x07, 0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
        { "www.the-1.blau", 4, { 0xC0, 0x1E, 0x46, 0x07, 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
        { "www.the-2.blau", 4, { 0xC0, 0x1E, 0x46, 0x07, 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
        { "www.the-3.blau", 4, { 0xC0, 0x1E, 0x46, 0x07, 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
        { "www.the-4.blau", 4, { 0xC0, 0x1E, 0x46, 0x07, 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
        { "www.the-5.blau", 4, { 0xC0, 0x1E, 0x46, 0x07, 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
        { "www.the-6.blau", 4, { 0xC0, 0x1E, 0x46, 0x07, 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
        { "www.the-7.blau", 4, { 0xC0, 0x1E, 0x46, 0x07, 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
        { "www.the-8.blau", 4, { 0xC0, 0x1E, 0x46, 0x07, 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
        { "www.the-9.blau", 4, { 0xC0, 0x1E, 0x46, 0x07, 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
        { "kizmiaz", 16, { 0xCA, 0xFE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00, 0xFE, 0xD1, 0xD0, 0x00 } },
    }, *test = &test_vector[0], *test_end = test + sizeof(test_vector) / sizeof(test_vector[0]);
    CUTE_ASSERT(macgonuts_open_etc_hoax(NULL) == NULL);
    remove("etc-hoax");
    CUTE_ASSERT(macgonuts_open_etc_hoax("etc-hoax") == NULL);
    fp = fopen("etc-hoax", "wb");
    CUTE_ASSERT(fp != NULL);
    fwrite(etc_hoax_data, 1, strlen(etc_hoax_data), fp);
    fclose(fp);
    etc_hoax_handle = macgonuts_open_etc_hoax("etc-hoax");
    CUTE_ASSERT(etc_hoax_handle != NULL);
    CUTE_ASSERT(macgonuts_gethostbyname(NULL, sizeof(in_addr), &in_addr_size, etc_hoax_handle, "abc", 3) == EINVAL);
    CUTE_ASSERT(macgonuts_gethostbyname(in_addr, 0, &in_addr_size, etc_hoax_handle, "abc", 3) == EINVAL);
    CUTE_ASSERT(macgonuts_gethostbyname(in_addr, sizeof(in_addr), NULL, etc_hoax_handle, "abc", 3) == EINVAL);
    CUTE_ASSERT(macgonuts_gethostbyname(in_addr, sizeof(in_addr), &in_addr_size, NULL, "abc", 3) == EINVAL);
    CUTE_ASSERT(macgonuts_gethostbyname(in_addr, sizeof(in_addr), &in_addr_size, etc_hoax_handle, NULL, 3) == EINVAL);
    CUTE_ASSERT(macgonuts_gethostbyname(in_addr, sizeof(in_addr), &in_addr_size, etc_hoax_handle, "abc", 0) == EINVAL);
    while (test != test_end) {
        CUTE_ASSERT(macgonuts_gethostbyname(in_addr, sizeof(in_addr), &in_addr_size,
                                            etc_hoax_handle, test->name, strlen(test->name)) == EXIT_SUCCESS);
        CUTE_ASSERT(in_addr_size == test->expected_in_addr_size);
        CUTE_ASSERT(memcmp(in_addr, test->expected_in_addr, in_addr_size) == 0);
        test++;
    }
    CUTE_ASSERT(macgonuts_gethostbyname(in_addr, sizeof(in_addr), &in_addr_size,
                                        etc_hoax_handle, "404", 3) == ENOENT);
    CUTE_ASSERT(macgonuts_gethostbyname(in_addr, sizeof(in_addr), &in_addr_size,
                                        etc_hoax_handle, "commented.io", 12) == ENOENT);
    macgonuts_close_etc_hoax(etc_hoax_handle);
    remove("etc-hoax");
CUTE_TEST_CASE_END
