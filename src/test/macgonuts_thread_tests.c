/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include "macgonuts_thread_tests.h"
#include <macgonuts_thread.h>
#include <unistd.h>

static void *test_routine(void *args) {
    int *number = (int *)args;
    usleep(1000);
    *number += 1;
    return number;
}

CUTE_TEST_CASE(macgonuts_mutex_lock_unlock_tests)
    macgonuts_mutex_t mtx = MACGONUTS_DEFAULT_MUTEX_INITIALIZER;
    CUTE_ASSERT(macgonuts_mutex_lock(NULL) == EINVAL);
    CUTE_ASSERT(macgonuts_mutex_lock(&mtx) == EXIT_SUCCESS);
    CUTE_ASSERT(macgonuts_mutex_unlock(NULL) == EINVAL);
    CUTE_ASSERT(macgonuts_mutex_unlock(&mtx) == EXIT_SUCCESS);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(macgonuts_mutex_trylock_tests)
    macgonuts_mutex_t mtx = MACGONUTS_DEFAULT_MUTEX_INITIALIZER;
    CUTE_ASSERT(macgonuts_mutex_lock(&mtx) == EXIT_SUCCESS);
    CUTE_ASSERT(macgonuts_mutex_trylock(NULL) == EINVAL);
    CUTE_ASSERT(macgonuts_mutex_trylock(&mtx) != EXIT_SUCCESS);
    CUTE_ASSERT(macgonuts_mutex_unlock(&mtx) == EXIT_SUCCESS);
    CUTE_ASSERT(macgonuts_mutex_trylock(&mtx) == EXIT_SUCCESS);
    CUTE_ASSERT(macgonuts_mutex_unlock(&mtx) == EXIT_SUCCESS);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(macgonuts_create_join_thread_tests)
    int g_cute_leak_check_status = g_cute_leak_check;
    macgonuts_thread_t th;
    int number = 0;
    int *number_ptr = NULL;
    g_cute_leak_check = 0;
    CUTE_ASSERT(macgonuts_create_thread(NULL, test_routine, NULL) == EINVAL);
    CUTE_ASSERT(macgonuts_create_thread(&th, NULL, NULL) == EINVAL);
    CUTE_ASSERT(macgonuts_create_thread(&th, test_routine, &number) == EXIT_SUCCESS);
    CUTE_ASSERT(macgonuts_thread_join(NULL, NULL) == EINVAL);
    CUTE_ASSERT(macgonuts_thread_join(&th, (void **)&number_ptr) == EXIT_SUCCESS);
    CUTE_ASSERT(number == 1);
    CUTE_ASSERT(*number_ptr == number);
    g_cute_leak_check = g_cute_leak_check_status;
CUTE_TEST_CASE_END
