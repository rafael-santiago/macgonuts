/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#ifndef MACGONUTS_TEST_MACGONUTS_THREAD_TESTS_H
#define MACGONUTS_TEST_MACGONUTS_THREAD_TESTS_H 1

#include <cutest.h>

CUTE_DECLARE_TEST_CASE(macgonuts_mutex_lock_unlock_tests);

CUTE_DECLARE_TEST_CASE(macgonuts_mutex_trylock_tests);

CUTE_DECLARE_TEST_CASE(macgonuts_create_join_thread_tests);

#endif // MACGONUTS_TEST_MACGONUTS_THREAD_TESTS_H
