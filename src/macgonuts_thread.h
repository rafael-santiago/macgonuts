/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#ifndef MACGONUTS_THREAD_H
#define MACGONUTS_THREAD_H 1

#include <macgonuts_types.h>

typedef void *(*macgonuts_thread_func)(void *);

int macgonuts_mutex_init(macgonuts_mutex_t *mtx);

int macgonuts_mutex_destroy(macgonuts_mutex_t *mtx);

int macgonuts_mutex_lock(macgonuts_mutex_t *mtx);

int macgonuts_mutex_trylock(macgonuts_mutex_t *mtx);

int macgonuts_mutex_unlock(macgonuts_mutex_t *mtx);

int macgonuts_create_thread(macgonuts_thread_t *thread, macgonuts_thread_func func, void *args);

int macgonuts_thread_join(macgonuts_thread_t *thread, void **retval);

#endif // MACGONUTS_THREAD_H
