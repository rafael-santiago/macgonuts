/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <macgonuts_thread.h>

int macgonuts_mutex_init(macgonuts_mutex_t *mtx) {
    if (mtx == NULL) {
        return EINVAL;
    }
    return pthread_mutex_init(mtx, NULL);
}

int macgonuts_mutex_destroy(macgonuts_mutex_t *mtx) {
    if (mtx == NULL) {
        return EINVAL;
    }
    return pthread_mutex_destroy(mtx);
}

int macgonuts_mutex_lock(macgonuts_mutex_t *mtx) {
    if (mtx == NULL) {
        return EINVAL;
    }
    return pthread_mutex_lock(mtx);
}

int macgonuts_mutex_unlock(macgonuts_mutex_t *mtx) {
    if (mtx == NULL) {
        return EINVAL;
    }
    return pthread_mutex_unlock(mtx);
}

int macgonuts_mutex_trylock(macgonuts_mutex_t *mtx) {
    if (mtx == NULL) {
        return EINVAL;
    }
    return pthread_mutex_trylock(mtx);
}

int macgonuts_create_thread(macgonuts_thread_t *thread, macgonuts_thread_func func, void *args) {
    if (thread == NULL || func == NULL) {
        return EINVAL;
    }
    return pthread_create(thread, NULL, func, args);
}

int macgonuts_thread_join(macgonuts_thread_t *thread, void **retval) {
    if (thread == NULL) {
        return EINVAL;
    }
    return pthread_join(*thread, retval);
}
