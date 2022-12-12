/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#ifndef MACGONUTS_CMD_MACGONUTS_PRINTPKT_IF_H
#define MACGONUTS_CMD_MACGONUTS_PRINTPKT_IF_H 1

#include <macgonuts_types.h>

int macgonuts_printpkt_if(const unsigned char *ethfrm, const size_t ethfrm_size,
                          const struct macgonuts_filter_glob_ctx **filter_globs,
                          const size_t filter_globs_nr);

#endif // MACGONUTS_CMD_MACGONUTS_PRINTPKT_IF_H
