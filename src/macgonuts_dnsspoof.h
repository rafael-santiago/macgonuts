/*
 * Copyright (c) 2023, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#ifndef MACGONUTS_DNSSPOOF_H
#define MACGONUTS_DNSSPOOF_H 1

#include <macgonuts_types.h>
#include <macgonuts_iplist.h>
#include <macgonuts_etc_hoax.h>

int macgonuts_dnsspoof(const macgonuts_socket_t rsk, struct macgonuts_spoof_layers_ctx *spf_layers,
                       macgonuts_iplist_handle *iplist_handle,
                       macgonuts_etc_hoax_handle *etc_hoax_handle,
                       const uint32_t dns_answer_ttl,
                       const unsigned char *ethfrm, const size_t ethfrm_size);

#endif // MACGONUTS_DNSSPOOF_H
