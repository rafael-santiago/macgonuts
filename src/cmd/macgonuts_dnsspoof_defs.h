/*
 * Copyright (c) 2023, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#ifndef MACGONUTS_CMD_MACGONUTS_DNSSPOOF_DEFS_H
#define MACGONUTS_CMD_MACGONUTS_DNSSPOOF_DEFS_H 1

#define macgonuts_dnsspoof_etc_hoax(s) ((macgonuts_etc_hoax_handle *)(s)->metainfo.arg[0])
#define macgonuts_dnsspoof_iplist(s) ((macgonuts_iplist_handle *)(s)->metainfo.arg[1])
#define macgonuts_dnsspoof_ttl(s) (*(uint32_t *)(s)->metainfo.arg[2])
#define macgonuts_dnsspoof_gw_wire(s) (*(macgonuts_socket_t *)(s)->metainfo.arg[3])

#define macgonuts_dnsspoof_set_etc_hoax(s, v) ((s)->metainfo.arg[0] = (void *)v)
#define macgonuts_dnsspoof_set_iplist(s, v) ((s)->metainfo.arg[1] = (void *)v)
#define macgonuts_dnsspoof_set_ttl(s, v) ((s)->metainfo.arg[2] = (void *)v)
#define macgonuts_dnsspoof_set_gw_wire(s, v) ((s)->metainfo.arg[3] = (void *)v)

#endif // MACGONUTS_CMD_MACGONUTS_DNSSPOOF_DEFS_H
