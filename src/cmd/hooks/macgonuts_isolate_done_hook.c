/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <cmd/hooks/macgonuts_isolate_done_hook.h>
#include <macgonuts_status_info.h>
#include <macgonuts_etherconv.h>
#include <macgonuts_ipconv.h>
#include <accacia.h>

int macgonuts_isolate_done_hook(struct macgonuts_spoofing_guidance_ctx *spfgd,
                                const unsigned char *ethfrm, const size_t ethfrm_size) {
    char spoof_address[256] = "";

    assert(spfgd != NULL
           && spfgd->usrinfo.lo_iface != NULL
           && spfgd->usrinfo.tg_address != NULL
           && spfgd->usrinfo.spoof_address != NULL);

    macgonuts_raw_ip2literal(spoof_address, sizeof(spoof_address),
                             spfgd->layers.spoof_proto_addr, spfgd->layers.proto_addr_size);

    macgonuts_si_info("fuddling resolution info related to `%s` sent to `%s`...\n", spoof_address,
                                                                                    spfgd->usrinfo.tg_address);

    return EXIT_SUCCESS;
}

