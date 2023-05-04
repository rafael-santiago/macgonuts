/*
 * Copyright (c) 2023, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <cmd/hooks/macgonuts_dnsspoof_redirect_hook.h>
#include <cmd/macgonuts_dnsspoof_defs.h>
#include <macgonuts_dnsspoof.h>
#include <macgonuts_redirect.h>
#include <macgonuts_dnsconv.h>
#include <macgonuts_status_info.h>

int macgonuts_dnsspoof_redirect_hook(struct macgonuts_spoofing_guidance_ctx *spfgd,
                                     const unsigned char *ethfrm, const size_t ethfrm_size) {
    char *spoofed_hostname = NULL;
    assert(spfgd != NULL
           && spfgd->handles.wire > -1);

    int err = macgonuts_dnsspoof(spfgd->handles.wire, &spfgd->layers,
                                 macgonuts_dnsspoof_iplist(spfgd),
                                 macgonuts_dnsspoof_etc_hoax(spfgd),
                                 macgonuts_dnsspoof_ttl(spfgd),
                                 ethfrm, ethfrm_size);
    if (err == EPROTOTYPE || err == EADDRNOTAVAIL || err == EAFNOSUPPORT) {
        err = macgonuts_redirect(spfgd->handles.wire, &spfgd->layers,
                                 ethfrm, ethfrm_size, NULL);
    } else {
        spoofed_hostname = macgonuts_get_dns_qname_from_ethernet_frame(ethfrm, ethfrm_size);
        if (spoofed_hostname != NULL) {
            macgonuts_si_info("spoofed resolution for host name <%s> sent to `%s`.\n", spoofed_hostname,
                                                                                       spfgd->usrinfo.tg_address);
            free(spoofed_hostname);
        } else {
            macgonuts_si_warn("unable to get hostname from ethernet frame.\n");
        }
    }

    return err;
}
