/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <hooks/macgonuts_spoof_redirect_hook.h>
#include <macgonuts_ethfrm.h>
#include <macgonuts_socket.h>

int macgonuts_spoof_redirect_hook(struct macgonuts_spoofing_guidance_ctx *spfgd,
                                  const unsigned char *ethfrm, const size_t ethfrm_size) {
    int err = EFAULT;
    uint16_t ether_type = 0;
    int do_redirect = 0;
    uint8_t *pkt_proto_addr = NULL;
    size_t pkt_proto_addr_size = 0;
    unsigned char *patched_frm = NULL;

    assert(spfgd != NULL && ethfrm != NULL && ethfrm_size > 14);

    ether_type = (uint16_t)ethfrm[12] << 8 | (uint16_t)ethfrm[13];

    if (memcmp(&ethfrm[0], spfgd->layers.lo_hw_addr, sizeof(spfgd->layers.lo_hw_addr)) != 0
        || (ether_type != MACGONUTS_ETHER_TYPE_IP4 && ether_type != MACGONUTS_ETHER_TYPE_IP6)) {
        err = EXIT_SUCCESS;
        goto macgonuts_spoof_redirect_hook_epilogue;
    }
    // INFO(Rafael): Does it have the local MAC but is reffering to the spoofed host in network layer?

    // INFO(Rafael): It is about a packet sent out to this interface.
    switch (ether_type) {
        case MACGONUTS_ETHER_TYPE_IP4:
            pkt_proto_addr = (uint8_t *)&ethfrm[14 + 16];
            pkt_proto_addr_size = 4;
            err = EXIT_SUCCESS;
            break;

        case MACGONUTS_ETHER_TYPE_IP6:
            pkt_proto_addr = (uint8_t *)&ethfrm[14 + 24];
            pkt_proto_addr_size = 6;
            err = EXIT_SUCCESS;
            break;

        default:
            err = EPROTO; // INFO(Rafael): It should never happen in normal conditions.
            break;
    }

    if (err != EXIT_SUCCESS) {
        goto macgonuts_spoof_redirect_hook_epilogue;
    }

    // INFO(Rafael): Does the destination network address is the same of the spoofed host?
    do_redirect = (pkt_proto_addr_size == spfgd->layers.proto_addr_size
                   && memcmp(pkt_proto_addr,
                             &spfgd->layers.spoof_proto_addr[0], pkt_proto_addr_size) == 0);

    if (!do_redirect) {
        goto macgonuts_spoof_redirect_hook_epilogue;
    }

    patched_frm = (unsigned char *)malloc(ethfrm_size);
    if (patched_frm == NULL) {
        err = ENOMEM;
        goto macgonuts_spoof_redirect_hook_epilogue;
    }

    // INFO(Rafael): Patch it and reinject in the wire.
    memcpy(&patched_frm[0], &spfgd->layers.spoof_hw_addr[0], sizeof(spfgd->layers.spoof_hw_addr));
    memcpy(&patched_frm[sizeof(spfgd->layers.spoof_hw_addr)],
           &ethfrm[sizeof(spfgd->layers.spoof_hw_addr)],
           ethfrm_size - sizeof(spfgd->layers.spoof_hw_addr));
    err = (macgonuts_sendpkt(spfgd->handles.wire, patched_frm, ethfrm_size) == ethfrm_size) ? EXIT_SUCCESS
                                                                                            : errno;

macgonuts_spoof_redirect_hook_epilogue:

    if (patched_frm != NULL) {
        free(patched_frm);
        patched_frm = NULL;
    }

    return err;
}
