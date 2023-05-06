/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <macgonuts_redirect.h>
#include <macgonuts_ethfrm.h>
#include <macgonuts_socket.h>

int macgonuts_should_redirect(const unsigned char *ethfrm, const size_t ethfrm_size,
                              struct macgonuts_spoof_layers_ctx *spf_layers) {
    uint16_t ether_type = 0;
    uint8_t *pkt_proto_addr = NULL;
    size_t pkt_proto_addr_size = 0;

    if (ethfrm == NULL || ethfrm_size == 0) {
        return 0;
    }

    ether_type = (uint16_t)ethfrm[12] << 8 | (uint16_t)ethfrm[13];

    if (memcmp(&ethfrm[0], spf_layers->lo_hw_addr, sizeof(spf_layers->lo_hw_addr)) != 0
        || (ether_type != MACGONUTS_ETHER_TYPE_IP4 && ether_type != MACGONUTS_ETHER_TYPE_IP6)) {
        return 0;
    }

    // INFO(Rafael): Does it have the local MAC but is reffering to the spoofed host in network layer?

    // INFO(Rafael): It is about a packet sent out to this interface.
    switch (ether_type) {
        case MACGONUTS_ETHER_TYPE_IP4:
            pkt_proto_addr = (uint8_t *)&ethfrm[14 + 16];
            pkt_proto_addr_size = 4;
            break;

        case MACGONUTS_ETHER_TYPE_IP6:
            pkt_proto_addr = (uint8_t *)&ethfrm[14 + 24];
            pkt_proto_addr_size = 16;
            break;

        default:
            return 0; // INFO(Rafael): It should never happen in normal conditions.
    }

    if (spf_layers->spoofing_gateway) {
        // INFO(Rafael): Since we are spoofing a gateway pkt_proto_addr can be different from spoof_proto_addr.
        //               In this situation, we only skip redirection when pkt_proto_addr is equals to lo_proto_addr.
        return (pkt_proto_addr_size == spf_layers->proto_addr_size
                && memcmp(pkt_proto_addr,
                          &spf_layers->lo_proto_addr[0], pkt_proto_addr_size) != 0);
    }

    // INFO(Rafael): Does the destination network address is the same of the spoofed host?
    return (pkt_proto_addr_size == spf_layers->proto_addr_size
            && memcmp(pkt_proto_addr,
                      &spf_layers->spoof_proto_addr[0], pkt_proto_addr_size) == 0);
}

int macgonuts_redirect(const macgonuts_socket_t rsk,
                       struct macgonuts_spoof_layers_ctx *spf_layers,
                       const unsigned char *ethfrm, const size_t ethfrm_size,
                       struct macgonuts_capture_ctx *capture) {
    int err = EFAULT;
    unsigned char *patched_frm = NULL;
    int should_capture = 0;

    assert(spf_layers != NULL && ethfrm != NULL && ethfrm_size > 14);

    if (!macgonuts_should_redirect(ethfrm, ethfrm_size, spf_layers)) {
        return ENODATA;
    }

    patched_frm = (unsigned char *)malloc(ethfrm_size);
    if (patched_frm == NULL) {
        err = ENOMEM;
        goto macgonuts_redirect_epilogue;
    }

    // INFO(Rafael): Patch it and reinject in the wire.
    memcpy(&patched_frm[0], &spf_layers->spoof_hw_addr[0], sizeof(spf_layers->spoof_hw_addr));
    memcpy(&patched_frm[sizeof(spf_layers->spoof_hw_addr)],
           &ethfrm[sizeof(spf_layers->spoof_hw_addr)],
           ethfrm_size - sizeof(spf_layers->spoof_hw_addr));
    err = (macgonuts_sendpkt(rsk, patched_frm, ethfrm_size) == ethfrm_size) ? EXIT_SUCCESS
                                                                            : errno;

    should_capture = (capture != NULL && capture->printpkt != NULL && capture->pktout != NULL
                      && capture->printpkt_if == NULL) ||
                     (capture != NULL && capture->printpkt != NULL && capture->pktout != NULL
                        && capture->printpkt_if != NULL && capture->filter_globs != NULL
                        && capture->filter_globs_nr > 0
                        && capture->printpkt_if(ethfrm, ethfrm_size,
                                                capture->filter_globs,
                                                capture->filter_globs_nr));

    if (should_capture) {
        capture->printpkt(capture->pktout, patched_frm, ethfrm_size);
    }

macgonuts_redirect_epilogue:

    if (patched_frm != NULL) {
        free(patched_frm);
        patched_frm = NULL;
    }

    return err;
}
