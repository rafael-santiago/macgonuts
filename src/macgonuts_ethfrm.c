/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <macgonuts_ethfrm.h>

#define ETH_FRAME_BASE_SIZE(ctx) (sizeof(ctx->dest_hw_addr) +\
                                  sizeof(ctx->src_hw_addr) +\
                                  sizeof(ctx->ether_type))

int macgonuts_read_ethernet_frm(struct macgonuts_ethfrm_ctx *ethfrm, const unsigned char *frm, const size_t frm_size) {
    const unsigned char *fp = NULL;
    const unsigned char *fp_end = NULL;

    if (ethfrm == NULL || frm == NULL) {
        fflush(stderr);
        return EINVAL;
    }

    if (frm_size < ETH_FRAME_BASE_SIZE(ethfrm)) {
        return EPROTO;
    }

    fp = frm;
    fp_end = fp + frm_size;

    memcpy(ethfrm->dest_hw_addr, fp, sizeof(ethfrm->dest_hw_addr));
    fp += sizeof(ethfrm->dest_hw_addr);

    memcpy(ethfrm->src_hw_addr , fp, sizeof(ethfrm->src_hw_addr));
    fp += sizeof(ethfrm->src_hw_addr);

    ethfrm->ether_type = (uint16_t)fp[0] << 8 |
                         (uint16_t)fp[1];

    fp += sizeof(ethfrm->ether_type);
    if (fp >= fp_end) {
        return EPROTO;
    }

    ethfrm->data_size = fp_end - fp;
    ethfrm->data = (uint8_t *)malloc(ethfrm->data_size);
    if (ethfrm->data == NULL) {
        macgonuts_release_ethfrm(ethfrm);
        return ENOMEM;
    }
    memcpy(ethfrm->data, fp, fp_end - fp);

    return EXIT_SUCCESS;
}

unsigned char *macgonuts_make_ethernet_frm(const struct macgonuts_ethfrm_ctx *ethfrm, size_t *frm_size) {
    unsigned char *frm = NULL;
    unsigned char *fp = NULL;

    if (ethfrm == NULL || frm_size == NULL || ethfrm->data == NULL || ethfrm->data_size == 0) {
        return NULL;
    }

    *frm_size = ETH_FRAME_BASE_SIZE(ethfrm) + ethfrm->data_size;
    frm = (unsigned char *)malloc(*frm_size);
    if (frm == NULL) {
        return NULL;
    }

    fp = frm;

    memcpy(fp, ethfrm->dest_hw_addr, sizeof(ethfrm->dest_hw_addr));
    fp += sizeof(ethfrm->dest_hw_addr);

    memcpy(fp, ethfrm->src_hw_addr, sizeof(ethfrm->src_hw_addr));
    fp += sizeof(ethfrm->src_hw_addr);

    fp[0] = ethfrm->ether_type >> 8;
    fp[1] = ethfrm->ether_type & 0xFF;
    fp += sizeof(ethfrm->ether_type);

    memcpy(fp, ethfrm->data, ethfrm->data_size);

    return frm;
}

void macgonuts_release_ethfrm(struct macgonuts_ethfrm_ctx *ethfrm) {
    if (ethfrm == NULL) {
        return;
    }
    if (ethfrm->data != NULL) {
        free(ethfrm->data);
        ethfrm->data = NULL;
        ethfrm->data_size = 0;
    }
}

#undef ETH_FRAME_BASE_SIZE
