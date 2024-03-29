/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include "macgonuts_metaspoofer_tests.h"
#include "macgonuts_test_utils.h"
#include <macgonuts_metaspoofer.h>
#include <macgonuts_spoof.h>
#include <macgonuts_thread.h>

static int test_init(struct macgonuts_spoofing_guidance_ctx *gdc, const unsigned char *pkt, const size_t pkt_size);

static int test_deinit(struct macgonuts_spoofing_guidance_ctx *gdc, const unsigned char *pkt, const size_t pkt_size);

static int test_done(struct macgonuts_spoofing_guidance_ctx *gdc, const unsigned char *pkt, const size_t pkt_size);

void *gohome(void *args) {
    struct macgonuts_spoofing_guidance_ctx *gd = (struct macgonuts_spoofing_guidance_ctx *)args;
    usleep(200000);
    macgonuts_mutex_lock(&gd->handles.lock);
    gd->spoofing.abort = 1;
    macgonuts_mutex_unlock(&gd->handles.lock);
    return NULL;
}

CUTE_TEST_CASE(macgonuts_metaspoofer_tests)
    struct macgonuts_spoofing_guidance_ctx spfgd = { 0 };
    macgonuts_thread_t td;
    int hooks = 0;
    CUTE_ASSERT(macgonuts_run_metaspoofer(NULL) == EINVAL);
    spfgd.hooks.init = test_init;
    spfgd.hooks.deinit = test_deinit;
    spfgd.hooks.done = test_done;
    spfgd.usrinfo.lo_iface = (char *)get_default_iface_name();
    spfgd.spoofing.total = 1000;
    spfgd.spoofing.timeout = 0;
    spfgd.usrinfo.tg_address = "10.0.2.15";
    spfgd.usrinfo.spoof_address = "10.0.2.13";
    //spfgd.usrinfo.lo_mac_address = "AA:BB:DD:CC:DD:FF";
    //spfgd.usrinfo.tg_mac_address = "00:11:22:33:44:55";
    //spfgd.usrinfo.spoof_mac_address = "AA:11:DD:33:DD:55";
    spfgd.layers.proto_addr_version = 4;
    spfgd.layers.proto_addr_version = 4;
    spfgd.layers.proto_addr_size = 4;
    spfgd.metainfo.arg[0] = &hooks;
    memcpy(&spfgd.layers.lo_hw_addr[0], "\xAA\xBB\xCC\xDD\xEE\xFF", sizeof(spfgd.layers.lo_hw_addr));
    memcpy(&spfgd.layers.lo_proto_addr[0], "\x7F\x00\x00\x01", 4);
    memcpy(&spfgd.layers.tg_proto_addr[0], "\x7F\x00\x00\x02", 4);
    memcpy(&spfgd.layers.spoof_proto_addr[0], "\x7F\x00\x00\x03", 4);
    memcpy(&spfgd.layers.tg_hw_addr[0], "\x00\x01\x02\x03\x04\x05", sizeof(spfgd.layers.tg_hw_addr));
    memcpy(&spfgd.layers.spoof_hw_addr[0], "\xAA\x01\xBB\x04\xCC\x05", sizeof(spfgd.layers.spoof_hw_addr));
    CUTE_ASSERT(macgonuts_create_thread(&td, gohome, &spfgd) == EXIT_SUCCESS);
    CUTE_ASSERT(macgonuts_run_metaspoofer(&spfgd) == EXIT_SUCCESS);
    CUTE_ASSERT(macgonuts_thread_join(&td, NULL) == EXIT_SUCCESS);
    macgonuts_release_spoof_layers_ctx(&spfgd.layers);
    CUTE_ASSERT(hooks == 7);
CUTE_TEST_CASE_END

static int test_init(struct macgonuts_spoofing_guidance_ctx *gdc, const unsigned char *pkt, const size_t pkt_size) {
    int *flag = (int *)gdc->metainfo.arg[0];
    *flag |= 1;
    fprintf(stdout, "[test init hook]\n");
    return EXIT_SUCCESS;
}

static int test_deinit(struct macgonuts_spoofing_guidance_ctx *gdc, const unsigned char *pkt, const size_t pkt_size) {
    int *flag = (int *)gdc->metainfo.arg[0];
    *flag |= 2;
    fprintf(stdout, "[test deinit hook]\n");
    return EXIT_SUCCESS;
}

static int test_done(struct macgonuts_spoofing_guidance_ctx *gdc, const unsigned char *pkt, const size_t pkt_size) {
    int *flag = (int *)gdc->metainfo.arg[0];
    *flag |= 4;
    usleep(gdc->spoofing.timeout);
    fprintf(stdout, "[test done hook]\n");
    return EXIT_SUCCESS;
}
