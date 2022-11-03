/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include "macgonuts_metaspoofer_tests.h"
#include <macgonuts_metaspoofer.h>
#include <hooks/macgonuts_spoof_init_hook.h>
#include <hooks/macgonuts_spoof_deinit_hook.h>
#include <hooks/macgonuts_spoof_done_hook.h>
#include <macgonuts_spoof.h>
#include <macgonuts_thread.h>

#if defined(__linux__)
# define DEFAULT_TEST_IFACE "eth0"
#else
# error Some code wanted.
#endif

void *gohome(void *args) {
    struct macgonuts_spoofing_guidance_ctx *gd = (struct macgonuts_spoofing_guidance_ctx *)args;
    usleep(200000);
    macgonuts_mutex_lock(&gd->handles.lock);
    gd->spoofing.abort = 1;
    macgonuts_mutex_unlock(&gd->handles.lock);
}

CUTE_TEST_CASE(macgonuts_metaspoofer_tests)
    struct macgonuts_spoofing_guidance_ctx spfgd = { 0 };
    macgonuts_thread_t td;
    CUTE_ASSERT(macgonuts_run_metaspoofer(NULL) == EINVAL);
    spfgd.hooks.init = macgonuts_spoof_init_hook;
    spfgd.hooks.deinit = macgonuts_spoof_deinit_hook;
    spfgd.hooks.done = macgonuts_spoof_done_hook;
    spfgd.usrinfo.lo_iface = DEFAULT_TEST_IFACE;
    spfgd.spoofing.total = 1000;
    spfgd.spoofing.timeout = 10;
    spfgd.usrinfo.tg_address = "10.0.2.15";
    spfgd.usrinfo.spoof_address = "10.0.2.13";
    spfgd.usrinfo.lo_mac_address = "AA:BB:DD:CC:DD:FF";
    spfgd.usrinfo.tg_mac_address = "00:11:22:33:44:55";
    spfgd.usrinfo.spoof_mac_address = "AA:11:DD:33:DD:55";
    spfgd.layers.proto_addr_version = 4;
    spfgd.layers.proto_addr_version = 4;
    spfgd.layers.proto_addr_size = 4;
    memcpy(&spfgd.layers.lo_hw_addr[0], "\xAA\xBB\xCC\xDD\xEE\xFF", sizeof(spfgd.layers.lo_hw_addr));
    memcpy(&spfgd.layers.lo_proto_addr[0], "\x7F\x00\x00\x01", sizeof(spfgd.layers.lo_proto_addr));
    memcpy(&spfgd.layers.tg_proto_addr[0], "\x7F\x00\x00\x02", sizeof(spfgd.layers.tg_proto_addr));
    memcpy(&spfgd.layers.spoof_proto_addr[0], "\x7F\x00\x00\x03", sizeof(spfgd.layers.spoof_proto_addr));
    memcpy(&spfgd.layers.tg_hw_addr[0], "\x00\x01\x02\x03\x04\x05", sizeof(spfgd.layers.tg_hw_addr));
    memcpy(&spfgd.layers.spoof_hw_addr[0], "\xAA\x01\xBB\x04\xCC\x05", sizeof(spfgd.layers.spoof_hw_addr));
    CUTE_ASSERT(macgonuts_create_thread(&td, gohome, &spfgd) == EXIT_SUCCESS);
    CUTE_ASSERT(macgonuts_run_metaspoofer(&spfgd) == EXIT_SUCCESS);
    CUTE_ASSERT(macgonuts_thread_join(&td, NULL) == EXIT_SUCCESS);
    macgonuts_release_spoof_layers_ctx(&spfgd.layers);
CUTE_TEST_CASE_END
