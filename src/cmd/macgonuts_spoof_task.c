/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <cmd/macgonuts_spoof_task.h>
#include <cmd/hooks/macgonuts_spoof_init_hook.h>
#include <cmd/hooks/macgonuts_spoof_deinit_hook.h>
#include <cmd/hooks/macgonuts_spoof_done_hook.h>
#include <cmd/hooks/macgonuts_spoof_redirect_hook.h>
#include <cmd/macgonuts_option.h>
#include <macgonuts_socket.h>
#include <macgonuts_spoof.h>
#include <macgonuts_metaspoofer.h>
#include <macgonuts_status_info.h>

static struct macgonuts_spoofing_guidance_ctx g_Spfgd = { 0 };

static int is_valid_number(const char *n);

static void sigint_watchdog(int signo);

static int undo_spoof(void);

int macgonuts_spoof_task(void) {
    const char *n = NULL;
    int err = EFAULT;
    int should_redirect = 0;

    g_Spfgd.usrinfo.lo_iface = macgonuts_get_option("lo-iface", NULL);
    if (g_Spfgd.usrinfo.lo_iface == NULL) {
        macgonuts_si_error("--lo-iface option is missing.\n");
        return EXIT_FAILURE;
    }

    g_Spfgd.usrinfo.tg_address = macgonuts_get_option("target-addr", NULL);
    if (g_Spfgd.usrinfo.tg_address == NULL) {
        macgonuts_si_error("--target-addr is missing.\n");
        return EXIT_FAILURE;
    }

    g_Spfgd.usrinfo.spoof_address = macgonuts_get_option("addr2spoof", NULL);
    if (g_Spfgd.usrinfo.spoof_address == NULL) {
        macgonuts_si_error("--addr2spoof is missing.\n");
        return EXIT_FAILURE;
    }

    should_redirect = macgonuts_get_bool_option("redirect", 0);

    n = macgonuts_get_option("fake-pkts-amount", NULL);
    if (n != NULL) {
        /*if (should_redirect) {
            macgonuts_si_error("--fake-pkts-amount is pointless if you want to redirect.\n");
            return EXIT_FAILURE;
        }*/
        if (is_valid_number(n)) {
            g_Spfgd.spoofing.total = atoi(n);
        } else {
            macgonuts_si_error("--fake-pkts-amount has invalid number.\n");
            return EXIT_FAILURE;
        }
    }

    n = macgonuts_get_option("timeout", NULL);
    if (n != NULL) {
        if (is_valid_number(n)) {
            g_Spfgd.spoofing.timeout = atoi(n);
        } else {
            macgonuts_si_error("--timeout has invalid number.\n");
            return EXIT_FAILURE;
        }
    }

    g_Spfgd.hooks.init = macgonuts_spoof_init_hook;
    g_Spfgd.hooks.deinit = macgonuts_spoof_deinit_hook;
    g_Spfgd.hooks.done = macgonuts_spoof_done_hook;
    g_Spfgd.hooks.redirect = (should_redirect) ? macgonuts_spoof_redirect_hook
                                               : NULL;

    g_Spfgd.handles.wire = macgonuts_create_socket(g_Spfgd.usrinfo.lo_iface, 1);
    if (g_Spfgd.handles.wire == -1) {
        macgonuts_si_error("unable to create socket.\n");
        return EXIT_FAILURE;
    }

    err = macgonuts_get_spoof_on_layers_info(g_Spfgd.handles.wire,
                                             &g_Spfgd.layers,
                                             g_Spfgd.usrinfo.tg_address,
                                             strlen(g_Spfgd.usrinfo.tg_address),
                                             g_Spfgd.usrinfo.spoof_address,
                                             strlen(g_Spfgd.usrinfo.spoof_address),
                                             g_Spfgd.usrinfo.lo_iface);


    if (err == EXIT_SUCCESS) {
        signal(SIGINT, sigint_watchdog);
        signal(SIGTERM, sigint_watchdog);
        err = macgonuts_run_metaspoofer(&g_Spfgd);
        if (macgonuts_get_bool_option("undo-spoof", 0)) {
            if (undo_spoof() == EXIT_SUCCESS) {
                macgonuts_si_info("spoof was undone, you have some chances of staying incognito...\n"
                                  "      muauhauahuaha, muhauahuah... did you like my evil laugh?\n");
            } else {
                macgonuts_si_warn("unable to undo spoof, start thinking about some excuse.\n");
            }
        }
    } else {
        macgonuts_si_error("unable to spoof, check on your conectivity besides target addresses.\n");
    }

    macgonuts_release_socket(g_Spfgd.handles.wire);

    return err;
}

int macgonuts_spoof_task_help(void) {
    macgonuts_si_print("use: macgonuts spoof --lo-iface=<label>\n"
                       "                     --target-addr=<ip4|ip6> --addr2spoof=<ip4|ip6>\n"
                       "                    [--fake-pkts-amount=<n> --timeout=<ms> --redirect --undo-spoof]\n");
    return EXIT_SUCCESS;
}

static int is_valid_number(const char *n) {
    const char *np = n;
    const char *np_end = n + strlen(n);
    while (np != np_end) {
        if (!isdigit(*np)) {
            return 0;
        }
        np++;
    }
    return 1;
}

static void sigint_watchdog(int signo) {
    g_Spfgd.spoofing.abort = 1;
}

static int undo_spoof(void) {
    int err = EFAULT;
    unsigned char *swp_spoof_frm = NULL;
    size_t swp_spoof_frm_size = 0;
    uint8_t swp_hw_addr[6];
    memcpy(&swp_hw_addr[0], &g_Spfgd.layers.lo_hw_addr[0], sizeof(swp_hw_addr));
    memcpy(&g_Spfgd.layers.lo_hw_addr[0], &g_Spfgd.layers.spoof_hw_addr[0], sizeof(g_Spfgd.layers.lo_hw_addr));
    swp_spoof_frm = g_Spfgd.layers.spoof_frm;
    swp_spoof_frm_size = g_Spfgd.layers.spoof_frm_size;
    g_Spfgd.layers.spoof_frm = NULL;
    g_Spfgd.layers.spoof_frm_size = 0;
    err = macgonuts_spoof(g_Spfgd.handles.wire, &g_Spfgd.layers);
    memcpy(&g_Spfgd.layers.lo_hw_addr[0], &swp_hw_addr[0], sizeof(g_Spfgd.layers.lo_hw_addr));
    g_Spfgd.layers.spoof_frm = swp_spoof_frm;
    g_Spfgd.layers.spoof_frm_size = swp_spoof_frm_size;
    swp_spoof_frm = NULL;
    return err;
}
