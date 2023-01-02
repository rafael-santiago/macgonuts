/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <cmd/macgonuts_eavesdrop_task.h>
#include <cmd/hooks/macgonuts_eavesdrop_init_hook.h>
#include <cmd/hooks/macgonuts_eavesdrop_deinit_hook.h>
#include <cmd/hooks/macgonuts_eavesdrop_done_hook.h>
#include <cmd/hooks/macgonuts_eavesdrop_redirect_hook.h>
#include <cmd/macgonuts_printpkt.h>
#include <cmd/macgonuts_option.h>
#include <macgonuts_ipconv.h>
#include <macgonuts_status_info.h>
#include <macgonuts_socket.h>
#include <macgonuts_thread.h>
#include <macgonuts_spoof.h>
#include <macgonuts_metaspoofer.h>
#include <macgonuts_pcap.h>
#include <macgonuts_filter_fmt.h>

static struct macgonuts_spoofing_guidance_ctx g_Spfgd[2];

static int run_metaspoofers(struct macgonuts_spoofing_guidance_ctx *target_a,
                            struct macgonuts_spoofing_guidance_ctx *target_b);

static void *run_metaspoofer(void *spfgd);

static void sigint_watchdog(int signo);

int macgonuts_eavesdrop_task(void) {
    int err = EFAULT;
    struct macgonuts_spoofing_guidance_ctx *alice = &g_Spfgd[0];
    struct macgonuts_spoofing_guidance_ctx *bob = &g_Spfgd[1];
    const char *filepath = NULL;
    char **filter_globs = NULL;
    size_t filter_globs_nr = 0;

    alice->usrinfo.lo_iface = macgonuts_get_option("lo-iface", NULL);
    if (alice->usrinfo.lo_iface == NULL) {
        macgonuts_si_error("--lo-iface option is missing.\n");
        return EXIT_FAILURE;
    }

    alice->usrinfo.tg_address = macgonuts_get_option("alice-addr", NULL);
    if (alice->usrinfo.tg_address == NULL) {
        macgonuts_si_error("--alice-addr option is missing.\n");
        return EXIT_FAILURE;
    }

    // INFO(Rafael): Mirroring the guidance structs to apply a bi-directional spoofing.

    bob->usrinfo.lo_iface = alice->usrinfo.lo_iface;

    bob->usrinfo.tg_address = macgonuts_get_option("bob-addr", NULL);
    if (bob->usrinfo.tg_address == NULL) {
        macgonuts_si_error("--bob-addr option is missing.\n");
        return EXIT_FAILURE;
    }

    if (macgonuts_get_ip_version(alice->usrinfo.tg_address, strlen(alice->usrinfo.tg_address)) !=
                macgonuts_get_ip_version(bob->usrinfo.tg_address, strlen(bob->usrinfo.tg_address))) {
        macgonuts_si_error("--alice-addr and --bob-addr must have the same ip version.\n");
        return EXIT_FAILURE;
    }

    alice->usrinfo.spoof_address = bob->usrinfo.tg_address;
    bob->usrinfo.spoof_address = alice->usrinfo.tg_address;

    filepath = macgonuts_get_option("pcap-file", NULL);
    if (filepath == NULL) {
        alice->hooks.capture.printpkt = macgonuts_printpkt;
        filepath = macgonuts_get_option("file", NULL);
        if (filepath == NULL) {
            alice->hooks.capture.pktout = stdout;
        } else {
            alice->metainfo.arg[0] = (void *)filepath;
            alice->hooks.capture.pktout = fopen(filepath, "ab");
            if (alice->hooks.capture.pktout == NULL) {
                macgonuts_si_error("unable to access file `%s`.\n", filepath);
                return EXIT_FAILURE;
            }
        }
    } else {
        alice->metainfo.arg[0] = (void *)filepath;
        alice->hooks.capture.printpkt = macgonuts_printpkt2pcap;
        alice->hooks.capture.pktout = macgonuts_pcapfile_open(filepath);
        if (alice->hooks.capture.pktout == NULL) {
            macgonuts_si_error("unable to access file `%s`.\n", filepath);
            return EXIT_FAILURE;
        }
    }

    bob->hooks.capture.printpkt = alice->hooks.capture.printpkt;
    bob->hooks.capture.pktout = alice->hooks.capture.pktout;

    // INFO(Rafael): Only one side must have init and deinit hooks, thus we can
    //               warn those events once. Redirect needs to be configured in
    //               both because we want to capture all data bidirectionally.
    alice->hooks.init = macgonuts_eavesdrop_init_hook;
    alice->hooks.deinit = macgonuts_eavesdrop_deinit_hook;
    alice->hooks.done = macgonuts_eavesdrop_done_hook;
    alice->hooks.redirect = macgonuts_eavesdrop_redirect_hook;
    bob->hooks.init = NULL;
    bob->hooks.deinit = NULL;
    bob->hooks.done = macgonuts_eavesdrop_done_hook;
    bob->hooks.redirect = macgonuts_eavesdrop_redirect_hook;

    alice->spoofing.timeout = 10;
    bob->spoofing.timeout = 10;

    bob->handles.wire = -1;
    alice->handles.wire = macgonuts_create_socket(alice->usrinfo.lo_iface, 1);
    if (alice->handles.wire == -1) {
        macgonuts_si_error("unable to create socket.\n");
        err = EXIT_FAILURE;
        goto macgonuts_eavesdrop_task_epilogue;
    }

    filter_globs = macgonuts_get_array_option("filter-globs", NULL, &filter_globs_nr);
    if (filter_globs != NULL) {
        alice->hooks.capture.filter_globs = macgonuts_get_filter_glob_ctx(filter_globs,
                                                                          filter_globs_nr,
                                                                          &alice->hooks.capture.filter_globs_nr);
        if (alice->hooks.capture.filter_globs == NULL) {
            macgonuts_si_error("while trying to process informed filter globs.\n");
            err = EFAULT;
            goto macgonuts_eavesdrop_task_epilogue;
        }

        bob->hooks.capture.filter_globs = macgonuts_get_filter_glob_ctx(filter_globs,
                                                                        filter_globs_nr,
                                                                        &bob->hooks.capture.filter_globs_nr);
        if (bob->hooks.capture.filter_globs == NULL) {
            macgonuts_si_error("while trying to process informed filter globs.\n");
            err = EFAULT;
            goto macgonuts_eavesdrop_task_epilogue;
        }
        macgonuts_free_array_option_value(filter_globs, filter_globs_nr);
        filter_globs = NULL;
    }

    err = macgonuts_get_spoof_layers_info(alice->handles.wire,
                                          &alice->layers,
                                          alice->usrinfo.tg_address,
                                          strlen(alice->usrinfo.tg_address),
                                          alice->usrinfo.spoof_address,
                                          strlen(alice->usrinfo.spoof_address),
                                          alice->usrinfo.lo_iface);
    if (err != EXIT_SUCCESS) {
        goto macgonuts_eavesdrop_task_epilogue;
    }

    bob->handles.wire = macgonuts_create_socket(bob->usrinfo.lo_iface, 1);
    if (bob->handles.wire == -1) {
        macgonuts_si_error("unable to create socket.\n");
        err = EXIT_FAILURE;
        goto macgonuts_eavesdrop_task_epilogue;
    }

    if (macgonuts_mutex_init(&alice->handles.lock) != EXIT_SUCCESS) {
        err = EXIT_FAILURE;
        goto macgonuts_eavesdrop_task_epilogue;
    }

    if (macgonuts_mutex_init(&bob->handles.lock) != EXIT_SUCCESS) {
        err = EXIT_FAILURE;
        goto macgonuts_eavesdrop_task_epilogue;
    }

    err = macgonuts_get_spoof_layers_info(bob->handles.wire,
                                          &bob->layers,
                                          bob->usrinfo.tg_address,
                                          strlen(bob->usrinfo.tg_address),
                                          bob->usrinfo.spoof_address,
                                          strlen(bob->usrinfo.spoof_address),
                                          bob->usrinfo.lo_iface);
    if (err != EXIT_SUCCESS) {
        macgonuts_release_spoof_layers_ctx(&alice->layers);
        goto macgonuts_eavesdrop_task_epilogue;
    }

    signal(SIGINT, sigint_watchdog);
    signal(SIGTERM, sigint_watchdog);
    err = run_metaspoofers(alice, bob);

    if (macgonuts_get_bool_option("undo-spoof", 0)) {
        if (macgonuts_undo_spoof(alice->handles.wire, &alice->layers) == EXIT_SUCCESS) {
            macgonuts_si_info("spoof was undone at `%s`.\n", alice->usrinfo.tg_address);
        } else {
            macgonuts_si_warn("unable to undone spoofing at `%s`.\n", alice->usrinfo.tg_address);
        }
        if (macgonuts_undo_spoof(bob->handles.wire, &bob->layers) == EXIT_SUCCESS) {
            macgonuts_si_info("spoof was undone at `%s`.\n", bob->usrinfo.tg_address);
        } else {
            macgonuts_si_warn("unable to undone spoofing at `%s`.\n", bob->usrinfo.tg_address);
        }
    }

    macgonuts_release_spoof_layers_ctx(&alice->layers);
    macgonuts_release_spoof_layers_ctx(&bob->layers);

    macgonuts_mutex_destroy(&alice->handles.lock);
    macgonuts_mutex_destroy(&bob->handles.lock);

macgonuts_eavesdrop_task_epilogue:

    if (alice->handles.wire != -1) {
        macgonuts_release_socket(bob->handles.wire);
    }

    if (bob->handles.wire != -1) {
        macgonuts_release_socket(alice->handles.wire);
    }

    if (alice->hooks.capture.filter_globs != NULL) {
        macgonuts_release_filter_glob_ctx(alice->hooks.capture.filter_globs,
                                          alice->hooks.capture.filter_globs_nr);
    }

    if (bob->hooks.capture.filter_globs != NULL) {
        macgonuts_release_filter_glob_ctx(bob->hooks.capture.filter_globs,
                                          bob->hooks.capture.filter_globs_nr);
    }

    if (filter_globs != NULL) {
        macgonuts_free_array_option_value(filter_globs, filter_globs_nr);
    }

    return err;
}

int macgonuts_eavesdrop_task_help(void) {
    macgonuts_si_print("use: macgonuts eavesdrop --lo-iface=<label>\n"
                       "                         --alice-addr=<ip4|ip6> --bob-addr=<ip4|ip6>\n"
                       "                        [--pcap-file=<path> --file=<path> --filter-globs=<glob_0,...,glob_n> "
                       "--undo-spoof]\n");
    return EXIT_SUCCESS;
}

static int run_metaspoofers(struct macgonuts_spoofing_guidance_ctx *target_a,
                            struct macgonuts_spoofing_guidance_ctx *target_b) {
    macgonuts_thread_t td_a, td_b;
    if (macgonuts_create_thread(&td_a, run_metaspoofer, target_a) != EXIT_SUCCESS) {
        macgonuts_si_error("unable to create spoofing thread for `%s`.\n", target_a->usrinfo.tg_address);
        return EXIT_FAILURE;
    }
    if (macgonuts_create_thread(&td_b, run_metaspoofer, target_b) != EXIT_SUCCESS) {
        macgonuts_si_error("unable to create spoofing thread for `%s`.\n", target_b->usrinfo.tg_address);
        sigint_watchdog(SIGINT);
        usleep(100);
        return EXIT_FAILURE;
    }
    macgonuts_thread_join(&td_a, NULL);
    macgonuts_thread_join(&td_b, NULL);
    return EXIT_SUCCESS;
}

static void *run_metaspoofer(void *spfgd) {
    macgonuts_run_metaspoofer((struct macgonuts_spoofing_guidance_ctx *)spfgd);
    return NULL;
}

static void sigint_watchdog(int signo) {
    g_Spfgd[0].spoofing.abort = 1;
    g_Spfgd[1].spoofing.abort = 1;
}
