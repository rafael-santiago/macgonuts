/*
 * Copyright (c) 2023, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <macgonuts_types.h>
#include <macgonuts_spoof.h>
#include <macgonuts_status_info.h>
#include <macgonuts_socket.h>

int macgonuts_binds_spoof(char *lo_iface, char *target_addr, char *addr2spoof,
                          int fake_pkts_amount, int timeout) {
    macgonuts_socket_t rsk = -1;
    struct macgonuts_spoof_layers_ctx layers;
    int err = EXIT_FAILURE;
    int f;
    int timeout_mss;

    rsk = macgonuts_create_socket(lo_iface, 1);

    if (rsk == -1) {
        macgonuts_si_error("unable to create socket.\n");
        return EXIT_FAILURE;
    }

    memset(&layers, 0, sizeof(layers));

    err = macgonuts_get_spoof_layers_info(rsk, &layers,
                                          target_addr, strlen(target_addr),
                                          addr2spoof, strlen(addr2spoof), lo_iface);
    if (err != EXIT_SUCCESS) {
        macgonuts_si_error("unable to fill up spoofing layers context.\n");
        goto macgonuts_binds_spoof_epilogue;
    }

    timeout_mss = timeout * 1000;

    for (f = 0; f < fake_pkts_amount && err == EXIT_SUCCESS; f++) {
        err = macgonuts_spoof(rsk, &layers);
        if (err != EXIT_SUCCESS) {
            macgonuts_si_error("when trying to spoof.\n");
            continue;
        }
        if (timeout_mss > 0) {
            usleep(timeout_mss);
        }
    }

    macgonuts_release_spoof_layers_ctx(&layers);

macgonuts_binds_spoof_epilogue:

    macgonuts_release_socket(rsk);

    return err;
}

int macgonuts_binds_undo_spoof(char *lo_iface, char *target_addr, char *addr2spoof) {
    int err = EXIT_FAILURE;
    macgonuts_socket_t rsk = -1;
    struct macgonuts_spoof_layers_ctx layers;

    rsk = macgonuts_create_socket(lo_iface, 1);

    if (rsk == -1) {
        macgonuts_si_error("unable to create socket.\n");
        return EXIT_FAILURE;
    }

    memset(&layers, 0, sizeof(layers));

    err = macgonuts_get_spoof_layers_info(rsk, &layers,
                                          target_addr, strlen(target_addr),
                                          addr2spoof, strlen(addr2spoof), lo_iface);
    if (err != EXIT_SUCCESS) {
        macgonuts_si_error("unable to fill up spoofing layers context.\n");
        goto macgonuts_binds_undo_spoof_epilogue;
    }

    err = macgonuts_undo_spoof(rsk, &layers);

    macgonuts_release_spoof_layers_ctx(&layers);

macgonuts_binds_undo_spoof_epilogue:

    macgonuts_release_socket(rsk);

    return err;
}
