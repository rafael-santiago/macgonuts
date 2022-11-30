/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <macgonuts_metaspoofer.h>
#include <macgonuts_thread.h>
#include <macgonuts_spoof.h>
#include <macgonuts_socket.h>
#include <macgonuts_status_info.h>

#define MACGONUTS_METASPOOFER_MAX_CAPBUF_SZ (64<<10)

static int should_abort(struct macgonuts_spoofing_guidance_ctx *spfgd);

int macgonuts_run_metaspoofer(struct macgonuts_spoofing_guidance_ctx *spfgd) {
    int err = EFAULT;
    size_t total = 1;
    int do_pktcap = 0;
    unsigned char *ethcapbuf = NULL;
    size_t ethcapbuf_size = 0;

    if (spfgd == NULL) {
        return EINVAL;
    }

    assert(spfgd->hooks.init != NULL
            && spfgd->hooks.done != NULL
            && spfgd->hooks.deinit != NULL);

    err = spfgd->hooks.init(spfgd, NULL, 0);

    if (err != EXIT_SUCCESS) {
        return err;
    }

    while (!should_abort(spfgd)) {
        if (macgonuts_mutex_lock(&spfgd->handles.lock) != EXIT_SUCCESS) {
            macgonuts_si_error("mutex exception when trying to hold spoofing guidance context's giant lock.\n");
            continue;
        }

        err = macgonuts_spoof(spfgd->handles.wire, &spfgd->layers);
        if (err != EXIT_SUCCESS) {
            macgonuts_si_warn("unable to inject the spoofed packet in the network, retrying...\n");
            goto macgonuts_run_metaspoofer_endloop;
        }

        // INFO(Rafael): All hooks are executed into a well-synchronized context.

        if (spfgd->hooks.done != NULL) {
            err = spfgd->hooks.done(spfgd, NULL, 0);
        }

        if (spfgd->spoofing.total > 0
            && (total++) == spfgd->spoofing.total) {
            macgonuts_si_info("the defined limit of spoofing packets was hit, now exiting... wait...\n");
            spfgd->spoofing.abort = 1;
        }

        do_pktcap = (err == EXIT_SUCCESS
                     && (spfgd->hooks.capture != NULL || spfgd->hooks.redirect != NULL));
        if (!do_pktcap) {
            goto macgonuts_run_metaspoofer_endloop;
        }

        if (ethcapbuf == NULL) {
            ethcapbuf = (unsigned char *)malloc(MACGONUTS_METASPOOFER_MAX_CAPBUF_SZ);
            if (ethcapbuf == NULL) {
                macgonuts_si_info("unable to allocate capture buffer, retrying at the next time...\n");
                goto macgonuts_run_metaspoofer_endloop;
            }
        }

        ethcapbuf_size = macgonuts_recvpkt(spfgd->handles.wire, ethcapbuf, MACGONUTS_METASPOOFER_MAX_CAPBUF_SZ);
        if (ethcapbuf_size == -1) {
            goto macgonuts_run_metaspoofer_endloop;
        }

        // INFO(Rafael): The idea is: redirect asap, capture later.
        if (spfgd->hooks.redirect != NULL) {
            err = spfgd->hooks.redirect(spfgd, ethcapbuf, ethcapbuf_size);
            if (err != EXIT_SUCCESS && err != ENODATA) {
                macgonuts_si_warn("unable to redirect the captured packet.\n");
            }
        }

        if (spfgd->hooks.capture != NULL) {
            err = spfgd->hooks.capture(spfgd, ethcapbuf, ethcapbuf_size);
            if (err != EXIT_SUCCESS) {
                macgonuts_si_warn("unable to handle the capture packet.\n");
            }
        }

macgonuts_run_metaspoofer_endloop:
        if (spfgd->spoofing.timeout > 0) {
            usleep(spfgd->spoofing.timeout * 1000);
        }

        macgonuts_mutex_unlock(&spfgd->handles.lock);
    }

    err = spfgd->hooks.deinit(spfgd, NULL, 0);

    if (ethcapbuf != NULL) {
        free(ethcapbuf);
        ethcapbuf = NULL;
    }

    return err;
}

static int should_abort(struct macgonuts_spoofing_guidance_ctx *spfgd) {
    int should = 0;
    if (macgonuts_mutex_trylock(&spfgd->handles.lock) == EXIT_SUCCESS) {
        should = spfgd->spoofing.abort;
        macgonuts_mutex_unlock(&spfgd->handles.lock);
    }
    return (should != 0);
}

#undef MACGONUTS_METASPOOFER_MAX_CAPBUF_SZ
