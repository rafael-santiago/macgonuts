/*
 * Copyright (c) 2023, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <freebsd/macgonuts_bpf_fifo.h>
#include <net/bpf.h>
#include <sys/ioctl.h>
#include <macgonuts_thread.h>
#include <macgonuts_socket.h>

struct ethframe_fifo_ctx {
    unsigned char *frame;
    size_t frame_size;
    struct ethframe_fifo_ctx *next;
};

struct socket_fifo_ctx {
    macgonuts_socket_t sockfd;
    struct {
        struct ethframe_fifo_ctx *head;
        struct ethframe_fifo_ctx *tail;
    }fifo;
    struct socket_fifo_ctx *last, *next;
};

static struct {
    macgonuts_mutex_t giant_lock;
    struct socket_fifo_ctx *sk_head;
    struct socket_fifo_ctx *sk_tail;
}g_MacgonutsBPFFifo;

#define new_ethframe_fifo_ctx(eff, frm, frm_size) {\
    (eff) = (struct ethframe_fifo_ctx *)malloc(sizeof(struct ethframe_fifo_ctx));\
    if ((eff) != NULL) {\
        (eff)->next = NULL;\
        (eff)->frame = (unsigned char *)malloc(frm_size);\
        if ((eff)->frame != NULL) {\
            memcpy((eff)->frame, frm, frm_size);\
            (eff)->frame_size = frm_size;\
        } else {\
            free((eff));\
            eff = NULL;\
        }\
    }\
}

#define new_socket_fifo_ctx(skf, sk) {\
    (skf) = (struct socket_fifo_ctx *)malloc(sizeof(struct socket_fifo_ctx));\
    if ((skf) != NULL) {\
        (skf)->sockfd = sk;\
        (skf)->fifo.head = (skf)->fifo.tail = NULL;\
        (skf)->next = (skf)->last = NULL;\
    }\
}

static void release_ethframe_fifo_ctx(struct ethframe_fifo_ctx *eff);

static int ethframe_fifo_ctx_enqueue(struct ethframe_fifo_ctx **eff,
                                     const unsigned char *frame, const size_t frame_size);

static int ethframe_fifo_ctx_dequeue(struct ethframe_fifo_ctx **eff, unsigned char *frame,
                                     const size_t max_frame_size, ssize_t *frame_size);

static struct socket_fifo_ctx *get_socket_fifo(const macgonuts_socket_t sockfd, struct socket_fifo_ctx *skf);

static void release_socket_fifo_ctx(struct socket_fifo_ctx *skf);

static int sync_macgonuts_bpf_fifo_close(const macgonuts_socket_t socfkd);

static int sync_macgonuts_bpf_fifo_create(const macgonuts_socket_t sockfd);

static size_t flush_bpf_device(struct socket_fifo_ctx *skf, const macgonuts_socket_t sockfd);

int macgonuts_bpf_fifo_init(void) {
    g_MacgonutsBPFFifo.sk_head = NULL;
    g_MacgonutsBPFFifo.sk_tail = NULL;
    return macgonuts_mutex_init(&g_MacgonutsBPFFifo.giant_lock);
}

int macgonuts_bpf_fifo_deinit(void) {
    release_socket_fifo_ctx(g_MacgonutsBPFFifo.sk_head);
    return macgonuts_mutex_destroy(&g_MacgonutsBPFFifo.giant_lock);
}

ssize_t macgonuts_bpf_fifo_enqueue(const macgonuts_socket_t sockfd, const void *buf, const size_t buf_size) {
    int err = EXIT_FAILURE;

    if (macgonuts_mutex_lock(&g_MacgonutsBPFFifo.giant_lock) != EXIT_SUCCESS) {
        return -1;
    }

    if (write(sockfd, buf, buf_size) == buf_size) {
        err = EXIT_SUCCESS;
    }

    macgonuts_mutex_unlock(&g_MacgonutsBPFFifo.giant_lock);

    return (err == EXIT_SUCCESS) ? buf_size : -1;
}

ssize_t macgonuts_bpf_fifo_dequeue(const macgonuts_socket_t sockfd, void *buf, const size_t buf_size) {
    int err = EXIT_FAILURE;
    struct socket_fifo_ctx *skf = NULL;
    ssize_t bytes_total = -1;

    if (macgonuts_mutex_lock(&g_MacgonutsBPFFifo.giant_lock) != EXIT_SUCCESS) {
        return -1;
    }

    skf = get_socket_fifo(sockfd, g_MacgonutsBPFFifo.sk_head);
    assert(skf != NULL);

    if (skf->fifo.head == NULL) {
        if (flush_bpf_device(skf, sockfd) == 0) {
            bytes_total = 0;
            err = EXIT_SUCCESS;
            goto macgonuts_bpf_fifo_dequeue_epilogue;
        }
        skf->fifo.head = skf->fifo.tail;
    }

    err = ethframe_fifo_ctx_dequeue(&skf->fifo.head, buf, buf_size, &bytes_total);

    if (skf->fifo.head == NULL) {
        skf->fifo.tail = NULL;
    }

macgonuts_bpf_fifo_dequeue_epilogue:

    macgonuts_mutex_unlock(&g_MacgonutsBPFFifo.giant_lock);

    return (err == EXIT_SUCCESS) ? bytes_total : -1;
}

int macgonuts_bpf_fifo_close(const macgonuts_socket_t sockfd) {
    int err = EXIT_FAILURE;

    err = macgonuts_mutex_lock(&g_MacgonutsBPFFifo.giant_lock);
    if (err != EXIT_SUCCESS) {
        return err;
    }

    err = sync_macgonuts_bpf_fifo_close(sockfd);

    macgonuts_mutex_unlock(&g_MacgonutsBPFFifo.giant_lock);
    return err;
}

int macgonuts_bpf_fifo_create(const macgonuts_socket_t sockfd) {
    int err = EXIT_FAILURE;
    err = macgonuts_mutex_lock(&g_MacgonutsBPFFifo.giant_lock);
    if (err != EXIT_SUCCESS) {
        return err;
    }

    err = sync_macgonuts_bpf_fifo_create(sockfd);

    macgonuts_mutex_unlock(&g_MacgonutsBPFFifo.giant_lock);
    return err;
}

static size_t flush_bpf_device(struct socket_fifo_ctx *skf, const macgonuts_socket_t sockfd) {
    unsigned char *bpf_buf = NULL;
    struct bpf_hdr *bpf_pkt = NULL;
    unsigned char *p = NULL;
    unsigned char *p_end = NULL;
    ssize_t bytes_total = -1;
    size_t flushes_nr = 0;

    bpf_buf = (unsigned char *)malloc(MACGONUTS_BPF_BLEN);
    if (bpf_buf == NULL) {
        return 0;
    }

    memset(bpf_buf, 0, MACGONUTS_BPF_BLEN);

    bytes_total = read(sockfd, bpf_buf, MACGONUTS_BPF_BLEN);
    if (bytes_total <= 0) {
        goto flush_bpf_device_epilogue;
    }

    p = bpf_buf;
    p_end = bpf_buf + bytes_total;
    while (p < p_end) {
        bpf_pkt = (struct bpf_hdr *)p;
        /*for (size_t x = 0; x < bpf_pkt->bh_datalen; x++) {
            printf("%.2X", ((unsigned char *)p + bpf_pkt->bh_hdrlen)[x]);
        }
        printf("--\n");*/
        flushes_nr += (ethframe_fifo_ctx_enqueue(&skf->fifo.tail,
                                                 (unsigned char *)(p + bpf_pkt->bh_hdrlen),
                                                 bpf_pkt->bh_datalen) == EXIT_SUCCESS);
        p += BPF_WORDALIGN(bpf_pkt->bh_hdrlen + bpf_pkt->bh_caplen);
    }

flush_bpf_device_epilogue:

    if (bpf_buf != NULL) {
        free(bpf_buf);
    }

    //printf("added %lu packets.\n", flushes_nr);

    return flushes_nr;
}

static int sync_macgonuts_bpf_fifo_close(const macgonuts_socket_t sockfd) {
    struct socket_fifo_ctx *skf = get_socket_fifo(sockfd, g_MacgonutsBPFFifo.sk_head);
    if (skf == NULL) {
        return ENOENT;
    }

    if (g_MacgonutsBPFFifo.sk_head == skf) {
        g_MacgonutsBPFFifo.sk_head = skf->next;
    } else if (g_MacgonutsBPFFifo.sk_tail == skf) {
        g_MacgonutsBPFFifo.sk_tail = skf->last;
    }

    if (skf->last != NULL) {
        skf->last->next = skf->next;
        skf->next = NULL;
    }

    release_socket_fifo_ctx(skf);
    return EXIT_SUCCESS;
}

static int sync_macgonuts_bpf_fifo_create(const macgonuts_socket_t sockfd) {
    struct socket_fifo_ctx *skf = get_socket_fifo(sockfd, g_MacgonutsBPFFifo.sk_head);
    if (skf != NULL) {
        return EEXIST;
    }

    new_socket_fifo_ctx(skf, sockfd);
    if (skf == NULL) {
        return ENOMEM;
    }

    if (g_MacgonutsBPFFifo.sk_head == NULL) {
        g_MacgonutsBPFFifo.sk_head = skf;
        g_MacgonutsBPFFifo.sk_tail = skf;
    } else {
        skf->last = g_MacgonutsBPFFifo.sk_tail;
        g_MacgonutsBPFFifo.sk_tail->next = skf;
        g_MacgonutsBPFFifo.sk_tail = skf;
    }

    return EXIT_SUCCESS;
}

static void release_ethframe_fifo_ctx(struct ethframe_fifo_ctx *eff) {
    struct ethframe_fifo_ctx *p = NULL;
    struct ethframe_fifo_ctx *t = NULL;
    if (eff == NULL) {
        return;
    }
    for (p = t = eff; t != NULL; p = t) {
        t = p->next;
        if (p->frame != NULL) {
            free(p->frame);
        }
        free(p);
    }
}

static int ethframe_fifo_ctx_enqueue(struct ethframe_fifo_ctx **eff,
                                     const unsigned char *frame, const size_t frame_size) {
    int err = EXIT_FAILURE;

    if (*eff == NULL) {
        new_ethframe_fifo_ctx(*eff, frame, frame_size);
        if (*eff == NULL) {
            err = ENOMEM;
            goto ethframe_fifo_ctx_enqueue_epilogue;
        }
    } else {
        new_ethframe_fifo_ctx((*eff)->next, frame, frame_size);
        if ((*eff)->next == NULL) {
            err = ENOMEM;
            goto ethframe_fifo_ctx_enqueue_epilogue;
        }
        (*eff) = (*eff)->next;
    }

    err = EXIT_SUCCESS;

ethframe_fifo_ctx_enqueue_epilogue:

    return err;
}

static int ethframe_fifo_ctx_dequeue(struct ethframe_fifo_ctx **eff, unsigned char *frame,
                                     const size_t max_frame_size, ssize_t *frame_size) {
    struct ethframe_fifo_ctx *next_frame = NULL;

    if ((*eff) == NULL) {
        *frame_size = 0;
        return ENODATA;
    }

    if ((*eff)->frame_size > max_frame_size) {
        *frame_size = (*eff)->frame_size;
        return ENOBUFS;
    }

    memcpy(frame, (*eff)->frame, (*eff)->frame_size);
    *frame_size = (*eff)->frame_size;
    next_frame = (*eff)->next;
    (*eff)->next = NULL;
    release_ethframe_fifo_ctx(*eff);
    *eff = next_frame;

    return EXIT_SUCCESS;
}

static struct socket_fifo_ctx *get_socket_fifo(const macgonuts_socket_t sockfd, struct socket_fifo_ctx *skf) {
    struct socket_fifo_ctx *sp = NULL;

    if (skf == NULL) {
        return NULL;
    }

    for (sp = skf; sp != NULL; sp = sp->next) {
        if (sp->sockfd == sockfd) {
            return sp;
        }
    }

    return NULL;
}

static void release_socket_fifo_ctx(struct socket_fifo_ctx *skf) {
    struct socket_fifo_ctx *p = NULL;
    struct socket_fifo_ctx *t = NULL;
    for (p = t = skf; t != NULL; p = t) {
        t = p->next;
        if (p->fifo.head != NULL) {
            release_ethframe_fifo_ctx(p->fifo.head);
        }
        free(p);
    }
}

#undef new_ethframe_fifo_ctx

#undef new_socket_fifo_ctx
