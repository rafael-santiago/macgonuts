/*
 * Copyright (c) 2023, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <macgonuts_types.h>
#include <macgonuts_thread.h>
#include <macgonuts_ipconv.h>
#include <macgonuts_memglob.h>
#include <macgonuts_status_info.h>

// INFO(Rafael): The following structures must be opaque out from here.
//               Do not include `macgonuts_etc_hoax.h`, please, otherwise redefinitions errors will show up.

struct macgonuts_ht_glob_ctx {
    unsigned char *ht_glob;
    size_t ht_glob_size;
    struct macgonuts_ht_glob_ctx *next;
};

typedef struct etc_hoax_handle {
    uint8_t in_addr[16];
    size_t in_addr_size;
    struct macgonuts_ht_glob_ctx *ht_globs;
    struct etc_hoax_handle *next;
    macgonuts_mutex_t giant_lock;
}macgonuts_etc_hoax_handle;

static size_t get_hoaxes_total(const char *data, const size_t data_size);

static size_t get_ht_globs_total(const char *data, const size_t data_size);

static const char *get_next_line(const char *data, const char *data_end);

static const char *get_next_hoax_entry(const char *data, const char *data_end, const char **entry_end);

static const char *get_next_hoax_entry_field(const char *data, const char *data_end, const char **field_end);

static char *get_etc_hoax_data(const char *filepath, char **etc_hoax_data_end);

static macgonuts_etc_hoax_handle *create_etc_hoax_recs(const size_t recs_nr);

static struct macgonuts_ht_glob_ctx *create_ht_glob_recs(const size_t recs_nr);

static size_t get_addr_from_hoax_entry(char *addr_buf, const size_t max_addr_buf_size,
                                       const char *data, const char *data_end);

static int load_ht_globs_from_entry(struct macgonuts_ht_glob_ctx *ht_globs, const char *data, const char *data_end);

static int last_addr_is_dup(const macgonuts_etc_hoax_handle *head, const macgonuts_etc_hoax_handle *tail);

static size_t get_field_len(const char *field, const char *data_end);

#define CREATE_RECS_IMPL(recs, recs_nr, recs_type) {\
    recs_type *recs =\
        (recs_type *)malloc(recs_nr * sizeof(recs_type));\
    recs_type *rp = recs;\
    recs_type *rp_end = rp + recs_nr - 1;\
    if (rp == NULL) {\
        return NULL;\
    }\
    memset(rp, 0, sizeof(recs_type) * recs_nr);\
    while (rp != rp_end) {\
        rp->next = rp + 1;\
        rp++;\
    }\
    return recs;\
}

#define ETC_HOAX_COMMENT        '#'
#define ETC_HOAX_NEW_LINE       '\n'
#define ETC_HOAX_LINE_RET       '\r'

#define is_etc_hoax_field_sep(c) ( (c) == ' ' || (c) == '\t' )

#define is_etc_hoax_line_tok(c) ( (c) == ETC_HOAX_NEW_LINE )

#define is_etc_hoax_comment_tok(c) ( (c) == ETC_HOAX_COMMENT )

#define is_etc_hoax_blank(c) ( is_etc_hoax_field_sep(c) || is_etc_hoax_line_tok(c) || c == ETC_HOAX_LINE_RET )

void macgonuts_close_etc_hoax(macgonuts_etc_hoax_handle *etc_hoax) {
    struct macgonuts_ht_glob_ctx *hp = NULL;
    macgonuts_etc_hoax_handle *ep = NULL;

    for (ep = etc_hoax; ep != NULL; ep = ep->next) {
        for (hp = ep->ht_globs; hp != NULL; hp = hp->next) {
            if (hp->ht_glob != NULL) {
                free(hp->ht_glob);
            }
        }
        free(ep->ht_globs);
    }

    macgonuts_mutex_destroy(&etc_hoax->giant_lock);

    free(etc_hoax);
}

macgonuts_etc_hoax_handle *macgonuts_open_etc_hoax(const char *filepath) {
    char *etc_hoax_data_end = NULL;
    char *etc_hoax_data = get_etc_hoax_data(filepath, &etc_hoax_data_end);
    size_t hoaxes_nr = 0;
    size_t ht_globs_nr = 0;
    macgonuts_etc_hoax_handle *etc_hoax_handle = NULL;
    macgonuts_etc_hoax_handle *ep = NULL;
    const char *curr_entry = NULL;
    const char *curr_entry_end = NULL;
    char addr_buf[256] = "";
    size_t addr_buf_size = 0;

    if (etc_hoax_data == NULL) {
        goto macgonuts_open_etc_hoax_epilogue;
    }

    hoaxes_nr = get_hoaxes_total(etc_hoax_data, etc_hoax_data_end - etc_hoax_data);
    if (hoaxes_nr == 0) {
        goto macgonuts_open_etc_hoax_epilogue;
    }

    etc_hoax_handle = create_etc_hoax_recs(hoaxes_nr);
    if (etc_hoax_handle == NULL) {
        goto macgonuts_open_etc_hoax_epilogue;
    }

    if (macgonuts_mutex_init(&etc_hoax_handle->giant_lock) != EXIT_SUCCESS) {
        macgonuts_close_etc_hoax(etc_hoax_handle);
        goto macgonuts_open_etc_hoax_epilogue;
    }

    curr_entry = etc_hoax_data;

    for (ep = etc_hoax_handle; ep != NULL; ep = ep->next) {
        curr_entry = get_next_hoax_entry(curr_entry, etc_hoax_data_end, &curr_entry_end);
        if (curr_entry == NULL) {
            break;
        }

        ht_globs_nr = get_ht_globs_total(curr_entry, curr_entry_end - curr_entry);
        if (ht_globs_nr == 0) {
            macgonuts_si_error("hoax file `%s` contains a unamed address.\n");
            macgonuts_close_etc_hoax(etc_hoax_handle);
            etc_hoax_handle = NULL;
            goto macgonuts_open_etc_hoax_epilogue;
        }
        ep->ht_globs = create_ht_glob_recs(ht_globs_nr);

        addr_buf_size = get_addr_from_hoax_entry(addr_buf, sizeof(addr_buf), curr_entry, curr_entry_end);

        switch (macgonuts_get_ip_version(addr_buf, addr_buf_size)) {
            case 4:
                ep->in_addr_size = 4;
                break;

            case 6:
                ep->in_addr_size = 16;
                break;

            default:
                ep->in_addr_size = 0;
                break;
        }

        if (ep->in_addr_size == 0) {
            macgonuts_si_error("a valid ip address was expected.\n", addr_buf, addr_buf_size);
            macgonuts_close_etc_hoax(etc_hoax_handle);
            etc_hoax_handle = NULL;
            goto macgonuts_open_etc_hoax_epilogue;
        }

        if (macgonuts_get_raw_ip_addr(ep->in_addr, sizeof(ep->in_addr), addr_buf, addr_buf_size) != EXIT_SUCCESS) {
            macgonuts_si_error("error during ip address conversion.\n");
            macgonuts_close_etc_hoax(etc_hoax_handle);
            etc_hoax_handle = NULL;
            goto macgonuts_open_etc_hoax_epilogue;
        }

        if (last_addr_is_dup(etc_hoax_handle, ep)) {
            macgonuts_si_error("address entry duplicated, merge them up and try again.\n");
            macgonuts_close_etc_hoax(etc_hoax_handle);
            etc_hoax_handle = NULL;
            goto macgonuts_open_etc_hoax_epilogue;
        }

        if (load_ht_globs_from_entry(ep->ht_globs, curr_entry, curr_entry_end) != EXIT_SUCCESS) {
            macgonuts_si_error("error during entry globs loading from the informed etc-hoax file.\n");
            macgonuts_close_etc_hoax(etc_hoax_handle);
            etc_hoax_handle = NULL;
            goto macgonuts_open_etc_hoax_epilogue;
        }
    }

macgonuts_open_etc_hoax_epilogue:

    if (etc_hoax_data != NULL) {
        free(etc_hoax_data);
    }

    return etc_hoax_handle;
}

int macgonuts_gethostbyname(uint8_t *in_addr, const size_t in_addr_max_size, size_t *in_addr_size,
                            macgonuts_etc_hoax_handle *etc_hoax, const char *name, const size_t name_size) {
    const macgonuts_etc_hoax_handle *ep = NULL;
    const struct macgonuts_ht_glob_ctx *hp = NULL;
    int err = ENOENT;

    if (in_addr == NULL
        || (in_addr_max_size != 4 && in_addr_max_size != 16)
        || in_addr_size == NULL
        || etc_hoax == NULL
        || name == NULL
        || name_size == 0) {
        return EINVAL;
    }

    if (macgonuts_mutex_lock(&etc_hoax->giant_lock) != EXIT_SUCCESS) {
        return EBUSY;
    }

    for (ep = etc_hoax; ep != NULL && err == ENOENT; ep = ep->next) {
        for (hp = ep->ht_globs; hp != NULL && err == ENOENT; hp = hp->next) {
            if (ep->in_addr_size == in_addr_max_size
                && macgonuts_memglob((const unsigned char *)name, name_size, hp->ht_glob, hp->ht_glob_size)) {
                memcpy(in_addr, ep->in_addr, ep->in_addr_size);
                *in_addr_size = ep->in_addr_size;
                err = EXIT_SUCCESS;
            }
        }
    }

    macgonuts_mutex_unlock(&etc_hoax->giant_lock);

    return err;
}

static int last_addr_is_dup(const macgonuts_etc_hoax_handle *head, const macgonuts_etc_hoax_handle *tail) {
    const macgonuts_etc_hoax_handle *p = NULL;
    for (p = head; p != tail; p = p->next) {
        if (p->in_addr_size == tail->in_addr_size && memcmp(p->in_addr, tail->in_addr, p->in_addr_size) == 0) {
            return 1;
        }
    }
    return 0;
}

static int load_ht_globs_from_entry(struct macgonuts_ht_glob_ctx *ht_globs, const char *data, const char *data_end) {
    // INFO(Rafael): It will parse information in the following form:
    //                          <addr> <glob_0> ... <glob_{n-1}> <glob_n>
    const char *curr_glob = NULL;
    const char *curr_glob_end = NULL;
    struct macgonuts_ht_glob_ctx *hp = NULL;

    // INFO(Rafael): Skipping up the address definition.
    curr_glob = get_next_hoax_entry_field(data, data_end, &curr_glob_end);
    if (curr_glob == NULL) {
        return EXIT_FAILURE;
    }

    curr_glob = get_next_hoax_entry_field(curr_glob_end, data_end, &curr_glob_end);
    if (curr_glob == NULL) {
        return EXIT_FAILURE;
    }

    hp = ht_globs;
    do {
        hp->ht_glob_size = get_field_len(curr_glob, data_end);
        if (hp->ht_glob_size == 0) {
            return ENODATA;
        }

        hp->ht_glob = (unsigned char *)malloc(hp->ht_glob_size);
        if (hp->ht_glob == NULL) {
            return ENOMEM;
        }

        memcpy(hp->ht_glob, curr_glob, hp->ht_glob_size);

        curr_glob = get_next_hoax_entry_field(curr_glob_end, data_end, &curr_glob_end);
        hp = hp->next;
    } while (curr_glob != NULL && hp != NULL);

    assert(curr_glob == NULL && hp == NULL);

    return EXIT_SUCCESS;
}

static struct macgonuts_ht_glob_ctx *create_ht_glob_recs(const size_t recs_nr) {
    CREATE_RECS_IMPL(recs, recs_nr, struct macgonuts_ht_glob_ctx);
}

static macgonuts_etc_hoax_handle *create_etc_hoax_recs(const size_t recs_nr) {
    CREATE_RECS_IMPL(recs, recs_nr, macgonuts_etc_hoax_handle);
}

static char *get_etc_hoax_data(const char *filepath, char **etc_hoax_data_end) {
    char *data = NULL;
    struct stat st;
    FILE *etc_hoax = NULL;

    if (filepath == NULL || stat(filepath, &st) != EXIT_SUCCESS) {
        return NULL;
    }

    etc_hoax = fopen(filepath, "rb");
    if (etc_hoax == NULL) {
        return NULL;
    }

    data = (char *)malloc(st.st_size);
    if (data == NULL) {
        return NULL;
    }

    fread(data, 1, st.st_size, etc_hoax);
    fclose(etc_hoax);
    *etc_hoax_data_end = data + st.st_size;

    return data;
}

static size_t get_hoaxes_total(const char *data, const size_t data_size) {
    const char *d = NULL;
    const char *d_end = NULL;
    size_t t = 0;

    if (data == NULL || data_size == 0) {
        return 0;
    }

    d = data;
    d_end = d + data_size;

    while (d < d_end) {
        switch (*d) {
            case ETC_HOAX_COMMENT:
                d = get_next_line(d, d_end);

            case ETC_HOAX_NEW_LINE:
            case ETC_HOAX_LINE_RET:
                d++;
                break;

            default:
                t += 1;
                d = get_next_line(d, d_end);
                break;
        }
    }

    return t;
}

static size_t get_ht_globs_total(const char *data, const size_t data_size) {
    const char *field = NULL;
    const char *field_end = NULL;
    const char *data_end = data + data_size;
    ssize_t t = -1;
    field = get_next_hoax_entry_field(data, data_end, &field_end);

    while (field != NULL) {
        t++;
        field = get_next_hoax_entry_field(field_end, data_end, &field_end);
    }

    assert(t > -1);

    return t;
}

static const char *get_next_line(const char *data, const char *data_end) {
    if (data >= data_end) {
        return data_end;
    }

    while ((data + 1) != data_end && !is_etc_hoax_line_tok(*data)) {
        data++;
    }

    return (data + 1);
}

static const char *get_next_hoax_entry(const char *data, const char *data_end, const char **entry_end) {
    const char *d = data;

    if (*entry_end == NULL && *data != '#') {
        d = data;
        goto get_next_hoax_entry_epilogue;
    }

    *entry_end = NULL;

    do {
        d = get_next_line(d, data_end);

        while (d != data_end
               && is_etc_hoax_blank(*d)) {
            d++;
        }

        if (d >= data_end) {
            return NULL;
        }
    } while (data != data_end && is_etc_hoax_comment_tok(*d));

get_next_hoax_entry_epilogue:

    *entry_end = get_next_line(d, data_end);

    return d;
}

static const char *get_next_hoax_entry_field(const char *data, const char *data_end, const char **field_end) {
    const char *field_head = data;
    const char *field_tail = NULL;

    if (field_head == NULL || field_head == data_end) {
        return NULL;
    }

    while (field_head != data_end && is_etc_hoax_field_sep(*field_head)) {
        field_head++;
    }

    field_tail = field_head;

    while (field_tail != data_end && !is_etc_hoax_field_sep(*field_tail)) {
        field_tail++;
    }

    *field_end = field_tail;

    return field_head;
}

static size_t get_addr_from_hoax_entry(char *addr_buf, const size_t max_addr_buf_size,
                                       const char *data, const char *data_end) {
    const char *d = data;
    char *ap = addr_buf;
    char *ap_end = ap + max_addr_buf_size - 1;

    if (d >= data_end) {
        return 0;
    }

    memset(addr_buf, 0, max_addr_buf_size);

    while (d != data_end && ap != ap_end && !is_etc_hoax_field_sep(*d)) {
        *ap = *d;
        d++;
        ap++;
    }

    // INFO(Rafael): Incomplete entry let's abort from here to finish this dead-end processing asap.
    if (d == data_end) {
        return 0;
    }

    return (ap - addr_buf); // INFO(Rafael): Small buffers will result on invalid addresses.
}

static size_t get_field_len(const char *field, const char *data_end) {
    const char *fp = field;
    while (fp != data_end && !is_etc_hoax_blank(*fp)) {
        fp++;
    }
    return (fp - field);
}

#undef CREATE_RECS_IMPL

#undef ETC_HOAX_COMMENT
#undef ETC_HOAX_NEW_LINE
#undef ETC_HOAX_LINE_RET

#undef is_etc_hoax_field_sep

#undef is_etc_hoax_line_tok

#undef is_etc_hoax_comment_tok

#undef is_etc_hoax_blank
