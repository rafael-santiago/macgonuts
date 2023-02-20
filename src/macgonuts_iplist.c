/*
 * Copyright (c) 2023, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <macgonuts_types.h>
#include <macgonuts_ipconv.h>
#include <macgonuts_status_info.h>

typedef struct iplist_handle {
    uint8_t in_addr[16];
    size_t in_addr_size;
    struct iplist_handle *next;
}macgonuts_iplist_handle;

void macgonuts_iplist_release(macgonuts_iplist_handle *iplist) {
    if (iplist != NULL) {
        free(iplist);
    }
}

macgonuts_iplist_handle *macgonuts_iplist_parse(const char *iplist, const size_t iplist_size) {
    const char *ip = NULL;
    const char *ip_end = NULL;
    const char *l_ip = NULL;
    macgonuts_iplist_handle *iplist_handle = NULL;
    macgonuts_iplist_handle *list_head = NULL;
    macgonuts_iplist_handle *list_tail = NULL;
    size_t iplist_items_nr = 0;
    char curr_addr[256] = "";
    size_t curr_addr_size = 0;
    int err = EFAULT;
    int (*ip_v)(const char *, const size_t) = NULL;

    if (iplist == NULL || iplist_size == 0) {
        return NULL;
    }

    ip = iplist;
    ip_end = ip + iplist_size;

    if (ip_end[-1] == ',') {
        return NULL;
    }

    while (ip != ip_end) {
        iplist_items_nr += (*ip == ',' || (ip + 1) == ip_end);
        ip++;
    }

    assert(iplist_items_nr > 0);

    iplist_handle = (macgonuts_iplist_handle *)malloc(iplist_items_nr * sizeof(macgonuts_iplist_handle));
    if (iplist_handle == NULL) {
        return NULL;
    }

    memset(iplist_handle, 0, iplist_items_nr * sizeof(macgonuts_iplist_handle));

    list_head = iplist_handle;
    list_tail = list_head + iplist_items_nr - 1;

    while (list_head != list_tail) {
        list_head->next = list_head + 1;
        list_head++;
    }

    l_ip = ip = iplist;
    list_head = iplist_handle;

    while (list_head != NULL && ip < ip_end) {
        if (*ip == ',' || (ip + 1) == ip_end) {
            ip += ((ip + 1) == ip_end);
            curr_addr_size = ip - l_ip;
            memcpy(curr_addr, l_ip, curr_addr_size);

            if (macgonuts_check_ip_addr(curr_addr, curr_addr_size)) {
                err = macgonuts_get_raw_ip_addr(list_head->in_addr,
                                              sizeof(list_head->in_addr),
                                              curr_addr, curr_addr_size);
                ip_v = macgonuts_get_ip_version;
            } else if (macgonuts_check_ip_cidr(curr_addr, curr_addr_size)) {
                err = macgonuts_get_last_net_addr(list_head->in_addr, curr_addr, curr_addr_size);
                ip_v = macgonuts_get_cidr_version;
            } else {
                macgonuts_si_error("macgonuts iplist item `%s` is invalid.\n", curr_addr);
                err = EPROTO;
            }

            if (err != EXIT_SUCCESS) {
                goto macgonuts_iplist_parse_epilogue;
            }

            assert(ip_v != NULL);

            switch (ip_v(curr_addr, curr_addr_size)) {
                case 4:
                    list_head->in_addr_size = 4;
                    break;

                case 6:
                    list_head->in_addr_size = 16;
                    break;

                default:
                    err = EINVAL;
                    goto macgonuts_iplist_parse_epilogue;
            }

            memset(curr_addr, 0, sizeof(curr_addr));
            l_ip = ip + 1;
            list_head = list_head->next;
        }
        ip++;
    }

    assert(ip > ip_end && list_head == NULL);

macgonuts_iplist_parse_epilogue:

    if (err != EXIT_SUCCESS) {
        macgonuts_iplist_release(iplist_handle);
        iplist_handle = NULL;
    }

    return iplist_handle;
}

int macgonuts_iplist_has(macgonuts_iplist_handle *iplist_handle, const uint8_t *in_addr, const size_t in_addr_size) {
    int has = 0;
    uint8_t in_addr_and[16];
    macgonuts_iplist_handle *hp = NULL;
    size_t i;

    for (hp = iplist_handle; hp != NULL && !has; hp = hp->next) {
        if (hp->in_addr_size == in_addr_size) {
            for (i = 0; i < in_addr_size; i++) {
                in_addr_and[i] = in_addr[i] & hp->in_addr[i];
            }
            has = (memcmp(in_addr_and, in_addr, in_addr_size) == 0);
        }
    }

    return has;
}
