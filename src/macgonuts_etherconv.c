/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <macgonuts_etherconv.h>
//#include <fcntl.h>
//#include <unistd.h>
//#include <errno.h>
//#include <ctype.h>
//#include <stdio.h>
//#include <stdlib.h>

int macgonuts_check_ether_addr(const char *ether, const size_t ether_size) {
    const char *ep = ether, *lp = ep;
    const char *ep_end = ep + ether_size;
    int is_valid = 1;
    int two_colon_nr = 0;
    if (ep == NULL || ether_size == 0) {
        return 0;
    }
    do {
        if (*ep == ':' || (ep + 1) == ep_end) {
            two_colon_nr += (*ep == ':');
            ep += ((ep + 1) == ep_end);
            is_valid = (((ep - lp) == 2) && isxdigit(lp[0]) && isxdigit(lp[1]));
            lp = ep + 1;
        }
        ep++;
    } while (is_valid && ep < ep_end);
    return (is_valid && two_colon_nr == 5);
}

int macgonuts_getrandom_ether_addr(char *ether, const size_t max_ether_size) {
    char *ep;
    char xbyte[10] = { 0 };
    size_t oct_nr;
    unsigned char u8;
    int urandom = -1;
    if (max_ether_size < 18) {
        return EXIT_FAILURE;
    }
    urandom = open("/dev/urandom", O_RDONLY);
    if (urandom == -1) {
        fprintf(stderr, "error: unable to read /dev/urandom.\n");
        return EXIT_FAILURE;
    }
    ep = ether;
    for (oct_nr = 0; oct_nr < 7; oct_nr++) {
        read(urandom, &u8, sizeof(u8));
        snprintf(ep, max_ether_size - (ep - ether), "%.2X%c", u8, (oct_nr < 5) ? ':' : '\0');
        ep += 3;
    }
    close(urandom);
    return EXIT_SUCCESS;
}

int macgonuts_get_raw_ether_addr(uint8_t *raw, const size_t max_raw_size,
                                 const char *ether_addr, const size_t ether_addr_size) {
    uint8_t *rp = NULL;
    uint8_t *rp_end = NULL;
    const char *ep = NULL;
    const char *ep_end = NULL;
    if (raw == NULL || !macgonuts_check_ether_addr(ether_addr, ether_addr_size)) {
        return EINVAL;
    }
    if (max_raw_size < 6) {
        return ERANGE;
    }
    memset(raw, 0, max_raw_size);
    rp = raw;
    rp_end = rp + max_raw_size;
    ep = ether_addr;
    ep_end = ep + ether_addr_size;
    while (ep < ep_end && rp != rp_end) {
#define nib2num(n) (isdigit((n)) ? (n) - 48 : toupper((n)) - 55)
        *rp = (uint8_t)nib2num(ep[0]) << 4 | (uint8_t)nib2num(ep[1]);
#undef nib2num
        ep += 3;
        rp++;
    }
    return EXIT_SUCCESS;
}
