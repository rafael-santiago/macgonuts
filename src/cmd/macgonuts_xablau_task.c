/*
 * Copyright (c) 2023, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <cmd/macgonuts_xablau_task.h>
#include <cmd/macgonuts_option.h>
#include <macgonuts_socket_common.h>
#include <macgonuts_socket.h>
#include <macgonuts_ipconv.h>
#include <macgonuts_get_ethaddr.h>
#include <macgonuts_oui_lookup.h>
#include <macgonuts_status_info.h>

#define XABLAU_DO_ARP                   1
#define XABLAU_DO_NDP (XABLAU_DO_ARP << 1)
#define XABLAU_WTF2DO                   0
#define OUI_DBPATH                      "/usr/local/share/macgonuts/etc/oui"

static int do_xablau(const char *lo_iface, const size_t lo_iface_size,
                     const unsigned char discover_type,
                     const int oui, const char *oui_dbpath,
                     FILE *out);

static unsigned char discover_wtf2do(const char *lo_iface);

int do_arp_hunt(FILE *out,
                const int oui, const char *oui_dbpath,
                const macgonuts_socket_t rsk,
                const char *lo_iface, const size_t lo_iface_size);

int do_ndp_hunt(FILE *out,
                const int oui, const char *oui_dbpath,
                const macgonuts_socket_t rsk,
                const char *lo_iface, const size_t lo_iface_size);

int do_meta_hunt(FILE *out,
                 const int oui, const char *oui_dbpath,
                 const macgonuts_socket_t rsk,
                 const char *lo_iface, const size_t lo_iface_size,
                 const size_t proto_size);

static void sigint_watchdog(int signo);

static int g_ShouldExit = 0;

int macgonuts_xablau_task(void) {
    const char *lo_iface = macgonuts_get_option("lo-iface", NULL);
    unsigned char discover_type;
    const char *out = NULL;
    FILE *out_fp = NULL;
    int err = EXIT_FAILURE;
    int oui = 0;
    const char *oui_dbpath = NULL;
    struct stat st = { 0 };

    if (lo_iface == NULL) {
        macgonuts_si_error("--lo-iface option is missing.\n");
        return EXIT_FAILURE;
    }

    discover_type = (macgonuts_get_bool_option("ipv4", 0) ? XABLAU_DO_ARP : 0) |
                    (macgonuts_get_bool_option("ipv6", 0) ? XABLAU_DO_NDP : 0);

    if (discover_type == 0) {
        discover_type = XABLAU_WTF2DO;
    }

    oui = macgonuts_get_bool_option("oui", 0);
    if (oui) {
        oui_dbpath = macgonuts_get_option("oui-dbpath", OUI_DBPATH);
        if (stat(oui_dbpath, &st) != EXIT_SUCCESS) {
            macgonuts_si_error("unable to open oui vendor database at `%s`.\n", oui_dbpath);
            return EXIT_FAILURE;
        }
    }

    out = macgonuts_get_option("out", NULL);
    if (out != NULL) {
        out_fp = fopen(out, "a");
        if (out_fp == NULL) {
            macgonuts_si_error("unable to open `%s` in append mode.\n", out);
            return EXIT_FAILURE;
        }
    } else {
        out_fp = stdout;
    }

    assert(out_fp != NULL);

    err = do_xablau(lo_iface, strlen(lo_iface),
                    discover_type,
                    oui, oui_dbpath,
                    out_fp);

    if (out_fp != NULL && out_fp != stdout) {
        fclose(out_fp);
    }

    return err;
}

int macgonuts_xablau_task_help(void) {
    macgonuts_si_print("use: macgonuts xablau --lo-iface=<label> [--ipv4 --ipv6 --oui --oui-dbpath=<filepath> "
                       "--out=<filepath>]\n");
    return EXIT_SUCCESS;
}

static int do_xablau(const char *lo_iface, const size_t lo_iface_size,
                     const unsigned char discover_type,
                     const int oui, const char *oui_dbpath,
                     FILE *out) {
    unsigned char temp = discover_type;
    int err_ct = 0;
    macgonuts_socket_t rsk = -1;
    struct timeval tv = { 0 };

    if (temp == XABLAU_WTF2DO) {
        temp = discover_wtf2do(lo_iface);
        if (temp == XABLAU_WTF2DO) {
            macgonuts_si_error("interface `%s` does not support ipv4 nor ipv6.\n", lo_iface);
            return EXIT_FAILURE;
        }
    }

    rsk = macgonuts_create_socket(lo_iface, 0);

    if (rsk == -1) {
        macgonuts_si_error("unable to create socket.\n");
        return EXIT_FAILURE;
    }

    tv.tv_usec = 50000;

#if defined(__linux__)
    setsockopt(rsk, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(rsk, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#elif defined(__FreeBSD__)
    ioctl(rsk, BIOCSRTIMEOUT, &tv);
#else
# error Some code wanted.
#endif // defined(__linux__)

    signal(SIGINT, sigint_watchdog);
    signal(SIGTERM, sigint_watchdog);

    macgonuts_si_mode_enter_announce("xablau");

    macgonuts_si_info("hit Ctrl + C to interrupt the targets hunting...\n%s", (out == stdout) ? "\n" : "");

    if (temp & XABLAU_DO_ARP) {
        if (do_arp_hunt(out,
                        oui, oui_dbpath,
                        rsk,
                        lo_iface, lo_iface_size) != EXIT_SUCCESS) {
            err_ct++;
            macgonuts_si_error("unable to find out ipv4 targets.\n");
        }
    }

    if (!g_ShouldExit && (temp & XABLAU_DO_NDP)) {
        if (do_ndp_hunt(out,
                        oui, oui_dbpath,
                        rsk,
                        lo_iface, lo_iface_size) != EXIT_SUCCESS) {
            err_ct++;
            macgonuts_si_error("unable to find out ipv6 targets.\n");
        }
    }

    macgonuts_release_socket(rsk);

    macgonuts_si_mode_leave_announce("xablau");

    return (err_ct == 0) ? EXIT_SUCCESS
                         : EXIT_FAILURE;
}

static unsigned char discover_wtf2do(const char *lo_iface) {
    // INFO(Rafael): A more well-behaved name would be check_on_dual_stack().
    uint8_t addr[16] = { 0 };
    size_t addr_size = 0;
    unsigned char discover_type = XABLAU_WTF2DO;
    if (macgonuts_get_gateway_addr_info_from_iface(&addr[0], &addr_size, 4, lo_iface) == EXIT_SUCCESS) {
        discover_type = XABLAU_DO_ARP;
    }
    if (macgonuts_get_gateway_addr_info_from_iface(&addr[0], &addr_size, 6, lo_iface) == EXIT_SUCCESS) {
        discover_type |= XABLAU_DO_NDP;
    }
    return discover_type;
}

int do_arp_hunt(FILE *out,
                const int oui, const char *oui_dbpath,
                const macgonuts_socket_t rsk,
                const char *lo_iface, const size_t lo_iface_size) {
    return do_meta_hunt(out, oui, oui_dbpath, rsk, lo_iface, lo_iface_size, 4);
}

int do_ndp_hunt(FILE *out,
                const int oui, const char *oui_dbpath,
                const macgonuts_socket_t rsk,
                const char *lo_iface, const size_t lo_iface_size) {
    return do_meta_hunt(out, oui, oui_dbpath, rsk, lo_iface, lo_iface_size, 16);
}

int do_meta_hunt(FILE *out,
                 const int oui, const char *oui_dbpath,
                 const macgonuts_socket_t rsk,
                 const char *lo_iface, const size_t lo_iface_size,
                 const size_t proto_size) {
    uint8_t last_addr[16] = { 0 };
    uint8_t curr_addr[16] = { 0 };
    uint8_t netmask[16] = { 0 };
    uint8_t hw_addr[16] = { 0 };
    const int ip_version[2] = { 6, 4 };
    char lit_addr[80] = "";
    char lit_max_addr[80] = "";
    char mac_addr[32] = "";
    char output[1<<10] = "";
    const char status[2][4] = { { '?', ' ', '?', ' ' }, { ' ', '?', ' ', '?' } };
    const char progress[] = { '|', '-', '\\', '/' };
    size_t p = 0;
    char vendor_id[256] = "";

    if (macgonuts_get_netmask_from_iface(lo_iface,
                                         lo_iface_size,
                                         &netmask[0],
                                         ip_version[(proto_size == 4)]) != EXIT_SUCCESS) {
        macgonuts_si_error("unable to get netmask from interface `%s`.\n", lo_iface);
        return EXIT_FAILURE;
    }

    if (macgonuts_get_maxaddr_from_iface(lo_iface, lo_iface_size,
                                         &last_addr[0], ip_version[(proto_size == 4)]) != EXIT_SUCCESS) {
        macgonuts_si_error("unable to get maximum network address.\n");
        return EXIT_FAILURE;
    }

    curr_addr[0] = last_addr[0] & netmask[0];
    curr_addr[1] = last_addr[1] & netmask[1];
    curr_addr[2] = last_addr[2] & netmask[2];
    curr_addr[3] = last_addr[3] & netmask[3];

    if (proto_size == 16) {
        curr_addr[ 4] = last_addr[ 4] & netmask[ 4];
        curr_addr[ 5] = last_addr[ 5] & netmask[ 5];
        curr_addr[ 6] = last_addr[ 6] & netmask[ 6];
        curr_addr[ 7] = last_addr[ 7] & netmask[ 7];
        curr_addr[ 8] = last_addr[ 8] & netmask[ 8];
        curr_addr[ 9] = last_addr[ 9] & netmask[ 9];
        curr_addr[10] = last_addr[10] & netmask[10];
        curr_addr[11] = last_addr[11] & netmask[11];
        curr_addr[12] = last_addr[12] & netmask[12];
        curr_addr[13] = last_addr[13] & netmask[13];
        curr_addr[14] = last_addr[14] & netmask[14];
        curr_addr[15] = last_addr[15] & netmask[15];
    }

    if (macgonuts_raw_ip2literal(lit_max_addr, sizeof(lit_max_addr) - 1, &last_addr[0], proto_size) != EXIT_SUCCESS) {
        macgonuts_si_error("unable to convert max ip addr to its literal form.\n");
        return EXIT_FAILURE;
    }

    macgonuts_inc_raw_ip(&last_addr[0], proto_size);

    if (!oui) {
        snprintf(output, sizeof(output),
                 ((proto_size == 4) ? "%-20s %-33s\n" : "%-40s %-50s\n"), "IP Address", "MAC Address");
    } else {
        snprintf(output, sizeof(output),
                 ((proto_size == 4) ? "%-20s %-33s %-33s\n" : "%-40s %-25s %-25s\n"),
                 "IP Address", "MAC Address", "Vendor");
    }

    fprintf(out, "%s", output);

    if (!oui) {
        fprintf(out, (proto_size == 4) ? "--------------------------------------\n"
                                       : "--------------------------------------"
                                         "--------------------\n");
    } else {
        fprintf(out, (proto_size == 4) ? "------------------------------------------------------------------------"
                                         "----------------------------\n"
                                       : "--------------------------------------"
                                         "------------------------------------------------------------------------\n");
    }

    do {
        if (macgonuts_raw_ip2literal(lit_addr, sizeof(lit_addr) - 1, &curr_addr[0], proto_size) != EXIT_SUCCESS) {
            macgonuts_si_warn("unable to convert raw ip to its literal form.\n");
            macgonuts_inc_raw_ip(&curr_addr[0], proto_size);
            continue;
        }
        if (macgonuts_get_ethaddr(&hw_addr[0], 6, lit_addr, strlen(lit_addr), rsk, lo_iface) == EXIT_SUCCESS) {
            snprintf(mac_addr, sizeof(mac_addr) - 1, "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X", hw_addr[0],
                                                                                      hw_addr[1],
                                                                                      hw_addr[2],
                                                                                      hw_addr[3],
                                                                                      hw_addr[4],
                                                                                      hw_addr[5]);
            if (!oui) {
                snprintf(output, sizeof(output) - 1,
                        ((proto_size == 4) ? "%-20s %-33s\n" : "%-40s %-50s\n"), lit_addr, mac_addr);
            } else {
                if (macgonuts_oui_lookup(vendor_id, sizeof(vendor_id) - 1,
                                         &hw_addr[0], sizeof(hw_addr),
                                         oui_dbpath) == ENOENT) {
                    snprintf(vendor_id, sizeof(vendor_id) - 1, "(unk)");
                }
                snprintf(output, sizeof(output) - 1,
                        ((proto_size == 4) ? "%-20s %-33s %-33s\n" : "%-40s %-25s %-25s\n"), lit_addr,
                                                                                             mac_addr,
                                                                                             vendor_id);

            }
            if (out == stdout) {
                fprintf(out, "\r                                                                               \r");
            }
            fprintf(out, "%s", output);
        }
        macgonuts_inc_raw_ip(&curr_addr[0], proto_size);
        macgonuts_si_print("\r                                                                                 \r");
        macgonuts_si_print("%c%c %s  /  %s %c\r", status[0][p], status[1][p], lit_addr, lit_max_addr, progress[p]);
        fflush(stdout);
        p = (p + 1) % sizeof(progress);
    } while (memcmp(&curr_addr[0], &last_addr[0], proto_size) != 0 && !g_ShouldExit);

    if (proto_size == 16) {
        macgonuts_si_print("\r                                                                                 \r");
    }

    if (!oui) {
        fprintf(out, (proto_size == 4) ? "--------------------------------------\n"
                                       : "--------------------------------------"
                                         "--------------------\n");
    } else {
        fprintf(out, (proto_size == 4) ? "------------------------------------------------------------------------"
                                         "----------------------------\n"
                                       : "--------------------------------------"
                                         "------------------------------------------------------------------------\n");
    }

    if (out != stdout) {
        macgonuts_si_print("\r                                                                                 \r");
    }

    return EXIT_SUCCESS;
}

static void sigint_watchdog(int signo) {
    g_ShouldExit = 1;
}

#undef XABLAU_DO_ARP
#undef XABLAU_DO_NDP
#undef XABLAU_WTF2DO
#undef OUI_DBPATH
