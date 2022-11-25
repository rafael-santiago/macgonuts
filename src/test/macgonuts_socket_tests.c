/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include "macgonuts_socket_tests.h"
#include "macgonuts_mocks.h"
#include <macgonuts_socket.h>
#include <macgonuts_socket_common.h>
#include <string.h>
#include <pthread.h>

#if defined(__linux__)
# define DEFAULT_TEST_IFACE "eth0"
#else
# error Some code wanted.
#endif

struct rcvctx {
    macgonuts_socket_t *s;
    ssize_t *sz;
};

static void *get_pkt(void *args);

static void *ping_pkt(void *args);

static int get_iface_addr4(char *addr, const size_t max_addr_size, const char *iface);

static int get_iface_addr6(char *addr, const size_t max_addr_size, const char *iface);

static int get_iface_mac(char *mac, const size_t max_mac_size, const char *iface);

static int check_promisc_mode_on(const char *iface);

static int check_promisc_mode_off(const char *iface);

CUTE_TEST_CASE(macgonuts_create_release_socket_tests)
    macgonuts_socket_t rsk = -1;
    rsk = macgonuts_create_socket("unk0", 0);
    CUTE_ASSERT(rsk == -1);
    rsk = macgonuts_create_socket(DEFAULT_TEST_IFACE, 0);
    CUTE_ASSERT(rsk > -1);
    macgonuts_release_socket(rsk);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(macgonuts_sendpkt_tests)
    macgonuts_socket_t rsk = macgonuts_create_socket(DEFAULT_TEST_IFACE, 0);
    char buf[] = "you're good for me.";
    CUTE_ASSERT(rsk > -1);
    CUTE_ASSERT(macgonuts_sendpkt(rsk, buf, strlen(buf)) == strlen(buf));
    macgonuts_release_socket(rsk);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(macgonuts_recvpkt_tests)
    // INFO(Rafael): Pthread stuff tends to leak a lot of resources due to performance issues.
    //               Let's ignore those leaks.
    int leak_chk_status = g_cute_leak_check;
    macgonuts_socket_t rsk = macgonuts_create_socket(DEFAULT_TEST_IFACE, 0);
    ssize_t sz = 0;
    int version = 4;
    pthread_t p0, p1;
    char buf[1024] = { 0 };
    struct rcvctx rcvctx = { 0 };
    g_cute_leak_check = 0;
    CUTE_ASSERT(rsk > -1);
    rcvctx.s = &rsk;
    rcvctx.sz = &sz;
    pthread_create(&p1, NULL, ping_pkt, &version);
    pthread_create(&p0, NULL, get_pkt, &rcvctx);
    pthread_join(p0, NULL);
    pthread_join(p1, NULL);
    CUTE_ASSERT(sz > 0);
    macgonuts_release_socket(rsk);
    g_cute_leak_check = leak_chk_status;
CUTE_TEST_CASE_END

CUTE_TEST_CASE(macgonuts_get_addr_from_iface_tests)
    char addr[50] = "";
    char expected_addr[256] = "";
#if defined(__linux__)
    char *iface = "eth0";
#else
# error Some code wanted.
#endif
    mock_set_expected_ip_version(4);
    CUTE_ASSERT(get_iface_addr4(expected_addr, sizeof(expected_addr), iface) == EXIT_SUCCESS);
    mock_set_expected_ip4_addr(expected_addr);
    /*CUTE_ASSERT(macgonuts_get_addr_from_iface(NULL, sizeof(addr), 4, iface) == EINVAL);
    CUTE_ASSERT(macgonuts_get_addr_from_iface(addr, 0, 4, iface) == EINVAL);
    CUTE_ASSERT(macgonuts_get_addr_from_iface(addr, sizeof(addr), 0, iface) == EINVAL);
    CUTE_ASSERT(macgonuts_get_addr_from_iface(addr, sizeof(addr), 4, NULL) == EINVAL);*/
    CUTE_ASSERT(macgonuts_get_addr_from_iface(addr, sizeof(addr), 4, iface) == EXIT_SUCCESS);
    CUTE_ASSERT(strcmp(addr, expected_addr) == 0);
    mock_set_expected_ip_version(6);
    CUTE_ASSERT(get_iface_addr6(expected_addr, sizeof(expected_addr), iface) == EXIT_SUCCESS);
    mock_set_expected_ip6_addr(expected_addr);
    CUTE_ASSERT(macgonuts_get_addr_from_iface(addr, sizeof(addr), 6, iface) == EXIT_SUCCESS);
    CUTE_ASSERT(strcmp(addr, expected_addr) == 0);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(macgonuts_get_mac_from_iface_tests)
    char mac[20] = "";
    char expected_mac[20] = "";
#if defined(__linux__)
    char *iface = "eth0";
#else
# error Some code wanted.
#endif
    CUTE_ASSERT(get_iface_mac(expected_mac, sizeof(expected_mac), iface) == EXIT_SUCCESS);
    CUTE_ASSERT(macgonuts_get_mac_from_iface(mac, sizeof(mac), iface) == EXIT_SUCCESS);
    CUTE_ASSERT(strcmp(mac, expected_mac) == 0);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(macgonuts_set_iface_promisc_on_off_tests)
#if defined(__linux__)
    char *iface = "eth0";
#else
# error Some code wanted.
#endif
    CUTE_ASSERT(macgonuts_set_iface_promisc_on(NULL) == EINVAL);
    CUTE_ASSERT(macgonuts_set_iface_promisc_on(iface) == EXIT_SUCCESS);
    CUTE_ASSERT(check_promisc_mode_on(iface) == 1);
    CUTE_ASSERT(macgonuts_set_iface_promisc_off(NULL) == EINVAL);
    CUTE_ASSERT(macgonuts_set_iface_promisc_off(iface) == EXIT_SUCCESS);
    CUTE_ASSERT(check_promisc_mode_off(iface) == 1);
CUTE_TEST_CASE_END

static void *get_pkt(void *args) {
    char buf[1<<10] = "";
    struct rcvctx *p = (struct rcvctx *)args;
    mock_set_expected_ip_version(4);
    mock_set_recv_buf((unsigned char *)buf, sizeof(buf));
    *p->sz = macgonuts_recvpkt(*p->s, buf, sizeof(buf));
    return NULL;
}

static void *ping_pkt(void *args) {
    int *version = (int *)args;
    system((*version == 4) ? "ping 127.0.0.1 -c 1" : (*version == 6) ? "ping6 ::1 -c 1" : "echo unknown ip version.");
    return NULL;
}

static int get_iface_addr4(char *addr, const size_t max_addr_size, const char *iface) {
    FILE *proc = NULL;
    char cmdline[1<<10];
    snprintf(cmdline, sizeof(cmdline) - 1,
             "ifconfig %s | grep \"inet.\\+[0-9]\\+\\.[0-9]\\+\\.[0-9]\\+\\.[0-9]\\+\" "
             "| sed 's/.*inet//;s/netmask.*$//;s/^[ \\t]\\+//;s/[ \\t\\n]\\+$//' | tr -d '\n'", iface);
    proc = popen(cmdline, "r");
    if (proc == NULL) {
        return EFAULT;
    }
    fread(addr, 1, max_addr_size, proc);
    pclose(proc);
    return EXIT_SUCCESS;
}

static int get_iface_addr6(char *addr, const size_t max_addr_size, const char *iface) {
    FILE *proc = NULL;
    char cmdline[1<<10];
    snprintf(cmdline, sizeof(cmdline) - 1,
             "ifconfig %s | grep \"inet.\\+[0-9,a-f]:\\+\""
             "| sed 's/.*inet6//;s/prefixlen.*$//;s/^[ \\t]\\+//;s/[ \\t\\n]\\+$//' | tr -d '\n'", iface);
    proc = popen(cmdline, "r");
    if (proc == NULL) {
        return EFAULT;
    }
    fread(addr, 1, max_addr_size, proc);
    pclose(proc);
    return EXIT_SUCCESS;
}

static int get_iface_mac(char *mac, const size_t max_mac_size, const char *iface) {
    FILE *proc = NULL;
    char cmdline[1<<10];
    snprintf(cmdline, sizeof(cmdline) - 1,
             "ifconfig %s | grep \"ether.\\+\" | sed 's/.*ether.//;s/ \\+.*$//' | tr -d '\n'", iface);
    proc = popen(cmdline, "r");
    if (proc == NULL) {
        return EFAULT;
    }
    fread(mac, 1, max_mac_size, proc);
    pclose(proc);
    return EXIT_SUCCESS;
}

static int check_promisc_mode_on(const char *iface) {
    char cmdline[1<<10];
    snprintf(cmdline, sizeof(cmdline) - 1,
             "ifconfig %s | grep PROMISC >/dev/null 2>&1", iface);
    return (system(cmdline) == 0);
}

static int check_promisc_mode_off(const char *iface) {
    char cmdline[1<<10];
    snprintf(cmdline, sizeof(cmdline) - 1,
             "ifconfig %s | grep PROMISC >/dev/null 2>&1", iface);
    return (system(cmdline) != 0);
}


#if defined(DEFAULT_TEST_IFACE)
# undef DEFAULT_TEST_IFACE
#endif // defined(DEFAULT_TEST_IFACE)
