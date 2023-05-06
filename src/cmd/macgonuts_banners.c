/*
 * Copyright (c) 2023, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <cmd/macgonuts_banners.h>
#include <cmd/macgonuts_version.h>
#include <macgonuts_types.h>
#include <accacia.h>

// INFO(Rafael): The '%s' formatter is for version info.

static char *g_MacgonutsBanners[] = {
    " _______                                      __\n"
    "|   |   |.---.-.----.-----.-----.-----.--.--.|  |_.-----.\n"
    "|       ||  _  |  __|  _  |  _  |     |  |  ||   _|__ --|\n"
    "|__|_|__||___._|____|___  |_____|__|__|_____||____|_____| %s\n"
    "                    |_____|\n",
};

static const struct gradients {
    int floor;
    int ceil;
} g_GradientRanges[] = {
    { 52, 58 }, { 88, 94 }, { 124, 130 }, { 160, 166 }, { 196, 202 },
    { 22, 28 }, { 58, 64 }, {  94, 100 }, { 130, 136 }, { 166, 172 }, { 202, 208 },
    { 28, 34 }, { 64, 70 }, { 100, 106 }, { 136, 142 }, { 172, 178 }, { 208, 214 },
    { 34, 40 }, { 70, 76 }, { 106, 112 }, { 142, 148 }, { 178, 184 }, { 214, 220 },
    { 40, 46 }, { 76, 82 }, { 112, 118 }, { 148, 154 }, { 184, 190 }, { 220, 226 },
    { 46, 52 }, { 82, 88 }, { 118, 124 }, { 154, 160 }, { 190, 196 },
    { 232, 244 },
};

void macgonuts_print_random_banner(void) {
    size_t b = 0;
    size_t g = 0;
    char banner_str[2][1<<10];
    char *bp = NULL;
    char *banner_end = NULL;
    size_t banner_str_size = 0;
    int color = 0;
    int urandom = open("/dev/urandom", O_RDONLY);
    if (urandom != -1) {
        read(urandom, &b, sizeof(b));
        g = b % sizeof(g_GradientRanges) / sizeof(g_GradientRanges[0]);
        b %= sizeof(g_MacgonutsBanners) / sizeof(g_MacgonutsBanners[0]);
        close(urandom);
    }
    color = g_GradientRanges[g].floor;
    banner_str_size = snprintf(banner_str[0], sizeof(banner_str[0]) - 1, "%s", g_MacgonutsBanners[b]);
    banner_str_size = snprintf(banner_str[1], sizeof(banner_str[1]) - 1, banner_str[0], MACGONUTS_CMD_VERSION);
    bp = &banner_str[1][0];
    banner_end = bp + banner_str_size;
    accacia_textstyle(AC_TSTYLE_BOLD);
    while (bp != banner_end) {
        fprintf(stdout, "\033[38;5;%dm%c\033[0m", color, *bp);
        if (*bp == '\n') {
            color = (color > g_GradientRanges[g].ceil) ? g_GradientRanges[g].floor : color + 1;
        }
        bp++;
    }
    fprintf(stdout, "\n");
    accacia_textcolor(AC_TCOLOR_BLACK);
    accacia_screennormalize();
}
