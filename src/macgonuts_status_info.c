/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <macgonuts_status_info.h>
#include <macgonuts_thread.h>
#include <accacia.h>

static macgonuts_mutex_t g_StatusInfoGiantLock = MACGONUTS_DEFAULT_MUTEX_INITIALIZER;

static macgonuts_si_outmode_t g_StatusInfoOutType = kMacgonutsSiSys | kMacgonutsSiColored;

static char g_StatusInfoBuffer[64<<10] = "";

static char *g_StatusInfoBufferHead = &g_StatusInfoBuffer[0];

static void sync_si_print(const char *info_label, const char *message, va_list args);

#define SI_IMPL_TEMPLATE(label_info) {\
    va_list args;\
    if (macgonuts_mutex_lock(&g_StatusInfoGiantLock) != EXIT_SUCCESS) {\
        return;\
    }\
    va_start(args, message);\
    sync_si_print(label_info, message, args);\
    va_end(args);\
    macgonuts_mutex_unlock(&g_StatusInfoGiantLock);\
}

void macgonuts_si_error(const char *message, ...) {
    SI_IMPL_TEMPLATE("error: ");
}

void macgonuts_si_info(const char *message, ...) {
    SI_IMPL_TEMPLATE("info: ");
}

void macgonuts_si_warn(const char *message, ...) {
    SI_IMPL_TEMPLATE("warn: ");
}

void macgonuts_si_print(const char *message, ...) {
    SI_IMPL_TEMPLATE(NULL);
}

void macgonuts_si_mode_enter_announce(const char *mode_name) {
    if ((g_StatusInfoOutType & (kMacgonutsSiBuf | kMacgonutsSiMonochrome))) {
        macgonuts_si_print("--- m a c g o n u t s  %s mode is on\n---\n", mode_name);
        return;
    }
    fprintf(stdout, "--- m a c g o n u t s  ");
    accacia_textstyle(AC_TSTYLE_BOLD);
    accacia_textcolor(AC_TCOLOR_BLUE);
    fprintf(stdout, "%s", mode_name);
    accacia_textstyle(AC_TSTYLE_DEFAULT);
    accacia_textcolor(AC_TCOLOR_WHITE);
    fprintf(stdout, " is now ");
    accacia_textstyle(AC_TSTYLE_BOLD);
    accacia_textcolor(AC_TCOLOR_GREEN);
    fprintf(stdout, "on");
    accacia_textstyle(AC_TSTYLE_DEFAULT);
    accacia_textcolor(AC_TCOLOR_WHITE);
    fprintf(stdout, "\n---\n");
    accacia_screennormalize();
}

void macgonuts_si_mode_leave_announce(const char *mode_name) {
    if ((g_StatusInfoOutType & (kMacgonutsSiBuf | kMacgonutsSiMonochrome))) {
        macgonuts_si_print("--- m a c g o n u t s  %s mode is off\n---\n", mode_name);
        return;
    }
    fprintf(stdout, "--- m a c g o n u t s  ");
    accacia_textstyle(AC_TSTYLE_BOLD);
    accacia_textcolor(AC_TCOLOR_BLUE);
    fprintf(stdout, "%s", mode_name);
    accacia_textstyle(AC_TSTYLE_DEFAULT);
    accacia_textcolor(AC_TCOLOR_WHITE);
    fprintf(stdout, " is now ");
    accacia_textcolor(AC_TCOLOR_RED);
    fprintf(stdout, "off");
    accacia_textstyle(AC_TSTYLE_DEFAULT);
    accacia_textcolor(AC_TCOLOR_WHITE);
    fprintf(stdout, "\n---\n");
    accacia_screennormalize();
}

int macgonuts_si_get_last_info(char *si_buf, const size_t max_si_buf) {
    if (si_buf == NULL || max_si_buf == 0) {
        return ERANGE;
    }
    if (macgonuts_mutex_trylock(&g_StatusInfoGiantLock) != EXIT_SUCCESS) {
        return EBUSY;
    }
    snprintf(si_buf, max_si_buf, "%s", g_StatusInfoBuffer);
    g_StatusInfoBufferHead = &g_StatusInfoBuffer[0];
    macgonuts_mutex_unlock(&g_StatusInfoGiantLock);
    return EXIT_SUCCESS;
}

void macgonuts_si_set_outmode(const macgonuts_si_outmode_t otype) {
    if (macgonuts_mutex_lock(&g_StatusInfoGiantLock) != EXIT_SUCCESS) {
        return;
    }
    g_StatusInfoOutType = otype;
    macgonuts_mutex_unlock(&g_StatusInfoGiantLock);
}

static void sync_si_print(const char *info_label, const char *message, va_list args) {
    char *out_buf = NULL;
    size_t out_buf_size = 0;
    size_t info_label_size = (info_label == NULL) ? 0 : strlen(info_label);
    FILE *stdfp = stdout;
    ACCACIA_TEXT_COLOR tcolor = AC_TCOLOR_WHITE;
    ACCACIA_TEXT_STYLE tstyle = AC_TSTYLE_DEFAULT;
    int written_bytes_nr = 0;

    if (message == NULL) {
        return;
    }
    if (g_StatusInfoOutType & kMacgonutsSiBuf) {
        out_buf = g_StatusInfoBufferHead + info_label_size;
        out_buf_size = sizeof(g_StatusInfoBuffer) - (out_buf - &g_StatusInfoBuffer[0]);
    } else {
        out_buf_size = strlen(message) * 65535;
        out_buf = (char *)malloc(out_buf_size);
        if (out_buf == NULL) {
            return;
        }
    }

    written_bytes_nr = vsnprintf(out_buf, out_buf_size, message, args);

    if (!(g_StatusInfoOutType & kMacgonutsSiBuf)) {
        if (g_StatusInfoOutType & kMacgonutsSiMonochrome) {
            if (strcmp(info_label, "error: ") == 0) {
                stdfp = stderr;
            }
            assert(stdfp != NULL);
            fprintf(stdfp, "%s%s", (((info_label) != NULL) ? info_label : ""), out_buf);
        } else if (g_StatusInfoOutType & kMacgonutsSiColored) {
            if (info_label != NULL) {
                tstyle = AC_TSTYLE_BOLD;
                if (strcmp(info_label, "info: ") == 0) {
                    tcolor = AC_TCOLOR_GREEN;
                } else if (strcmp(info_label, "error: ") == 0) {
                    tcolor = AC_TCOLOR_RED;
                } else if (strcmp(info_label, "warn: ") == 0) {
                    tcolor = AC_TCOLOR_YELLOW;
                }
                accacia_textstyle(tstyle); accacia_textcolor(tcolor); fprintf(stdfp, "%s", info_label);
                accacia_screennormalize();
            }
            fprintf(stdfp, "%s", out_buf);
        }
    } else {
        if (written_bytes_nr > -1) {
            memcpy(&out_buf[-info_label_size], info_label, info_label_size);
            g_StatusInfoBufferHead += written_bytes_nr + info_label_size;
        }
    }

    if (out_buf != NULL && !(g_StatusInfoOutType & kMacgonutsSiBuf)) {
        free(out_buf);
    }
}

#undef SI_IMPL_TEMPLATE
