/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <cmd/macgonuts_exec.h>
#if defined(__FreeBSD__)
# include <freebsd/macgonuts_bpf_fifo.h>
#endif // defined(__FreeBSD__)
#include <cmd/macgonuts_option.h>
#include <cmd/macgonuts_spoof_task.h>
#include <cmd/macgonuts_eavesdrop_task.h>
#include <cmd/macgonuts_isolate_task.h>
#include <cmd/macgonuts_mayhem_task.h>
#include <cmd/macgonuts_dnsspoof_task.h>
#include <cmd/macgonuts_xablau_task.h>
#include <cmd/macgonuts_version_task.h>
#include <cmd/macgonuts_banners.h>
#include <macgonuts_status_info.h>

typedef int (*macgonuts_task_func)(void);

static int macgonuts_unknown_task(void);

static int macgonuts_help_task(void);

static int macgonuts_help_task_help(void); // :S

static int macgonuts_no_help_topic(void);

#define MACGONUTS_CMD_REGISTER_TASK(t) { #t, macgonuts_## t ##_task, macgonuts_## t ##_task_help }

struct macgonuts_task_ctx {
    const char *name;
    macgonuts_task_func task;
    macgonuts_task_func help;
} g_MacgonutsCmdTasks[] = {
    MACGONUTS_CMD_REGISTER_TASK(spoof),
    MACGONUTS_CMD_REGISTER_TASK(eavesdrop),
    MACGONUTS_CMD_REGISTER_TASK(isolate),
    MACGONUTS_CMD_REGISTER_TASK(mayhem),
    MACGONUTS_CMD_REGISTER_TASK(dnsspoof),
    MACGONUTS_CMD_REGISTER_TASK(xablau),
    MACGONUTS_CMD_REGISTER_TASK(version),
    MACGONUTS_CMD_REGISTER_TASK(help),
};

#undef MACGONUTS_CMD_REGISTER_TASK

int macgonuts_exec(const int argc, const char **argv) {
    const char *task = NULL;
    macgonuts_task_func task_subprogram = macgonuts_unknown_task;
    struct macgonuts_task_ctx *tp = &g_MacgonutsCmdTasks[0], *tp_end = tp +
            sizeof(g_MacgonutsCmdTasks) / sizeof(g_MacgonutsCmdTasks[0]);
    macgonuts_set_argc_argv(argc, argv);
    task = macgonuts_get_raw_option(1);
#if defined(__FreeBSD__)
    int err = EXIT_FAILURE;
#endif // defined(__FreeBSD__)

    if (task == NULL) {
        macgonuts_si_error("no task informed.\n");
        return EXIT_FAILURE;
    }

    if (strcmp(task, "--version") == 0) {
        return macgonuts_version_task();
    }

    do {
        if (strcmp(tp->name, task) == 0) {
            task_subprogram = tp->task;
        }
        tp++;
    } while (tp != tp_end && task_subprogram == macgonuts_unknown_task);

    if (task_subprogram != macgonuts_unknown_task
        && task_subprogram != macgonuts_help_task
        && task_subprogram != macgonuts_version_task) {
        macgonuts_print_random_banner();
    }

#if defined(__FreeBSD__)
    err = macgonuts_bpf_fifo_init();
    if (err == EXIT_SUCCESS) {
        err = task_subprogram();
        macgonuts_bpf_fifo_deinit();
    }

    return err;
#else
    return task_subprogram();
#endif // defined(__FreeBSD__)
}

static int macgonuts_unknown_task(void) {
    macgonuts_si_error("'%s' is not a known task.\n", macgonuts_get_raw_option(1));
    return EXIT_FAILURE;
}

static int macgonuts_help_task(void) {
    const char *topic = macgonuts_get_raw_option(2);
    char avail_tasks[8<<10] = "";
    char *ap = NULL, *ap_end = NULL;
    size_t written = 0;
    const char *sep[2] = { ", ", "." };
    struct macgonuts_task_ctx *tp = &g_MacgonutsCmdTasks[0], *tp_end = tp +
        sizeof(g_MacgonutsCmdTasks) / sizeof(g_MacgonutsCmdTasks[0]);
    macgonuts_task_func help_subprogram = macgonuts_no_help_topic;
    if (topic == NULL) {
        ap = &avail_tasks[0];
        ap_end = ap + sizeof(avail_tasks);
        do {
            written = snprintf(ap, sizeof(avail_tasks) - written, "'%s'%s", tp->name, sep[(tp + 1) == tp_end]);
            ap += written;
            tp += 1;
        } while (ap < ap_end && tp != tp_end);
        macgonuts_si_warn("no help topic provided, try %s\n_________\n", avail_tasks);
        macgonuts_si_print("Macgonuts is Copyright (C) 2022-2023 by Rafael Santiago and licensed under BSD-4.\n"
                           "This is a free software. You can redistribute it and/or modify under the terms of "
                           "BSD-4 license.\n\n");
        macgonuts_si_print("Use this software at your own responsibility and risk. I am not responsible for any "
                           "misuse of it,\nincluding some kind of damage, data loss etc. Sniffing network, "
                           "eavesdropping people's communication\nwithout them knowing is wrong and a crime. Do "
                           "not be a jerk, respect people rights. Macgonuts is an\nARP/NDP swiss army knife with "
                           "batteries included but ethics you need to bring it from home!! ;)\n\n");
        macgonuts_si_print("Remember to be ethical when using it. Macgonuts is a tool designed to ethical hacking, "
                           "pentests and\nred teams. Once it stated, when using this tool you are assuming that any "
                           "damage, data loss or even\nlaw infringements that some wrong action taken by you could "
                           "cause is of your entire responsibility.\n\n");
        macgonuts_si_print("Bug reports, feedback etc: <https://github.com/rafael-santiago/macgonuts/issues>\n\n");
        return EXIT_SUCCESS;
    }
    do {
        if (strcmp(tp->name, topic) == 0) {
            help_subprogram = tp->help;
        }
        tp++;
    } while (tp != tp_end && help_subprogram == macgonuts_no_help_topic);
    return help_subprogram();
}

static int macgonuts_no_help_topic(void) {
    macgonuts_si_error("no help topic for '%s', btw this is not an available task.\n", macgonuts_get_raw_option(2));
    return EXIT_FAILURE;
}

static int macgonuts_help_task_help(void) {
    macgonuts_si_print("use: macgonuts help <task>\n");
    return EXIT_SUCCESS;
}
