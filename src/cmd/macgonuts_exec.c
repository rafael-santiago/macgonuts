/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <cmd/macgonuts_exec.h>
#include <cmd/macgonuts_option.h>
#include <cmd/macgonuts_spoof_task.h>
#include <cmd/macgonuts_eavesdrop_task.h>
#include <cmd/macgonuts_isolate_task.h>
#include <cmd/macgonuts_mayhem_task.h>
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
    if (task == NULL) {
        macgonuts_si_error("no task informed.\n");
        return EXIT_FAILURE;
    }
    do {
        if (strcmp(tp->name, task) == 0) {
            task_subprogram = tp->task;
        }
        tp++;
    } while (tp != tp_end && task_subprogram == macgonuts_unknown_task);
    if (task_subprogram != macgonuts_unknown_task && task_subprogram != macgonuts_help_task) {
        macgonuts_print_random_banner();
    }
    return task_subprogram();
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
        macgonuts_si_error("no help topic provided, try %s\n", avail_tasks);
        return EXIT_FAILURE;
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
