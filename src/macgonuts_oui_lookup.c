/*
 * Copyright (c) 2023, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <macgonuts_oui_lookup.h>
#include <macgonuts_status_info.h>

int macgonuts_oui_lookup(char *vendor_ident,
                         const size_t max_vendor_ident_size,
                         uint8_t *hw_addr,
                         const size_t hw_addr_size,
                         const char *oui_dbpath) {
    int err = EXIT_FAILURE;
    char *dataset = NULL;
    char *dataset_head = NULL;
    char *dataset_neck = NULL;
    char *dataset_tail = NULL;
    int db = -1;
    struct stat st = { 0 };
    ssize_t bytes_total = -1;
    char wanted_oui[10] = "";

    if (vendor_ident == NULL
        || max_vendor_ident_size == 0
        || hw_addr == NULL
        || hw_addr_size < 3
        || oui_dbpath == NULL) {
        return EINVAL;
    }

    memset(vendor_ident, 0, max_vendor_ident_size);

    if (stat(oui_dbpath, &st) != EXIT_SUCCESS) {
        macgonuts_si_error("unable to open oui database at `%s`.\n", oui_dbpath);
        err = EFAULT;
        goto macgonuts_oui_lookup_epilogue;
    }

    dataset = (char *)malloc(st.st_size + 1);
    if (dataset == NULL) {
        macgonuts_si_error("unable to allocate memory for oui dataset loading.\n");
        err = ENOMEM;
        goto macgonuts_oui_lookup_epilogue;
    }

    db = open(oui_dbpath, O_RDONLY);
    if (db == -1) {
        macgonuts_si_error("unable to open oui database.\n");
        err = EFAULT;
        goto macgonuts_oui_lookup_epilogue;
    }

    bytes_total = read(db, dataset, st.st_size);
    if (bytes_total != st.st_size) {
        macgonuts_si_error("unable to load oui database.\n");
        err = EFAULT;
        goto macgonuts_oui_lookup_epilogue;
    }

    close(db);
    db = -1;

    dataset_tail = dataset + bytes_total;

    if (snprintf(wanted_oui, sizeof(wanted_oui) - 1,
                 "%.2X%.2X%.2X", hw_addr[0], hw_addr[1], hw_addr[2]) != 6) {
        macgonuts_si_error("unable to format wanted oui.\n");
        err = EFAULT;
        goto macgonuts_oui_lookup_epilogue;
    }

    dataset_head = strstr(dataset, wanted_oui);
    if (dataset_head == NULL) {
        err = ENOENT;
        goto macgonuts_oui_lookup_epilogue;
    }

    if ((dataset_head + 6) >= dataset_tail) {
        macgonuts_si_error("unexpected end of data, oui database seems corrupted.\n");
        err = EFAULT;
        goto macgonuts_oui_lookup_epilogue;
    }

    dataset_head += 6;

    while (dataset_head != dataset_tail
           && isblank(*dataset_head)) {
        dataset_head++;
    }

    if (dataset_head == dataset_tail) {
        macgonuts_si_error("unexpected end of data, oui database seems corrupted.\n");
        err = EFAULT;
        goto macgonuts_oui_lookup_epilogue;
    }

    dataset_neck = dataset_head;
    while (dataset_neck != dataset_tail
           && *dataset_neck != '\n'
           && *dataset_neck != '\r') {
        dataset_neck++;
    }

    if (dataset_neck == dataset_tail) {
        macgonuts_si_error("unexpected end of data, oui database seems corrupted.\n");
        err = EFAULT;
        goto macgonuts_oui_lookup_epilogue;
    }


    if (max_vendor_ident_size < (dataset_neck - dataset_head)) {
        macgonuts_si_error("not enough buf size to copy vendor identity.\n");
        err = ENOBUFS;
        goto macgonuts_oui_lookup_epilogue;
    }

    memcpy(vendor_ident, dataset_head, dataset_neck - dataset_head);
    err = EXIT_SUCCESS;

macgonuts_oui_lookup_epilogue:

    if (dataset != NULL) {
        free(dataset);
    }

    if (db != -1) {
        close(db);
    }

    return err;
}

