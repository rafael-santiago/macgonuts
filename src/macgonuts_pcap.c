/*
 * Copyright (c) 2022, Rafael Santiago
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#include <macgonuts_pcap.h>
#include <macgonuts_status_info.h>

#define MACGONUTS_PCAP_MAGIC_NUMBER_TMS_INSECS 0xA1B2C3D4

#define MACGONUTS_PCAP_MAJOR_VERSION    2

#define MACGONUTS_PCAP_MINOR_VERSION    4

struct macgonuts_pcap_header_ctx {
    uint32_t magic_number;
    uint16_t major_version;
    uint16_t minor_version;
    uint32_t reserved[2];
    uint32_t snaplen;
    uint32_t fcs_linktype;
};

struct macgonuts_pcap_pktrec_ctx {
    uint32_t tmstamp_sec;
    uint32_t tmstamp_un_secs;
    uint32_t captured_pkt_len;
    uint32_t original_pkt_len;
    uint8_t *captured_pkt;
};

static void macgonuts_init_pcaphdr(struct macgonuts_pcap_header_ctx *pcaphdr);

static void macgonuts_init_pcaprec(struct macgonuts_pcap_pktrec_ctx *pcaprec,
                                   const unsigned char *ethfrm, const size_t ethfrm_size);

static int macgonuts_write_pcaprec(FILE *pcapfile, const struct macgonuts_pcap_pktrec_ctx *pcaprec);

static int macgonuts_is_pcapfile(const char *filepath);

FILE *macgonuts_pcapfile_open(const char *filepath) {
    struct stat st = { 0 };
    FILE *pcapfile = NULL;
    int should_init = 0;
    struct macgonuts_pcap_header_ctx pcaphdr = { 0 };
    if (stat(filepath, &st) != 0) {
        pcapfile = fopen(filepath, "wb");
        should_init = 1;
    } else if (macgonuts_is_pcapfile(filepath)) {
        pcapfile = fopen(filepath, "ab");
    } else {
        macgonuts_si_error("the existent file `%s` does not seem to be a valid pcap.\n", filepath);
        return NULL;
    }

    if (pcapfile == NULL) {
        macgonuts_si_error("unable to open `%s` as a pcap file.\n", filepath);
        return NULL;
    }

    if (should_init) {
        macgonuts_init_pcaphdr(&pcaphdr);
        fwrite(&pcaphdr, sizeof(pcaphdr), 1, pcapfile);
    }

    return pcapfile;
}

int macgonuts_pcapfile_write(FILE *pcapfile, const unsigned char *ethfrm, const size_t ethfrm_size) {
    struct macgonuts_pcap_pktrec_ctx pcaprec = { 0 };
    macgonuts_init_pcaprec(&pcaprec, ethfrm, ethfrm_size);
    return macgonuts_write_pcaprec(pcapfile, &pcaprec);
}

void macgonuts_pcapfile_close(FILE *pcapfile) {
    if (pcapfile != NULL) {
        fclose(pcapfile);
    }
}

static void macgonuts_init_pcaphdr(struct macgonuts_pcap_header_ctx *pcaphdr) {
    if (pcaphdr == NULL) {
        return;
    }
    pcaphdr->magic_number = MACGONUTS_PCAP_MAGIC_NUMBER_TMS_INSECS;
    pcaphdr->major_version = MACGONUTS_PCAP_MAJOR_VERSION;
    pcaphdr->minor_version = MACGONUTS_PCAP_MINOR_VERSION;
    pcaphdr->reserved[0] = pcaphdr->reserved[1] = 0L;
    pcaphdr->snaplen = 0xFFFF;
    pcaphdr->fcs_linktype = 1; // INFO(Rafael): LINKTYPE_ETHERNET.
}

static int macgonuts_write_pcaprec(FILE *pcapfile, const struct macgonuts_pcap_pktrec_ctx *pcaprec) {
    size_t written = fwrite(&pcaprec->tmstamp_sec, sizeof(pcaprec->tmstamp_sec), 1, pcapfile);
    if (written != 1) {
        return EXIT_FAILURE;
    }
    written = fwrite(&pcaprec->tmstamp_un_secs, sizeof(pcaprec->tmstamp_un_secs), 1, pcapfile);
    if (written != 1) {
        return EXIT_FAILURE;
    }
    written = fwrite(&pcaprec->captured_pkt_len, sizeof(pcaprec->captured_pkt_len), 1, pcapfile);
    if (written != 1) {
        return EXIT_FAILURE;
    }
    written = fwrite(&pcaprec->original_pkt_len, sizeof(pcaprec->original_pkt_len), 1, pcapfile);
    if (written != 1) {
        return EXIT_FAILURE;
    }
    written = fwrite(&pcaprec->captured_pkt[0], pcaprec->captured_pkt_len, 1, pcapfile);
    return ((written == 1) ? EXIT_SUCCESS : EXIT_FAILURE);
}

static void macgonuts_init_pcaprec(struct macgonuts_pcap_pktrec_ctx *pcaprec,
                                   const unsigned char *ethfrm, const size_t ethfrm_size) {
    if (pcaprec == NULL) {
        return;
    }
    pcaprec->tmstamp_sec = (uint32_t)time(NULL);
    pcaprec->tmstamp_un_secs = 0;
    pcaprec->captured_pkt_len = (uint32_t)ethfrm_size;
    pcaprec->original_pkt_len = (uint32_t)ethfrm_size;
    pcaprec->captured_pkt = (uint8_t *)ethfrm;
}

static int macgonuts_is_pcapfile(const char *filepath) {
    FILE *pcapfile = NULL;
    uint32_t magic = 0;
    if (filepath == NULL) {
        return 0;
    }
    pcapfile = fopen(filepath, "rb");
    if (pcapfile == NULL) {
        return 0;
    }
    fread(&magic, sizeof(magic), 1, pcapfile);
    fclose(pcapfile);
    return (magic == MACGONUTS_PCAP_MAGIC_NUMBER_TMS_INSECS);
}

#undef MACGONUTS_PCAP_MAJOR_VERSION
#undef MACGONUTS_PCAP_MINOR_VERSION
