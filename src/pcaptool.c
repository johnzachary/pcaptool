/* -*- coding: utf-8 -*-
 *
 * NAME
 *  pcaptool - process libpcap files using callback functions
 *
 * DESCRIPTION
 *  pcaptool is a simple C program that uses callback functions to process
 *  libpcap files (e.g., .pcap, .dmp). It is intended to provide a simple
 *  extensible framework for any kind of processing functions.
 *
 *  The tool extensively uses the libcork and clogger libraries.
 *
 * Copyright 2012. All rights reservered.
 */


#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <clogger.h>
#include <libcork/cli.h>
#include <libcork/core.h>
#include <libcork/ds.h>
#include <libcork/helpers/errors.h>

#include "pcaptool.h"

#define CLOG_CHANNEL  "pcaptool"
#define CLOG_TRACE  1


/* ----------------------------------------------------------------------
 * Program state and macros
 */

/* cork-hash of "pcaptool_error" */
#define PCAPTOOL_ERROR  0x90c36cbc

enum pcaptool_errors {
    PCAPTOOL_ERROR__FILE_IO_ERROR,
    PCAPTOOL_ERROR__DUPLICATE_TYPE,
    PCAPTOOL_ERROR__UNKNOWN_TYPE,
    PCAPTOOL_ERROR__MALFORMED_PACKET,
    PCAPTOOL_ERROR__UNKNOWN_ERROR
};

static bool  g_read_file_list = false;
static const char*  g_file_list = NULL;
static bool  g_process_packets = false;


/* ----------------------------------------------------------------------
 * Pcaptool data types
 */

struct packet_callbacks {
    int  (*pcap_callback)(struct pcap_packet *p);
    int  (*ethernet_callback)(struct ethernet_packet *p);
    int  (*ipv4_callback)(struct ipv4_packet *p);
    int  (*ipv6_callback)(struct ipv6_packet *p);
    int  (*tcp_callback)(struct tcp_packet *p);
    int  (*udp_callback)(struct udp_packet *p);
    int  (*icmp_callback)(struct icmp_packet *p);
    int  (*data_callback)(struct data_packet *p);
};

struct packet_stats {
    size_t  num_packets;
    struct packet_callbacks  handlers;
};


/* ----------------------------------------------------------------------
 * Platform specifics
 */

#if defined (__linux)

/* Reset glibc getop by setting optind to 1 */
static void
reset_getopt(void)
{
    optind = 1;
}

#elif defined (__APPLE__) && defined (__MACH__)

/* Reset BSD getopt by setting optreset and optind to 1 */
static void
reset_getopt(void)
{
    optreset = 1;
    optind = 1;
}

#else
#error "Error: This platform is unrecognized."
#endif  /* Platform specifics */


/* ----------------------------------------------------------------------
 * PCAP processing functions
 */

static bool
is_string_whitespace(const char *str)
{
    while (*str) {
        if (isspace(*str) == 0) {
            return false;
        }
        str++;
    }
    return true;
}

static int
read_pcap_file(char *file_name, struct packet_stats *ps)
{
    int  rc;
    pcap_t  *pcap;
    struct pcap_pkthdr  *header;
    char  pcap_error[PCAP_ERRBUF_SIZE];
    const  unsigned char  *packet_buf = NULL;

    pcap = pcap_open_offline(file_name, pcap_error);
    if (pcap == NULL) {
        cork_error_set(PCAPTOOL_ERROR, PCAPTOOL_ERROR__FILE_IO_ERROR,
                       "\nFile IO: %s", pcap_error);
        return -1;
    }

    ps->num_packets = 0;
    while ((rc = pcap_next_ex(pcap, &header, &packet_buf)) == 1) {
        ps->num_packets++;

        /* TODO (johnzachary2@gmail.com): Need to implement a loop or
         * a chain of function calls for callbacks here to support
         * simple processing pcap files.
         */
    }
    if (rc == -1) {
        cork_error_set(PCAPTOOL_ERROR, PCAPTOOL_ERROR__MALFORMED_PACKET,
                       "\nMalformed packet: %s", pcap_geterr(pcap));
        return -1;
    }
    pcap_close(pcap);
    return 0;
}

#define MAX_LINE_LENGTH  256
static int
read_file_list(const char *file_list_name)
{
    int  rc;
    FILE  *stream;
    char  line[MAX_LINE_LENGTH];
    struct packet_stats  ps;

    stream = fopen(file_list_name, "r");
    if (stream == NULL) {
        cork_error_set(PCAPTOOL_ERROR, PCAPTOOL_ERROR__FILE_IO_ERROR,
                       "\nFile IO: Error opening %s", file_list_name);
        return -1;
    }
    while (fgets(line, MAX_LINE_LENGTH, stream) != NULL) {
        /* Skip empty lines and commented lines started with '#'
         * in the first column.
         */
        if ((line[0] == '#') || is_string_whitespace(line)) {
            continue;
        }
        size_t  len = strlen(line);
        line[len-1] = '\0';
        fprintf(stdout, "'%s'", line);
        rc = read_pcap_file(line, &ps);
        if (rc != 0) {
            fprintf(stdout, ": cannot process file.\n");
        } else {
            fprintf(stdout, " %zu\n", ps.num_packets);
        }
        fflush(stdout);
    }
    return 0;
}


/* ----------------------------------------------------------------------
 * pcaptool count command
 */

#define COUNT_SHORT_DESC  "Count packets in file(s)"

#define COUNT_USAGE_SUFFIX  "[<PCAP file>]"

#define COUNT_HELP_TEXT \
"Reads a PCAP file and prints the number of packets in the file.\n" \
"\n" \
"Options:\n" \
"  --file-list\n"\

static int
count_command_options(int argc, char **argv);

static void
count_command(int argc, char **argv);

static struct cork_command  count =
    cork_leaf_command("count",
                      COUNT_SHORT_DESC,
                      COUNT_USAGE_SUFFIX,
                      COUNT_HELP_TEXT,
                      count_command_options, count_command);

static struct option  count_opts[] = {
    {"file-list", required_argument, NULL, 'f'},
    {NULL, 0, NULL, 0}
};

static int
count_command_options(int argc, char **argv)
{
    int  ch;
    reset_getopt();
    while ((ch = getopt_long(argc, argv, "f:", count_opts, NULL)) != -1) {
        switch (ch) {
            case 'f':
                g_read_file_list = true;
                g_file_list = cork_strdup(optarg);
                break;
            default:
                cork_command_show_help(&count, NULL);
                exit(EXIT_FAILURE);
        }
    }
    return optind;
}

static void
count_command(int argc, char **argv)
{
    if (g_read_file_list) {
        read_file_list(g_file_list);
        cork_strfree(g_file_list);
    } else {
        if (argc < 1) {
            cork_command_show_help(&count, "Please provide a pcap filename.");
            exit(EXIT_FAILURE);
        } else if (argc > 1) {
            cork_command_show_help
                (&count, "Please use the '--file-list' option.");
            exit(EXIT_FAILURE);
        }
        struct packet_stats  ps;
        read_pcap_file(argv[0], &ps);
        if (cork_error_occurred()) {
            fprintf(stderr, "%s\n", cork_error_message());
            exit(EXIT_FAILURE);
        }
        fprintf(stdout, "%zu\n", ps.num_packets);
    }
    return;
}


/* ----------------------------------------------------------------------
 * pcaptool process command
 */

#define PROCESS_SHORT_DESC  "Process packets in file(s)"

#define PROCESS_USAGE_SUFFIX  "[<PCAP file>]"

#define PROCESS_HELP_TEXT \
"Reads a PCAP file and processes each packet in the file.\n" \
"\n" \
"Options:\n" \
"  --file-list\n"\

static int
process_command_options(int argc, char **argv);

static void
process_command(int argc, char **argv);

static struct cork_command  process =
    cork_leaf_command("process", PROCESS_SHORT_DESC, PROCESS_USAGE_SUFFIX,
                      PROCESS_HELP_TEXT, process_command_options,
                      process_command);

static struct option  process_opts[] = {
    {"file-list", required_argument, NULL, 'f'},
    {NULL, 0, NULL, 0}
};

static int
process_command_options(int argc, char **argv)
{
    int  ch;
    reset_getopt();
    while ((ch = getopt_long(argc, argv, "+f:", process_opts, NULL)) != -1) {
        switch (ch) {
            case 'f':
                g_read_file_list = true;
                g_file_list = cork_strdup(optarg);
                break;
            default:
                cork_command_show_help(&process, NULL);
                exit(EXIT_FAILURE);
        }
    }
    return optind;
}

static void
process_command(int argc, char **argv)
{
    g_process_packets = true;
    if (g_read_file_list) {
        read_file_list(g_file_list);
        cork_strfree(g_file_list);
    } else {
        if (argc < 1) {
            cork_command_show_help(&count, "Please provide a pcap filename.");
            exit(EXIT_FAILURE);
        } else if (argc > 1) {
            cork_command_show_help
                (&count, "Please use the '--file-list' option.");
            exit(EXIT_FAILURE);
        }
        struct packet_stats  ps;
        fprintf(stdout, "Processing '%s': ", argv[0]);
        fflush(stdout);
        read_pcap_file(argv[0], &ps);
        if (cork_error_occurred()) {
            fprintf(stderr, "%s\n", cork_error_message());
            exit(EXIT_FAILURE);
        }
        fprintf(stdout, "\n%zu packets processed in \n", ps.num_packets);
    }
    return;
}


/* ----------------------------------------------------------------------
 * Root command set
 */

static struct cork_command  *root_subcommands[] = {
    &count,
    &process,
    NULL
};

static struct cork_command  root =
    cork_command_set("pcaptool", NULL, NULL, root_subcommands);


/* ----------------------------------------------------------------------
 * Main function
 */

int
main(int argc, char **argv)
{
    int  rc;
    rc = cork_command_main(&root, argc, argv);
    return rc;
}
