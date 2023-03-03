/*
 * Copyright (C) 2023 ludwit
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     examples
 * @{
 *
 * @file
 * @brief       implements networking capabilities for sphinx
 *
 * @author      ludwit <ludwit@protonmail.com>
 *
 * @}
 */

#include "shpinx.h"

/* parse user input */
int sphinx_cmd(int argc, char **argv)
{
    if (argc < 2) {
        printf("usage: %s [send|server]\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "send") == 0) {
        if (argc != 4) {
            printf("usage: %s send <addr> <data>\n", argv[0]);
            return 1;
        }

        /* parse destinaiton addr */
        ipv6_addr_t dest_addr;
        if (ipv6_addr_from_buf(&dest_addr, argv[2], strlen(argv[2])) == NULL) {
            puts("error: address malformed");
            return 1;
        }

        /* check data length */
        if (strlen(argv[3]) > PAYLOAD_SIZE) {
            printf("error: data input too big\nPAYLOAD_SIZE = %d", PAYLOAD_SIZE);
        }
        
        /* send sphinx message */
        if (sphinx_send(&dest_addr, argv[3], strlen(argv[3])) < 0) {
            puts("error: sending message failed");
        }
    }

    else if (strcmp(argv[1], "server") == 0) {
        if (argc != 3) {
            printf("usage: %s server [start|stop]\n", argv[0]);
            return 1;
        }
        if (strcmp(argv[2], "start") == 0) {
            /* start sphinx server */
            if (sphinx_server_start() < 0) {
                puts("error: can't start server");
            }
        }
        else if (strcmp(argv[2], "stop") == 0) {
            /* stop sphinx server */
            puts("sphinx server stoped");
            
        }
        else {
            printf("error: invalid command \"%s\"\n", argv[2]);
        }
    }

    else {
        printf("error: invalid command \"%s\"\n", argv[1]);
    }

    return 0;
}

SHELL_COMMAND(sphinx, "send data over UDP and listen on UDP ports", sphinx_cmd);