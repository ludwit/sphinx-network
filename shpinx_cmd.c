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

/* address of message destination */
ipv6_addr_t dest_addr;

/* parse user input */
int sphinx_cmd(int argc, char **argv)
{ 
    if (argc == 2) {
        if (strcmp(argv[1], "start") == 0) {
            if (sphinx_pid) {
                puts("sphinx: thread already running");
                return 1;
            }
            if (sphinx_start() < 0) {
                puts("sphinx: can't start server");
                return 1;
            }
            return 0;
        }
        if (strcmp(argv[1], "stop") == 0) {
            if (!sphinx_pid) {
                puts("sphinx: no thread running");
                return 1;
            }
            
            event_t sphinx_stop = { .handler = handle_stop };
            event_post(&sphinx_queue, &sphinx_stop);

            if (thread_kill_zombie(sphinx_pid) != 1) {
                puts("error: can't stop thread");
                return 1;
            }

            sphinx_pid = 0;
            puts("sphinx: thread stopped"); 
            return 0;
        }
    }
    
    if (argc == 4 && strcmp(argv[1], "send") == 0) {

        if (!sphinx_pid) {
            puts("error: sphinx not running\nusage: sphinx start");
            return 1;
        }

        if (sent_msg_count >=  SENT_MSG_TABLE_SIZE) {
            puts("error: can't send message, waiting for too many replies");
            return 1;
        }

        /* parse destinaiton addr */
        if (ipv6_addr_from_buf(&dest_addr, argv[2], strlen(argv[2])) == NULL) {
            puts("error: ipv6 address malformed");
            return 1;
        }

        /* check data length */
        if (strlen(argv[3]) > PAYLOAD_SIZE) {
            printf("error: data input too big\nPAYLOAD_SIZE = %d\n", PAYLOAD_SIZE);
            return 1;
        }

        /* create event for sendig a message and save it to local array */
        sent_msg_table[sent_msg_count] = (event_send) {.handler = handle_send,
                                                       .transmit_count = 0,
                                                       .data = argv[3],
                                                       .data_len = strlen(argv[3])};
        memcpy(&sent_msg_table[sent_msg_count].dest_addr, &dest_addr, ADDR_SIZE);
        
        sent_msg_count ++;
        event_post(&sphinx_queue, (event_t*) &sent_msg_table[sent_msg_count-1]);


        return 0;
    }

    puts("sphinx: invalid command");
    puts("usage: sphinx [start|stop]");
    puts("usage: sphinx send <addr> <data>");

    return 1;

}

SHELL_COMMAND(sphinx, "send and receive anonymous messages", sphinx_cmd);