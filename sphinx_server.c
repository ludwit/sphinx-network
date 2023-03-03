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


/* stores random bytes from stream cipher */
unsigned char prg_stream[PRG_STREAM_SIZE];

/* stores created and received sphinx messages */
unsigned char sphinx_message[SPHINX_MESSAGE_SIZE];

char sphinx_server_stack[THREAD_STACKSIZE_MAIN];

void *sphinx_server(void *arg)
{
    (void)arg;

    sock_udp_t sock;
    ssize_t res;

    sock_udp_ep_t local = SOCK_IPV6_EP_ANY;
    local.port = SPHINX_PORT;

    ipv6_addr_t local_addr;

    struct network_node *node_self;

    /* array to store seen message tags to prevent replay attacks */
    unsigned char tag_table[TAG_TABLE_LEN][TAG_SIZE];
    int tag_count = 0;

    if (sock_udp_create(&sock, &local, NULL, 0) < 0) {
        puts("error: creating udp sock");
        return NULL;
    }
    
    get_local_ipv6_addr(&local_addr);

    /* get node information */
    if ((node_self = get_node(&local_addr)) == NULL) {
        puts("error: no entry in pki with this ipv6 address");
        print_hex_memory(&local_addr, sizeof(ipv6_addr_t));
        puts("");
        return NULL;
    } 

    /* print ipv6 address */
    puts("sphinx server running at address");
    print_hex_memory(&local_addr, sizeof(ipv6_addr_t));
    puts("");


    while (1) {
        res = sock_udp_recv(&sock, sphinx_message, SPHINX_MESSAGE_SIZE, SOCK_NO_TIMEOUT, NULL);

        if (res < 0) {
            printf("server: error %d receiving message\n", res);
            continue;
        } else if (res != SPHINX_MESSAGE_SIZE) {
            puts("sphinx: received malformed message");
            continue;
        }

        if (sphinx_process_message(sphinx_message, node_self, tag_table, &tag_count) < 0) {
            puts("sphinx: could not process sphinx message");
        }
    }

    return NULL;
}

/* starts the sphinx server thread */
int sphinx_server_start(void)
{   
    if ((thread_create(sphinx_server_stack,
                       sizeof(sphinx_server_stack),
                       THREAD_PRIORITY_MAIN - 1,
                       THREAD_CREATE_STACKTEST,
                       sphinx_server,
                       NULL, "sphinx_server")) > SCHED_PRIO_LEVELS)
    {
        return -1;
    }

    return 1;
}