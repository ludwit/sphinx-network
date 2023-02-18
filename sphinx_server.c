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

#include <stdio.h>

#include "thread.h"
#include "net/sock/udp.h"

#include "shpinx.h"

char sphinx_server_stack[THREAD_STACKSIZE_MAIN];

void *sphinx_server(void *arg)
{
    (void)arg;

    sock_udp_t sock;
    ssize_t res;
    char rcv_buf[SPHINX_MESSAGE_SIZE];

    sock_udp_ep_t local = SOCK_IPV6_EP_ANY;
    local.port = SPHINX_PORT;

    ipv6_addr_t local_addr;

    struct network_node *node_self;

    if (sock_udp_create(&sock, &local, NULL, 0) < 0) {
        puts("error: creating udp sock");
        return NULL;
    }
    
    get_local_ipv6_addr(&local_addr);

    /* get node information */
    if ((node_self = pki_get_node(&local_addr)) == NULL) {
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
        res = sock_udp_recv(&sock, rcv_buf, sizeof(rcv_buf), SOCK_NO_TIMEOUT, NULL);

        if (res < 0) {
            printf("server: error %d receiving message\n", res);
            memset(rcv_buf, 0, sizeof(rcv_buf));
            continue;
        }

        // showcase
        puts("server: message received");
        print_hex_memory(rcv_buf, res);

        if (sphinx_process_message(rcv_buf, res, node_self) < 0) {
            puts("server: could not process sphinx message");
        }

        /* clear buffer for next iteration */
        memset(rcv_buf, 0, sizeof(rcv_buf));
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