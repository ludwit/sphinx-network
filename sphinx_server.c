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

char sphinx_server_stack[THREAD_STACKSIZE_MAIN];

/* stores random bytes from stream cipher */
unsigned char prg_stream[PRG_STREAM_SIZE];

/* stores created and received sphinx messages */
unsigned char sphinx_message[SPHINX_MESSAGE_SIZE];

/* array to store seen message tags to prevent replay attacks */
unsigned char tag_table[TAG_TABLE_LEN][TAG_SIZE];
int tag_count = 0;

/* event queue for sphinx thread */
event_queue_t sphinx_queue;

/* ipv6 address of this node */
ipv6_addr_t local_addr;

void handle_socket(sock_udp_t *sock, sock_async_flags_t type, void *node_self)
{
    ssize_t res;

    if (type == SOCK_ASYNC_MSG_RECV) {

        res = sock_udp_recv(sock, sphinx_message, SPHINX_MESSAGE_SIZE, 0, NULL);

        if (res < 0) {
            printf("sphinx: error %d receiving data\n", res);
            return;
        }
        
        if (res != SPHINX_MESSAGE_SIZE) {
            puts("sphinx: received malformed data");
            return;
        }

        if (sphinx_process_message(sphinx_message, (struct network_node *) node_self, tag_table, &tag_count) < 0) {
            puts("sphinx: could not process sphinx message");
        }
    }
}

void *sphinx_server(void *arg)
{
    (void) arg;
    struct network_node *node_self;

    sock_udp_t sock;

    sock_udp_ep_t local = SOCK_IPV6_EP_ANY;
    local.port = SPHINX_PORT;

    get_local_ipv6_addr(&local_addr);

    /* get node information */
    if ((node_self = get_node(&local_addr)) == NULL) {
        puts("error: no entry in pki with this ipv6 address");
        print_hex_memory(&local_addr, sizeof(ipv6_addr_t));
        return NULL;
    }

    /* print ipv6 address */
    puts("sphinx: server running at address");
    print_hex_memory(&local_addr, sizeof(ipv6_addr_t));

    if (sock_udp_create(&sock, &local, NULL, 0) < 0) {
        puts("error: creating udp sock");
        return NULL;
    }

    event_queue_init(&sphinx_queue);
    sock_udp_event_init(&sock, &sphinx_queue, handle_socket, node_self);
    event_loop(&sphinx_queue);

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