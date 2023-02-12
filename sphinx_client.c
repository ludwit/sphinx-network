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
#include <string.h>

#include "net/sock/udp.h"

#include "shpinx.h"

int udp_send(ipv6_addr_t* dest_addr, unsigned char *message, size_t message_size)
{
    /* set up remote endpoint */
    sock_udp_ep_t remote = { .family = AF_INET6 };
    remote.port = SPHINX_PORT;
    memcpy(remote.addr.ipv6, dest_addr, sizeof(ipv6_addr_t));

    /* send message */
    if (sock_udp_send(NULL, message, message_size, &remote) < 0) {
        puts("could not send message with udp");
        return -1;
    }

    return 1;
}

int sphinx_send(ipv6_addr_t* dest_addr, char *data, size_t data_len)
{
    unsigned char sphinx_message[SPHINX_MESSAGE_SIZE];

    /* create sphinx message */
    if (create_sphinx_message(sphinx_message, dest_addr, data, data_len) < 0) {
        puts("could not create sphinx message");
        return -1;
    }

    /* send sphinx message */
    if (udp_send(dest_addr, sphinx_message, SPHINX_MESSAGE_SIZE) < 0) {
        return -1;
    }

    puts("sphinx: message sent");
    print_hex_memory(sphinx_message, sizeof(sphinx_message));
    
    return 1;
}