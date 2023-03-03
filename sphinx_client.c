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

int sphinx_send(ipv6_addr_t* dest_addr, char *data, size_t data_len)
{
    /* create sphinx message */
    if (sphinx_create_message(sphinx_message, dest_addr, data, data_len) < 0) {
        puts("could not create sphinx message");
        return -1;
    }

    /* send sphinx message */
    if (udp_send(dest_addr, sphinx_message, SPHINX_MESSAGE_SIZE) < 0) {
        return -1;
    }
    
    return 1;
}