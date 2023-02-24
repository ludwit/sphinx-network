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

#include "net/netif.h"
#include "kernel_defines.h"
#include "random.h"

#include "shpinx.h"

void print_hex_memory (void *mem, int mem_size)
{
    int i;
    unsigned char *p = (unsigned char *)mem;

    for (i=0; i<mem_size -1; i++) {
        if (! (i % 16) && i) {
            printf("\n");
        }
        printf("%02x ", p[i]);
    }
    printf("%02x\n\n", p[i]);

    return;
}

int get_local_ipv6_addr(ipv6_addr_t *result)
{
    netif_t *netif;
    ipv6_addr_t addrs[1];

    netif = netif_iter(NULL);
    // no error return value defined for netif_iter

    if ((netif_get_ipv6(netif, addrs, ARRAY_SIZE(addrs))) < 0) {
        return -1;
    }
    *result = addrs[0];
    return 1;
}

struct network_node* pki_get_node(ipv6_addr_t *node_addr)
{   
    unsigned int i;
    for (i=0; i < SPHINX_NET_SIZE; i++) {
        if (ipv6_addr_equal(&network_pki[i].addr, node_addr)) {
            return (struct network_node*) &network_pki[i];
        }
    }

    /* nothing found */
    return NULL;
}

int pki_bulid_mix_path(struct network_node* path_nodes[], size_t path_size, ipv6_addr_t *dest_addr)
{
    ipv6_addr_t local_addr;
    uint32_t random;
    char chosen[SPHINX_NET_SIZE];
    unsigned int i;

    memset(chosen, 0, sizeof(chosen));
    
    /* get address of this node */
    if (get_local_ipv6_addr(&local_addr) < 0) {
        return -1;
    }

    /* select random mix nodes */
    i = 0;
    while (i < (path_size-1)) {
        random = random_uint32_range(0, SPHINX_NET_SIZE);

        if (chosen[random]) {
            continue;
        }

        if (ipv6_addr_equal(&network_pki[random].addr, &local_addr) || ipv6_addr_equal(&network_pki[random].addr, dest_addr)) {
            chosen[random] = '1';
            continue;
        }

        path_nodes[i] = (struct network_node*) &network_pki[random];
        chosen[random] = '1';
        i++;
    }

    /* add final destination node */
    if ((path_nodes[i] = pki_get_node(dest_addr)) == NULL) {
        puts("destination address not found in pki");
        return -1;
    }

    return 1;
}