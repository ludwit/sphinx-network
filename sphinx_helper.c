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

void print_hex_memory(void *mem, int mem_size)
{
    int i;
    unsigned char *p = (unsigned char *)mem;

    for (i=0; i<mem_size -1; i++) {
        if (! (i % 16) && i) {
            printf("\n");
        }
        printf("0x%02x, ", p[i]);
    }
    printf("0x%02x\n\n", p[i]);
}

void print_id(void *id)
{
    int i;
    unsigned char *p = (unsigned char *)id;

    for (i=0; i<ID_SIZE; i++) {
        printf("%02x", p[i]);
    }
    printf(": ");
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

network_node* get_node(ipv6_addr_t *node_addr)
{   
    unsigned int i;
    for (i=0; i < SPHINX_NET_SIZE; i++) {
        if (ipv6_addr_equal(&network_pki[i].addr, node_addr)) {
            return (network_node*) &network_pki[i];
        }
    }

    /* nothing found */
    return NULL;
}

int udp_send(ipv6_addr_t* dest_addr, unsigned char *message, size_t message_size)
{
    /* set up remote endpoint */
    sock_udp_ep_t remote = { .family = AF_INET6 };
    remote.port = SPHINX_PORT;
    memcpy(remote.addr.ipv6, dest_addr, sizeof(ipv6_addr_t));

    /* send message */
    if (sock_udp_send(NULL, message, message_size, &remote) < 0) {
        puts("error: could not send message with udp");
        return -1;
    }

    return 1;
}

void hash_blinding_factor(unsigned char *dest, unsigned char *public_key, unsigned char *sharde_secret)
{
    unsigned char hash_input[2 * KEY_SIZE];
    unsigned char hash[crypto_hash_BYTES];

    memcpy(&hash_input[0], public_key, KEY_SIZE);
    memcpy(&hash_input[KEY_SIZE], sharde_secret, KEY_SIZE);
    crypto_hash(hash, hash_input, sizeof(hash_input));
    memcpy(dest, &hash, KEY_SIZE);
}

void hash_shared_secret(unsigned char *dest, unsigned char *raw_sharde_secret)
{
    unsigned char hash[crypto_hash_BYTES];
    crypto_hash(hash, raw_sharde_secret, KEY_SIZE);
    memcpy(dest, &hash, KEY_SIZE);
}

void xor_backwards_inplace(unsigned char *dest, size_t dest_size, unsigned char *arg, size_t arg_size, int num_bytes)
{
    for (int i=1; i<=num_bytes; i++) {
        dest[dest_size - i] = dest[dest_size -  i] ^ arg[arg_size - i];
    }
}