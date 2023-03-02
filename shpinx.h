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

#include "net/ipv6/addr.h"
#include "kernel_defines.h"

/* dev tools */
#define DEBUG 0

/* sphinx network metrics */
#define SPHINX_PORT 45678
#define SPHINX_NET_SIZE ARRAY_SIZE(network_pki)
#define SPHINX_MAX_PATH 5

/* sphinx format metrics */
#define KEY_SIZE 32
#define ADDR_SIZE 16
#define MAC_SIZE 16
#define PAYLOAD_SIZE 128
#define NODE_ROUT_SIZE (ADDR_SIZE + MAC_SIZE)
#define NODE_PADDING NODE_ROUT_SIZE
#define ENC_ROUTING_SIZE (SPHINX_MAX_PATH * NODE_ROUT_SIZE)
#define MAX_NODES_PADDING (SPHINX_MAX_PATH * NODE_PADDING)
#define HEADER_SIZE (KEY_SIZE + MAC_SIZE + ENC_ROUTING_SIZE)
#define SURB_SIZE (ADDR_SIZE + MAC_SIZE + ENC_ROUTING_SIZE)
#define PRG_STREAM_SIZE ( ENC_ROUTING_SIZE + NODE_PADDING + SURB_SIZE + PAYLOAD_SIZE)
#define SPHINX_MESSAGE_SIZE (HEADER_SIZE + SURB_SIZE + PAYLOAD_SIZE)

/* mix node metrics */
#define TAG_SIZE 4
#define TAG_TABLE_LEN 128

struct network_node {
    ipv6_addr_t addr;
    unsigned char public_key[32];
    unsigned char private_key[32];
};

static const struct network_node network_pki[] =
{
    /* 0 */
    {
        /* ipv6 address */
        {{0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc4, 0xb2, 0xcc, 0xff, 0xfe, 0xaf, 0x86, 0xf2}},
        /* public key */
        {0xb3, 0x92, 0x25, 0xc9, 0xd8, 0x41, 0x9d, 0x06, 0xb3, 0x7a, 0xe2, 0x64, 0x8b, 0xca, 0x9f, 0x83, 0x1b, 0xd1, 0xee, 0x08, 0x02, 0xd1, 0xcd, 0x8f, 0xbf, 0x36, 0x5e, 0x47, 0xba, 0xdb, 0x68, 0x09},
        /* secret key */
        {0x23, 0x4f, 0xd3, 0x74, 0x94, 0x07, 0xb7, 0xdf, 0x6c, 0xd4, 0x0e, 0x0a, 0x80, 0xde, 0xb5, 0xe1, 0xde, 0x06, 0x7c, 0x49, 0x6d, 0x77, 0xf5, 0x40, 0x1e, 0xed, 0xf9, 0x8d, 0xf5, 0x7f, 0xf0, 0x37}
    },
    /* 1 */
    {
        /* ipv6 address */
        {{0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x98, 0xed, 0xfa, 0xff, 0xfe, 0x6e, 0x79, 0xec}},
        /* public key */
        {0xd5, 0x88, 0x47, 0x3e, 0x97, 0xc0, 0x53, 0x30, 0xa9, 0x32, 0xf5, 0x74, 0xa0, 0xd9, 0x30, 0xec, 0x03, 0x1e, 0x34, 0x2e, 0xec, 0xc3, 0x9b, 0x67, 0xc1, 0x56, 0xe1, 0x1f, 0x73, 0xef, 0x2b, 0x3a},
        /* secret key */
        {0xae, 0x22, 0x7e, 0x1c, 0xab, 0xf7, 0x1d, 0xbb, 0x9a, 0xd6, 0x72, 0x3e, 0x6d, 0x6d, 0x6d, 0xb9, 0x75, 0x12, 0xaf, 0x23, 0x18, 0xdb, 0xc2, 0x5c, 0x92, 0x17, 0x32, 0x23, 0x67, 0xfa, 0x33, 0x74}
    },
    /* 2 */
    {
        /* ipv6 address */
        {{0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0x82, 0xbb, 0xff, 0xfe, 0x4a, 0xc0, 0x6b}},
        /* public key */
        {0x2b, 0xef, 0xff, 0x0b, 0x68, 0x1f, 0xd8, 0x14, 0x02, 0xb1, 0x20, 0x27, 0xaa, 0xda, 0x1b, 0x0a, 0x85, 0x63, 0x75, 0x8e, 0xab, 0x00, 0xe1, 0x80, 0xa9, 0x3c, 0xb9, 0x6b, 0x3b, 0xb1, 0xf3, 0x44},
        /* secret key */
        {0x71, 0xe2, 0xef, 0x0e, 0x44, 0xf5, 0xf3, 0x95, 0x1c, 0xf7, 0xc0, 0x5c, 0xcb, 0x70, 0xec, 0x23, 0x31, 0x10, 0x51, 0xfb, 0x4f, 0xe8, 0x24, 0x92, 0x6e, 0xc7, 0x69, 0x49, 0x21, 0x8a, 0xa9, 0xc4}
    },
    /* 3 */
    {
        /* ipv6 address */
        {{0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb4, 0xcf, 0x65, 0xff, 0xfe, 0xac, 0x25, 0x29}},
        /* public key */
        {0x87, 0x68, 0x06, 0xf2, 0x59, 0x83, 0x5d, 0x43, 0x9f, 0x8a, 0xf5, 0xdc, 0xab, 0x41, 0x74, 0x85, 0x8f, 0x9e, 0x1c, 0xe2, 0x75, 0x60, 0x14, 0xb8, 0x6c, 0x52, 0xc6, 0x22, 0xb8, 0xee, 0xbb, 0x1e},
        /* secret key */
        {0x74, 0x0e, 0x97, 0xf1, 0x02, 0x9d, 0x65, 0x0b, 0xa9, 0xd7, 0x5a, 0x51, 0x10, 0xf4, 0x45, 0x0b, 0x40, 0xf4, 0x4e, 0x71, 0x49, 0x1b, 0xd2, 0x43, 0xbf, 0x40, 0xf8, 0xb0, 0x6f, 0xb9, 0x7b, 0x7c}
    },
    /* 4 */
    {
        /* ipv6 address */
        {{0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x1b, 0x7b, 0xff, 0xfe, 0x97, 0xb7, 0x99}},
        /* public key */
        {0x3d, 0x55, 0x59, 0xfc, 0x81, 0x23, 0x01, 0xe3, 0x83, 0x2c, 0x97, 0x2c, 0x4b, 0x54, 0x22, 0x23, 0x88, 0x25, 0x71, 0x4e, 0x5b, 0xdc, 0xb5, 0x93, 0x40, 0x8b, 0xe4, 0xb5, 0xf0, 0xd1, 0xa6, 0x1a},
        /* secret key */
        {0x83, 0xfe, 0x1c, 0xe6, 0x48, 0x51, 0xf2, 0x6b, 0xbb, 0xba, 0x06, 0xdb, 0x2f, 0xe4, 0xdb, 0x44, 0x16, 0x4c, 0xf9, 0xbd, 0x2a, 0x69, 0x79, 0x11, 0x29, 0x46, 0x0a, 0x83, 0x3e, 0x9e, 0x4d, 0xa6}
    },
    /* 5 */
    {
        /* ipv6 address */
        {{0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd8, 0x84, 0xc3, 0xff, 0xfe, 0x05, 0xe9, 0x15}},
        /* public key */
        {0xad, 0xb9, 0x1f, 0x56, 0x9a, 0xff, 0x33, 0x3a, 0xb6, 0x12, 0xb8, 0x91, 0x19, 0xc7, 0x80, 0xc2, 0x27, 0xe2, 0xe0, 0x6d, 0xef, 0xc3, 0x0a, 0x6b, 0xb3, 0x51, 0xa9, 0x77, 0x88, 0xa0, 0x50, 0x3e},
        /* secret key */
        {0x41, 0xa6, 0xef, 0x58, 0x7c, 0x26, 0xbf, 0x17, 0xf4, 0x33, 0xd0, 0x63, 0x74, 0x81, 0xc4, 0x08, 0x0c, 0xf2, 0x28, 0x20, 0x69, 0x94, 0x30, 0xbd, 0xbe, 0x18, 0x08, 0xa8, 0xc1, 0x82, 0x85, 0x73}
    }
};

static const unsigned char nonce[] = { 0xff, 0xcb, 0x7c, 0x4f, 0xcc, 0x0e, 0xf9, 0x29, 0xde, 0xaa, 0x42, 0xd2, 0xa2, 0x3e, 0x5f, 0xa3, 0xbd, 0x6d, 0xd8, 0x76, 0xf8, 0x7c, 0x84, 0x3f };

int sphinx_server_start(void);

int sphinx_send(ipv6_addr_t* dest_addr, char *data, size_t data_len);

int udp_send(ipv6_addr_t* dest_addr, unsigned char *message, size_t message_size);

int get_local_ipv6_addr(ipv6_addr_t *result);

int create_sphinx_message(unsigned char *sphinx_message, ipv6_addr_t* dest_addr, char *data, size_t data_len);

int sphinx_process_message(char *message, int message_size, struct network_node* node_self, unsigned char tag_table[][TAG_SIZE], int* tag_count);

void print_hex_memory (void *mem, int mem_size);

int pki_bulid_mix_path(struct network_node* path_nodes[], int path_len, ipv6_addr_t *start_addr, ipv6_addr_t *dest_addr);

struct network_node* pki_get_node(ipv6_addr_t *node_addr);
