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

int process_reply(unsigned char *message)
{
    /* look for id in sent messages */
    for (int i=0; i<sent_msg_count; i++) {
        /* delet if found */
        if (memcmp(&message[MAC_SIZE + ADDR_SIZE], sent_msg_table[i].id, ID_SIZE) == 0) {
            memcpy(&sent_msg_table[i], &sent_msg_table[i+1], (SENT_MSG_TABLE_SIZE - sent_msg_count) * sizeof(event_send));
            sent_msg_count--;
            print_id(&message[KEY_SIZE]);
            puts("message acknoleged");
            return 1;
        }
    }

    puts("error: id of acknolegement not found");
    return -1;
}

int receive_message(unsigned char *message, unsigned char *public_key, unsigned char *shared_secret)
{
    ipv6_addr_t first_reply_hop;

    unsigned char blinding_factor[KEY_SIZE];

    /* verify integrity of surb and payload */
    if (crypto_onetimeauth_verify(&message[HEADER_SIZE], &message[HEADER_SIZE + MAC_SIZE], SURB_SIZE + PAYLOAD_SIZE, shared_secret) < 0) {
        puts("error: surb and payload authentication failed");
        return -1;
    }

    /* print message */
    printf("sphinx: %s\n", &message[HEADER_SIZE + MAC_SIZE + SURB_SIZE]);

    /* parse address of first reply hop */
    memcpy(&first_reply_hop, &message[HEADER_SIZE + MAC_SIZE], ADDR_SIZE);

    /* calculate public key for next hop */
    hash_blinding_factor(blinding_factor, public_key, shared_secret);
    crypto_scalarmult(message, blinding_factor, public_key);

    /* move surb to header position */
    memmove(&message[KEY_SIZE], &message[HEADER_SIZE + MAC_SIZE + ADDR_SIZE], MAC_SIZE + ENC_ROUTING_SIZE);

    /* fill rest with random bytes */
    random_bytes(&message[HEADER_SIZE], MAC_SIZE + SURB_SIZE + PAYLOAD_SIZE);

    if (udp_send(&first_reply_hop, message, SPHINX_MESSAGE_SIZE) < 0) {
        return -1;
    }

    return 1;
}

int forward_message(unsigned char *message, unsigned char *public_key, unsigned char *shared_secret)
{
    ipv6_addr_t next_hop;

    unsigned char blinding_factor[KEY_SIZE];

    /* parse next hop address */
    memcpy(&next_hop, &message[MAC_SIZE], ADDR_SIZE);

    /* calculate public key for next hop */
    hash_blinding_factor(blinding_factor, public_key, shared_secret);
    crypto_scalarmult(message, blinding_factor, public_key);

    if (udp_send(&next_hop, message, SPHINX_MESSAGE_SIZE) < 0) {
        return -1;
    }

    puts("sphinx: message forwarded");
    return 1;
}


int sphinx_process_message(unsigned char *message, network_node* node_self, unsigned char tag_table[][TAG_SIZE], int* tag_count)
{
    /* shared secret */
    unsigned char raw_shared_secret[KEY_SIZE];
    unsigned char shared_secret[KEY_SIZE];

    /* public key of message */
    unsigned char public_key[KEY_SIZE];

    /* check if public key is valid point on ecc (not supported by tweetnacl) */

    /* save public key */
    memcpy(public_key, message, KEY_SIZE);

    /* calculate shared secret for decryption */
    crypto_scalarmult(raw_shared_secret, node_self->private_key, public_key);
    hash_shared_secret(shared_secret, raw_shared_secret);

    #if DEBUG
    puts("DEBUG: message received");
    print_hex_memory(message, SPHINX_MESSAGE_SIZE);
    puts("DEBUG: shared secret");
    print_hex_memory(shared_secret, KEY_SIZE);
    #endif /* DEBUG */

    /* check for duplicate */
    for (int i=0; i<*tag_count; i++) {
        if (memcmp(shared_secret, &tag_table[i], TAG_SIZE) == 0) {
            puts("error: duplicate detected");
            return -1;
        }
    }

    /* check if tag table is full */
    if (*tag_count == 128) {
        *tag_count = 0;
        puts("sphinx: rotated public key"); //theory
    }

    /* save message tag */
    memcpy(&tag_table[*tag_count], shared_secret, TAG_SIZE);
    (*tag_count)++;


    /* verify encrypted routing information */
    if (crypto_onetimeauth_verify(&message[KEY_SIZE], &message[KEY_SIZE + MAC_SIZE], ENC_ROUTING_SIZE, shared_secret) < 0) {
        puts("error: message authentication failed");
        return -1;
    }

    /* add node padding */
    memmove(&message[KEY_SIZE + MAC_SIZE - NODE_PADDING_SIZE], &message[KEY_SIZE + MAC_SIZE], ENC_ROUTING_SIZE);
    memset(&message[HEADER_SIZE - NODE_PADDING_SIZE], 0, NODE_PADDING_SIZE);

    /* decrypt message */
    crypto_stream(prg_stream, PRG_STREAM_SIZE, nonce, shared_secret);
    xor_backwards_inplace(message, SPHINX_MESSAGE_SIZE, prg_stream, PRG_STREAM_SIZE, PRG_STREAM_SIZE);

    /* check if message is forward, receive or reply */
    if (ipv6_addr_equal(&node_self->addr, (ipv6_addr_t *) &message[MAC_SIZE])) {

        if (message[MAC_SIZE + ADDR_SIZE] == 0x00 && memcmp(&message[MAC_SIZE + ADDR_SIZE], &message[MAC_SIZE + ADDR_SIZE + 1], ID_SIZE - 1) == 0) {
            return receive_message(message, public_key, shared_secret);
        } else {
            return process_reply(message);
        }

        puts("error: corrupted payload");
        return -1;
        
    } else {
        return forward_message(message, public_key, shared_secret);
    }
}