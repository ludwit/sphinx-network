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

#include "net/ipv6/addr.h"
#include "net/netif.h"
#include "random.h"
#include "net/sock/udp.h"
#include "tweetnacl.h"

#include "shpinx.h"

void hash_blinding_factor(unsigned char *dest, unsigned char *public_key, unsigned char *sharde_secret, size_t key_size)
{
    unsigned char hash_input[2 * crypto_scalarmult_BYTES];
    unsigned char hash[crypto_hash_BYTES];

    memcpy(&hash_input[0], public_key, key_size);
    memcpy(&hash_input[key_size], sharde_secret, key_size);
    crypto_hash(hash, hash_input, sizeof(hash_input));
    memcpy(dest, &hash, key_size);

    return;
}

void hash_shared_secret(unsigned char *dest, unsigned char *sharde_secret, size_t key_size)
{
    unsigned char hash[crypto_hash_BYTES];
    crypto_hash(hash, sharde_secret, key_size);
    memcpy(dest, &hash, key_size);

    return;
}

void xor_backwards(unsigned char *dest, size_t dest_size, unsigned char *a, size_t a_size, unsigned char *b, size_t b_size, unsigned int num_bytes)
{
    unsigned int i;

    for (i=1; i<=num_bytes; i++) {
        dest[dest_size - i] = a[a_size -  i] ^ b[b_size - i];
    }

    return;
}

void calculate_shared_secrets(unsigned char shared_secrets[][KEY_SIZE], struct network_node* path_nodes[], unsigned char *secret_key, unsigned char *public_key_root)
{
    /* public keys for computing the shared secrets at each hop (a0, a1, ... in sphinx spec) */
    unsigned char public_keys[SPHINX_PATH_LEN][KEY_SIZE];

    /* blinding factors for each hop (b0, b1, ... in sphinx spec) */
    unsigned char blinding_factors[SPHINX_PATH_LEN][KEY_SIZE];

    /* used to store intermediate results */
    unsigned char buff_shared_secret[KEY_SIZE];

    /* prepare root for iteration */

    /* public key for first hop is the generic public key of the sender (a0 in sphinx spec) */
    memcpy(&public_keys[0], public_key_root, sizeof(public_keys[0]));

    /* calculates raw shared secret with first hop (s0 in sphinx spec) */
    crypto_scalarmult(buff_shared_secret, secret_key, path_nodes[0]->public_key);

    /* hash shared secret */
    hash_shared_secret(shared_secrets[0], buff_shared_secret, sizeof(buff_shared_secret));

    /* calculates blinding factor at firt hop (b0 in sphinx spec) */
    hash_blinding_factor(blinding_factors[0], public_keys[0], shared_secrets[0], sizeof(blinding_factors[0]));

    /* iteratively calculates all remaining public keys, shared secrets and blinding factors */
    for (int i=1; i<SPHINX_PATH_LEN; i++) {

        /* blinds the public key for node i-1 to get public key for node i */
        crypto_scalarmult(public_keys[i], blinding_factors[i-1], public_keys[i-1]);

        /* calculates the generic shared secret with node i */
        crypto_scalarmult(buff_shared_secret, secret_key, path_nodes[i]->public_key);

        /* iteratively applies all past blinding to shared secret with node i */
        for (int j=0; j<i; j++) {
            crypto_scalarmult(shared_secrets[i], blinding_factors[j], buff_shared_secret);
            memcpy(buff_shared_secret, &shared_secrets[i], sizeof(buff_shared_secret));
        }

        /* hash shared secret */
        hash_shared_secret(shared_secrets[i], buff_shared_secret, sizeof(buff_shared_secret));

        /* calculates blinding factor */
        hash_blinding_factor(blinding_factors[i], public_keys[i], shared_secrets[i], sizeof(blinding_factors[i]));
    }

    return;
}

void calculate_header_padding(unsigned char* header_padding, unsigned char shared_secrets[][KEY_SIZE])
{ 
    /* stores interim results */
    unsigned char buff_header_padding[HEADER_PADDING_SIZE];
    
    /* random bytes from stream cipher */
    unsigned char prg_stream[ROUTE_SIZE + ENC_ROUTING_SIZE];

    unsigned int padding_size = 0;

    for (int i=0; i<SPHINX_PATH_LEN; i++) {
        /* copy xored value to intermediate header padding */
        memcpy(&buff_header_padding[sizeof(buff_header_padding) - padding_size - ROUTE_SIZE], &header_padding[sizeof(buff_header_padding) - padding_size], padding_size);
        /* add padding to intermediate header */
        memset(&buff_header_padding[sizeof(buff_header_padding) - ROUTE_SIZE], 0, ROUTE_SIZE);
        /* increase padding variable */
        padding_size += ROUTE_SIZE;
        /* calculate pseudo random byte stream with shared secret */
        crypto_stream(prg_stream, sizeof(prg_stream), nonce, shared_secrets[i]);
        /* xor intermediate padding and stream */
        xor_backwards(header_padding, sizeof(buff_header_padding), buff_header_padding, sizeof(buff_header_padding), prg_stream, sizeof(prg_stream), padding_size);
    }

    return;
}

void encapsulate_routing_and_mac(unsigned char* enc_routing, unsigned char* mac, unsigned char* header_padding, unsigned char shared_secrets[][KEY_SIZE], struct network_node* path_nodes[], unsigned char* id)
{
    /* stores intermediate results */
    unsigned char buff_enc_routing[ADDR_SIZE + MAC_SIZE + ENC_ROUTING_SIZE];

    /* prepare root routing information for iteration */
    memcpy(buff_enc_routing, &path_nodes[SPHINX_PATH_LEN-1]->addr, ADDR_SIZE);
    memcpy(&buff_enc_routing[ADDR_SIZE], id, ID_SIZE);
    memcpy(&buff_enc_routing[ADDR_SIZE + ID_SIZE], header_padding, HEADER_PADDING_SIZE);

    for (int i=SPHINX_PATH_LEN - 1; i>=0; i--) {

        /* encrypt routing information for node i (and cutt off padding) */
        crypto_stream_xor(enc_routing, buff_enc_routing, ENC_ROUTING_SIZE, nonce, shared_secrets[i]);

        /* calculate mac of encrypted routng information */
        crypto_onetimeauth(mac, enc_routing, ENC_ROUTING_SIZE, shared_secrets[i]);

        /* end early if last iteration */
        if (i>0) {

            /* append address of node i to intermediate routing information */
            memcpy(buff_enc_routing, &path_nodes[i]->addr, ADDR_SIZE);

            /* append mac to intermediate routing information */
            memcpy(&buff_enc_routing[ADDR_SIZE], mac, MAC_SIZE);

            /* append encrypted routng information to intermediate routing information */
            memcpy(&buff_enc_routing[ADDR_SIZE + MAC_SIZE], enc_routing, ENC_ROUTING_SIZE);
        }
    }

    return;
}

void encapsulate_payload(unsigned char* payload, unsigned char shared_secrets[][KEY_SIZE])
{
    unsigned char buff_payload[PAYLOAD_SIZE];
    unsigned char prg_stream[ADDR_SIZE + MAC_SIZE + ENC_ROUTING_SIZE + PAYLOAD_SIZE];

    for (int i=SPHINX_PATH_LEN - 1; i>=0; i--) {
        memcpy(buff_payload, payload, sizeof(buff_payload));
        crypto_stream(prg_stream, sizeof(prg_stream), nonce, shared_secrets[i]);
        xor_backwards(payload, sizeof(buff_payload), buff_payload, sizeof(buff_payload), prg_stream, sizeof(prg_stream), sizeof(buff_payload));
    }
    return;
}

int create_sphinx_message(unsigned char* sphinx_message, ipv6_addr_t* dest_addr, char* data, size_t data_len)
{
    /* network path for sphinx message (n0, n1, ... in sphinx spec) */
    struct network_node* path_nodes[SPHINX_PATH_LEN];

    /* repeatedly encrypted payload */
    unsigned char enc_payload[PAYLOAD_SIZE];

    /* secret ecc key of the sender (x in sphinx spec) */
    unsigned char secret_key[KEY_SIZE];

    /* generic ecc public key of the sender (a0 in sphinx spec) */
    unsigned char public_key[KEY_SIZE];

    /* shared secrets with nodes at each hop (s0, s1, ... in sphinx spec) */
    unsigned char shared_secrets[SPHINX_PATH_LEN][KEY_SIZE];

    /* generates an ephermal asymmetric key pair for the sender */
    crypto_box_keypair(public_key, secret_key);

    /* padding in header to keep header size invarant at eacht hop */
    unsigned char header_padding[HEADER_PADDING_SIZE];

    /* repeatedly encrypted routing information in the header */
    unsigned char enc_routing[ENC_ROUTING_SIZE];

    /* message authentication code for first hop */
    unsigned char mac[MAC_SIZE];

    /* use mac of payload as id */
    unsigned char id[MAC_SIZE];

    /* builds a random path to the recipient */
    if (pki_bulid_mix_path(path_nodes, ARRAY_SIZE(path_nodes), dest_addr) < 0) {
        puts("could not build mix path");
        return -1;
    }

    /* precomputes the shared secrets with all nodes in path */
    calculate_shared_secrets(shared_secrets, path_nodes, secret_key, public_key);

    /* initialise payload with plain text message and padding */
    memcpy(enc_payload, data, data_len);
    memset(&enc_payload[data_len], 0, PAYLOAD_SIZE - data_len);

    /* calculates mac of plain text payload for athentication at destination and as message id */
    crypto_onetimeauth(id, enc_payload, sizeof(enc_payload), shared_secrets[SPHINX_PATH_LEN - 1]);

    /* repeatedly encrypt payload  */
    encapsulate_payload(enc_payload, shared_secrets);

    /* calculates the final header padding */
    calculate_header_padding(header_padding, shared_secrets);

    /* calculates the nested encrypted routing information */
    encapsulate_routing_and_mac(enc_routing, mac, header_padding, shared_secrets, path_nodes, id);

    /* compose sphinx message */
    memcpy(sphinx_message, public_key, KEY_SIZE);
    memcpy(&sphinx_message[KEY_SIZE], mac, MAC_SIZE);
    memcpy(&sphinx_message[KEY_SIZE + MAC_SIZE], enc_routing, ENC_ROUTING_SIZE);
    memcpy(&sphinx_message[HEADER_SIZE], enc_payload, PAYLOAD_SIZE);

    /* chande destination to first hop */
    memcpy(dest_addr, &path_nodes[0]->addr, ADDR_SIZE);

    return 1;
}

int sphinx_process_message(char *message, int message_size, struct network_node* node_self, unsigned char tag_table[][TAG_SIZE], int* tag_count)
{
    /* sphinx message fields */
    unsigned char public_key[KEY_SIZE];
    unsigned char mac[MAC_SIZE];
    unsigned char enc_routing[ENC_ROUTING_SIZE + ADDR_SIZE + MAC_SIZE];
    unsigned char enc_payload[PAYLOAD_SIZE];
    
    /* shared secret */
    unsigned char raw_shared_secret[KEY_SIZE];
    unsigned char shared_secret[KEY_SIZE];

    /* forward message parts */
    ipv6_addr_t next_hop;
    unsigned char next_public_key[KEY_SIZE];
    unsigned char next_enc_routing[ENC_ROUTING_SIZE + ADDR_SIZE + MAC_SIZE];
    unsigned char next_payload[PAYLOAD_SIZE];
    unsigned char fwd_message[SPHINX_MESSAGE_SIZE];

    /* utils */
    unsigned char prg_stream[ADDR_SIZE + MAC_SIZE + ENC_ROUTING_SIZE + PAYLOAD_SIZE];
    unsigned char blinding_factor[KEY_SIZE];

    /* check for correct message size */
    if (message_size != SPHINX_MESSAGE_SIZE) {
        puts("error: message malformed");
        return -1;
    }

    /* parse sephinx message */
    memcpy(public_key, message, KEY_SIZE);
    memcpy(mac, &message[KEY_SIZE], MAC_SIZE);
    memcpy(enc_routing, &message[KEY_SIZE + MAC_SIZE], ENC_ROUTING_SIZE);
    memcpy(enc_payload, &message[KEY_SIZE + MAC_SIZE + ENC_ROUTING_SIZE], PAYLOAD_SIZE);

    /* calculate shared secret for decryption */
    crypto_scalarmult(raw_shared_secret, node_self->private_key, public_key);
    hash_shared_secret(shared_secret, raw_shared_secret, sizeof(raw_shared_secret));

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
        puts("server: rotated public key");
    }

    /* save message tag */
    memcpy(&tag_table[*tag_count], shared_secret, TAG_SIZE);
    (*tag_count)++;

    /* verify encrypted routing information */
    if (crypto_onetimeauth_verify(mac, enc_routing, ENC_ROUTING_SIZE, shared_secret) < 0) {
        puts("error: message authentication failed");
        return -1;
    }

    /* decrypt routing information */
    memset(&enc_routing[ENC_ROUTING_SIZE], 0, ADDR_SIZE + MAC_SIZE); 
    crypto_stream_xor(next_enc_routing, enc_routing, sizeof(enc_routing), nonce, shared_secret);

    /* decrypt payload */
    crypto_stream(prg_stream, sizeof(prg_stream), nonce, shared_secret);
    xor_backwards(next_payload, sizeof(next_payload), enc_payload, sizeof(enc_payload), prg_stream, sizeof(prg_stream), sizeof(next_payload));
    
    /* parse next hop address */
    memcpy(&next_hop, next_enc_routing, ADDR_SIZE);

    /* check if message is for this node */
    if (ipv6_addr_equal(&node_self->addr, &next_hop)) {

        /* check for payload integrity */
        if (crypto_onetimeauth_verify(&next_enc_routing[ADDR_SIZE], next_payload, sizeof(next_payload), shared_secret) < 0) {
            puts("error: payload authentication failed");
            return -1;
        }
        printf("message received:\n%s\n", next_payload);
        return 1;
    }

    /* calculate next public key */
    hash_blinding_factor(blinding_factor, public_key, shared_secret, sizeof(blinding_factor));
    crypto_scalarmult(next_public_key, blinding_factor, public_key);

    /* compose forward message */
    memcpy(fwd_message, next_public_key, KEY_SIZE);
    memcpy(&fwd_message[KEY_SIZE], &next_enc_routing[ADDR_SIZE], ENC_ROUTING_SIZE + MAC_SIZE);
    memcpy(&fwd_message[HEADER_SIZE], next_payload, PAYLOAD_SIZE);

    if (udp_send(&next_hop, fwd_message, SPHINX_MESSAGE_SIZE) < 0) {
        return -1;
    }

    puts("server: message forwarded");

    return 1;
}