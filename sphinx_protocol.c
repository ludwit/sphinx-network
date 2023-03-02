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

/* network path for sphinx message for one direction */
struct network_node* path_nodes[SPHINX_MAX_PATH];

/* shared secrets with nodes to dest */
unsigned char shared_secrets_send[SPHINX_MAX_PATH][KEY_SIZE];

/* shared secrets with nodes for reply */
unsigned char shared_secrets_reply[SPHINX_MAX_PATH][KEY_SIZE];

/* random bytes from stream cipher */
unsigned char prg_stream[PRG_STREAM_SIZE];


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
    // make inplace
    
    unsigned int i;

    for (i=1; i<=num_bytes; i++) {
        dest[dest_size - i] = a[a_size -  i] ^ b[b_size - i];
    }

    return;
}

void calculate_shared_secrets(unsigned char shared_secrets[][KEY_SIZE], struct network_node* path_nodes[], int path_len, unsigned char *secret_key, unsigned char *public_key_root)
{
    /* public keys for computing the shared secrets at each hop (a0, a1, ... in sphinx spec) */
    unsigned char public_keys[SPHINX_MAX_PATH][KEY_SIZE];

    /* blinding factors for each hop (b0, b1, ... in sphinx spec) */
    unsigned char blinding_factors[SPHINX_MAX_PATH][KEY_SIZE];

    /* used to store intermediate results */
    unsigned char buff_shared_secret[KEY_SIZE];

    /* prepare root for calculation of public keys, shared secrets and blinding factors */

    /* public key for first hop is the generic public key of the sender (a0 in sphinx spec) */
    memcpy(&public_keys[0], public_key_root, KEY_SIZE);

    /* calculates raw shared secret with first hop (s0 in sphinx spec) */
    crypto_scalarmult(buff_shared_secret, secret_key, path_nodes[0]->public_key);

    /* hash shared secret */
    hash_shared_secret(shared_secrets[0], buff_shared_secret, KEY_SIZE);

    /* calculates blinding factor at firt hop (b0 in sphinx spec) */
    hash_blinding_factor(blinding_factors[0], public_keys[0], shared_secrets[0], KEY_SIZE);

    /* iteratively calculates all remaining public keys, shared secrets and blinding factors */
    for (int i=1; i<path_len; i++) {

        /* blinds the public key for node i-1 to get public key for node i */
        crypto_scalarmult(public_keys[i], blinding_factors[i-1], public_keys[i-1]);

        /* calculates the generic shared secret with node i */
        crypto_scalarmult(buff_shared_secret, secret_key, path_nodes[i]->public_key);

        /* iteratively applies all past blinding to shared secret with node i */
        for (int j=0; j<i; j++) {
            crypto_scalarmult(shared_secrets[i], blinding_factors[j], buff_shared_secret);
            memcpy(buff_shared_secret, &shared_secrets[i], KEY_SIZE);
        }

        /* hash shared secret */
        hash_shared_secret(shared_secrets[i], buff_shared_secret, KEY_SIZE);

        /* calculates blinding factor */
        hash_blinding_factor(blinding_factors[i], public_keys[i], shared_secrets[i], KEY_SIZE);
    }

    /* blinds the public key for last node to get public key for first node of surb */
    crypto_scalarmult(public_key_root, blinding_factors[path_len-1], public_keys[path_len-1]);

    return;
}

void calculate_nodes_padding(unsigned char* nodes_padding, unsigned char shared_secrets[][KEY_SIZE], int path_len)
{  
    /* stores interim results */
    unsigned char buff_nodes_padding[MAX_NODES_PADDING];

    unsigned int padding_size = 0;

    #if DEBUG
    memset(nodes_padding, 0, MAX_NODES_PADDING);
    #endif /* DEBUG */

    for (int i=0; i<path_len; i++) {
        /* copy xored value to intermediate node padding */
        memcpy(&buff_nodes_padding[MAX_NODES_PADDING - padding_size - NODE_ROUT_SIZE], &nodes_padding[MAX_NODES_PADDING - padding_size], padding_size);
        /* add padding to intermediate node padding */
        memset(&buff_nodes_padding[MAX_NODES_PADDING - NODE_ROUT_SIZE], 0, NODE_ROUT_SIZE);
        /* increase padding variable */
        padding_size += NODE_ROUT_SIZE;
        /* calculate pseudo random byte stream with shared secret */
        crypto_stream(prg_stream, MAX_NODES_PADDING + NODE_PADDING, nonce, shared_secrets[i]);
        /* xor intermediate padding and stream */
        xor_backwards(nodes_padding, MAX_NODES_PADDING, buff_nodes_padding, MAX_NODES_PADDING, prg_stream, MAX_NODES_PADDING + NODE_PADDING, padding_size);

        #if DEBUG
        printf("Node Padding at Node %d\n", i);
        print_hex_memory(nodes_padding, MAX_NODES_PADDING);
        #endif /* DEBUG */
    }

    return;
}

void encapsulate_routing_and_mac(unsigned char* sphinx_message, unsigned char shared_secrets[][KEY_SIZE], int path_len, unsigned char* id)
{
    // hier konnen vielliecht 32 byte von den array gespart werden

    /* stores intermediate results */
    unsigned char buff_enc_routing[ADDR_SIZE + MAC_SIZE + ENC_ROUTING_SIZE];

    /* padding to keep header size invariant regardless of actual path length */
    int header_padding_size = (SPHINX_MAX_PATH - path_len) * NODE_ROUT_SIZE;

    /* prepare root routing information for iteration */
    memcpy(buff_enc_routing, &path_nodes[path_len-1]->addr, ADDR_SIZE);
    memcpy(&buff_enc_routing[ADDR_SIZE], id, MAC_SIZE);
    random_bytes(&buff_enc_routing[ADDR_SIZE + MAC_SIZE], header_padding_size);
    memcpy(&buff_enc_routing[ADDR_SIZE + MAC_SIZE + header_padding_size], &sphinx_message[MAC_SIZE + header_padding_size], MAX_NODES_PADDING - header_padding_size);

    for (int i=path_len - 1; i>=0; i--) {


        /* encrypt routing information for node i (and cutt off padding) */
        crypto_stream_xor(&sphinx_message[MAC_SIZE], buff_enc_routing, ENC_ROUTING_SIZE, nonce, shared_secrets[i]);

        /* calculate mac of encrypted routng information */
        crypto_onetimeauth(sphinx_message, &sphinx_message[MAC_SIZE], ENC_ROUTING_SIZE, shared_secrets[i]);

        #if DEBUG
        printf("Encrypted Routing Inforamtion at Node %d\n", i);
        print_hex_memory(&sphinx_message[MAC_SIZE], ENC_ROUTING_SIZE);
        printf("MAC of enrypted routing at Node %d\n", i);
        print_hex_memory(sphinx_message, MAC_SIZE);
        #endif /* DEBUG */

        /* end early if last iteration */
        if (i>0) {

            /* append address of node i to intermediate routing information */
            memcpy(buff_enc_routing, &path_nodes[i]->addr, ADDR_SIZE);

            /* append mac and routing information to intermediate routing information */
            memcpy(&buff_enc_routing[ADDR_SIZE], sphinx_message, MAC_SIZE + ENC_ROUTING_SIZE);
        }
    }

    return;
}

int build_sphinx_header(unsigned char* sphinx_header, unsigned char* id, ipv6_addr_t* first_hop_addr, ipv6_addr_t* start_addr, ipv6_addr_t* dest_addr, unsigned char* public_key, unsigned char* secret_key)
{
    /* choose random number for path length */
    int path_len = random_uint32_range(3, SPHINX_MAX_PATH);

    #if DEBUG
    printf("path_len to dest = %d\n", path_len);
    #endif /* DEBUG */

    /* builds a random path to the destination */
    if (pki_bulid_mix_path(path_nodes, path_len, start_addr, dest_addr) < 0) {
        puts("could not build mix path");
        return -1;
    }

    /* save address of first hop */
    memcpy(first_hop_addr, &path_nodes[0]->addr, ADDR_SIZE);

    /* precomputes the shared secrets with all nodes in path */
    calculate_shared_secrets(shared_secrets_send, path_nodes, path_len, secret_key, public_key);

    #if DEBUG
    puts("shared secrets to dest");
    print_hex_memory(shared_secrets_send, KEY_SIZE * SPHINX_MAX_PATH);
    #endif /* DEBUG */

    /* calculates mac of plain text payload for authentication at destination and as message id */
    crypto_onetimeauth(id, &sphinx_header[HEADER_SIZE + SURB_SIZE], PAYLOAD_SIZE, shared_secrets_send[path_len - 1]);

    #if DEBUG
    puts("MAC of Payload");
    print_hex_memory(id, MAC_SIZE);
    puts("plaintext payload");
    print_hex_memory(&sphinx_header[HEADER_SIZE + SURB_SIZE], PAYLOAD_SIZE);
    #endif /* DEBUG */

    /* precalculates the accumulated padding added at each hop */
    calculate_nodes_padding(&sphinx_header[KEY_SIZE + MAC_SIZE], shared_secrets_send, path_len);

    /* calculates the nested encrypted routing information */
    encapsulate_routing_and_mac(&sphinx_header[KEY_SIZE], shared_secrets_send, path_len, id);

    return path_len;
}


void encrypt_surb_and_payload(unsigned char* surb_and_payload, int path_len)
{

    unsigned char buff[SURB_SIZE + PAYLOAD_SIZE];

    for (int i=path_len-1; i>=0; i--) {

        crypto_stream(prg_stream, PRG_STREAM_SIZE, nonce, shared_secrets_send[i]);

        xor_backwards(buff, SURB_SIZE + PAYLOAD_SIZE, prg_stream, PRG_STREAM_SIZE, surb_and_payload, SURB_SIZE + PAYLOAD_SIZE, SURB_SIZE + PAYLOAD_SIZE);

        memcpy(surb_and_payload, buff, SURB_SIZE + PAYLOAD_SIZE);

        #if DEBUG
        printf("enc surb at node %d\n", i);
        print_hex_memory(surb_and_payload, SURB_SIZE);
        printf("enc payload at node %d\n", i);
        print_hex_memory(&surb_and_payload[SURB_SIZE], PAYLOAD_SIZE);
        #endif /* DEBUG */
    }
    return;
}

int build_sphinx_surb(unsigned char *sphinx_surb, unsigned char *id, ipv6_addr_t *dest_addr, ipv6_addr_t *local_addr, unsigned char* public_key, unsigned char* secret_key)
{
    /* choose random number for path length */
    int path_len = random_uint32_range(3, SPHINX_MAX_PATH);

    /* builds a random path to the destination */
    if (pki_bulid_mix_path(path_nodes, path_len, dest_addr, local_addr) < 0) {
        puts("could not build mix path");
        return -1;
    }

    /* save address of first hop to surb */
    memcpy(sphinx_surb, &path_nodes[0]->addr, ADDR_SIZE);

    /* precomputes the shared secrets with all nodes in path */
    calculate_shared_secrets(shared_secrets_reply, path_nodes, path_len, secret_key, public_key);

    #if DEBUG
    puts("shared secrets for reply");
    print_hex_memory(shared_secrets_reply, KEY_SIZE * SPHINX_MAX_PATH);
    #endif /* DEBUG */

    /* precalculates the accumulated padding added at each hop */
    calculate_nodes_padding(&sphinx_surb[ADDR_SIZE], shared_secrets_reply, path_len);

    /* calculates the nested encrypted routing information */
    encapsulate_routing_and_mac(&sphinx_surb[ADDR_SIZE], shared_secrets_reply, path_len, id);

    return 1;
}

int create_sphinx_message(unsigned char* sphinx_message, ipv6_addr_t* dest_addr, char* data, size_t data_len)
{
    /* generic ecc public key of the sender (a0 in sphinx spec) */
    unsigned char public_key[KEY_SIZE];

    /* secret ecc key of the sender (x in sphinx spec) */
    unsigned char secret_key[KEY_SIZE];
    
    // irgendwann ganz global machen
    ipv6_addr_t local_addr;

    /* used to save address of first hop */
    ipv6_addr_t first_hop_addr;

    int path_len;

    /* mac of payload as message id */
    unsigned char id[MAC_SIZE];

    /* local ipv6 addr */  // kann wenn die event sache ist wegrationalisiert werden
    get_local_ipv6_addr(&local_addr);

    /* generates an ephermal asymmetric key pair for the sender */
    crypto_box_keypair(public_key, secret_key);

    /* put public key for first hop in place */
    memcpy(sphinx_message, public_key, KEY_SIZE);

    /* put payload in place */
    memcpy(&sphinx_message[HEADER_SIZE + SURB_SIZE], data, data_len);

    path_len = build_sphinx_header(sphinx_message, id, &first_hop_addr, &local_addr, dest_addr, public_key, secret_key);

    build_sphinx_surb(&sphinx_message[HEADER_SIZE], id, dest_addr, &local_addr, public_key, secret_key);

    encrypt_surb_and_payload(&sphinx_message[HEADER_SIZE], path_len);

    /* change destination to first hop */
    memcpy(dest_addr, &first_hop_addr, ADDR_SIZE);

    //save_id(id);

    #if DEBUG
    puts("Sphinx message");
    print_hex_memory(sphinx_message, SPHINX_MESSAGE_SIZE);
    #endif /* DEBUG */

    return 1;
}

int sphinx_process_message(char *message, int message_size, struct network_node* node_self, unsigned char tag_table[][TAG_SIZE], int* tag_count)
{
    /* sphinx message fields */
    unsigned char public_key[KEY_SIZE];
    unsigned char mac[MAC_SIZE];
    unsigned char enc_routing[ENC_ROUTING_SIZE + NODE_PADDING];
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
    memcpy(enc_payload, &message[HEADER_SIZE + SURB_SIZE], PAYLOAD_SIZE);

    /* calculate shared secret for decryption */
    crypto_scalarmult(raw_shared_secret, node_self->private_key, public_key);
    hash_shared_secret(shared_secret, raw_shared_secret, sizeof(raw_shared_secret));

    #if DEBUG
    puts("Public Key");
    print_hex_memory(public_key, KEY_SIZE);
    puts("MAC");
    print_hex_memory(mac, MAC_SIZE);
    puts("Encrypted Routing Information");
    print_hex_memory(enc_routing, ENC_ROUTING_SIZE);
    puts("Encrypted Payload");
    print_hex_memory(enc_payload, PAYLOAD_SIZE);
    puts("Shared Secret Key");
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
    memset(&enc_routing[ENC_ROUTING_SIZE], 0, NODE_PADDING); 
    crypto_stream_xor(next_enc_routing, enc_routing, sizeof(enc_routing), nonce, shared_secret);

    /* decrypt payload */
    crypto_stream(prg_stream, PRG_STREAM_SIZE, nonce, shared_secret);
    xor_backwards(next_payload, sizeof(next_payload), enc_payload, sizeof(enc_payload), prg_stream, sizeof(prg_stream), sizeof(next_payload));
    
    /* parse next hop address */
    memcpy(&next_hop, next_enc_routing, ADDR_SIZE);

    /* check if message is for this node */
    if (ipv6_addr_equal(&node_self->addr, &next_hop)) {

        /* check for payload integrity */
        if (crypto_onetimeauth_verify(&next_enc_routing[ADDR_SIZE], next_payload, sizeof(next_payload), shared_secret) < 0) {
            #if DEBUG
            puts("mac of payload");
            print_hex_memory(&next_enc_routing[ADDR_SIZE], MAC_SIZE);
            puts("dec payload");
            print_hex_memory(next_payload, PAYLOAD_SIZE);
            #endif /* DEBUG */
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
    memcpy(&fwd_message[HEADER_SIZE+SURB_SIZE], next_payload, PAYLOAD_SIZE);

    if (udp_send(&next_hop, fwd_message, SPHINX_MESSAGE_SIZE) < 0) {
        return -1;
    }

    puts("server: message forwarded");

    return 1;
}