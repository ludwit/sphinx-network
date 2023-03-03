#include "shpinx.h"

/* network path for sphinx message for one direction */
struct network_node* path_nodes[SPHINX_MAX_PATH];

/* shared secrets with nodes to dest */
unsigned char shared_secrets_send[SPHINX_MAX_PATH][KEY_SIZE];

/* shared secrets with nodes for reply */
unsigned char shared_secrets_reply[SPHINX_MAX_PATH][KEY_SIZE];



void calculate_shared_secrets(unsigned char shared_secrets[][KEY_SIZE], struct network_node* path_nodes[], int path_len, unsigned char *secret_key, unsigned char *public_key_root)
{
    /* public keys for computing the shared secrets at each hop (a0, a1, ... in sphinx spec) */
    unsigned char public_keys[SPHINX_MAX_PATH][KEY_SIZE];

    /* blinding factors for each hop (b0, b1, ... in sphinx spec) */
    unsigned char blinding_factors[SPHINX_MAX_PATH][KEY_SIZE];

    /* used to store intermediate results */
    unsigned char buff_shared_secret[KEY_SIZE];

    /* prepare root for calculation of public keys, shared secrets and blinding factors */

    /* public key for first hop is the generic public key of the sender (for surb the blinded public key for dest) */
    memcpy(&public_keys[0], public_key_root, KEY_SIZE);

    /* calculates raw shared secret with first hop (s0 in sphinx spec) */
    crypto_scalarmult(buff_shared_secret, secret_key, path_nodes[0]->public_key);

    /* hash shared secret */
    hash_shared_secret(shared_secrets[0], buff_shared_secret);

    /* calculates blinding factor at firt hop (b0 in sphinx spec) */
    hash_blinding_factor(blinding_factors[0], public_keys[0], shared_secrets[0]);

    /* iteratively calculates all remaining public keys, shared secrets and blinding factors */
    for (int i=1; i<path_len; i++) {

        /* blinds the public key for node i-1 to get public key for node i */
        crypto_scalarmult(public_keys[i], blinding_factors[i-1], public_keys[i-1]);

        /* calculates the generic shared secret with node i */
        crypto_scalarmult(buff_shared_secret, secret_key, path_nodes[i]->public_key);

        /* iteratively applies all past blinding to shared secret with node i */ // das hier für den SURB irgendwie auch machen :))))))))))))))))))
        for (int j=0; j<i; j++) {
            crypto_scalarmult(shared_secrets[i], blinding_factors[j], buff_shared_secret);
            memcpy(buff_shared_secret, &shared_secrets[i], KEY_SIZE);
        }

        /* hash shared secret */
        hash_shared_secret(shared_secrets[i], buff_shared_secret);

        /* calculates blinding factor */
        hash_blinding_factor(blinding_factors[i], public_keys[i], shared_secrets[i]);
    }

    /* blinds the public key for last node to get public key for first node of surb */
    crypto_scalarmult(public_key_root, blinding_factors[path_len-1], public_keys[path_len-1]);

    #if DEBUG
    puts("public keys");
    print_hex_memory(public_keys, SPHINX_MAX_PATH * KEY_SIZE);
    #endif /* DEBUG */

    return;
}

void calculate_nodes_padding(unsigned char* nodes_padding, unsigned char shared_secrets[][KEY_SIZE], int path_len)
{
    unsigned int padding_size = 0;

    #if DEBUG
    memset(nodes_padding, 0, MAX_NODES_PADDING);
    #endif /* DEBUG */

    for (int i=0; i<path_len; i++) {
        /* move padding for NODE_ROUTE_SIZE = NODE_PADDING_SIZE bytes to the left */
        memmove(&nodes_padding[MAX_NODES_PADDING - padding_size - NODE_ROUT_SIZE], &nodes_padding[MAX_NODES_PADDING - padding_size], padding_size);
        /* set the rightmost NODE_ROUTE_SIZE bytes to zero (this is the padding) */
        memset(&nodes_padding[MAX_NODES_PADDING - NODE_ROUT_SIZE], 0, NODE_ROUT_SIZE);
        /* increase padding variable */
        padding_size += NODE_ROUT_SIZE;
        /* calculate pseudo random byte stream with shared secret */
        crypto_stream(prg_stream, MAX_NODES_PADDING + NODE_PADDING_SIZE, nonce, shared_secrets[i]);
        /* xor padding with random byte stream */
        xor_backwards_inplace(nodes_padding, MAX_NODES_PADDING, prg_stream, MAX_NODES_PADDING + NODE_PADDING_SIZE, padding_size);

        #if DEBUG
        printf("Node Padding at Node %d\n", i);
        print_hex_memory(nodes_padding, MAX_NODES_PADDING);
        #endif /* DEBUG */
    }

    /* cutt off last node padding to move nodes padding in place for encapsulation of routing and mac */
    memmove(&nodes_padding[MAX_NODES_PADDING - ((path_len - 1) * NODE_ROUT_SIZE)], &nodes_padding[MAX_NODES_PADDING - ((path_len) * NODE_ROUT_SIZE)], (path_len - 1) * NODE_ROUT_SIZE);
    
    return;
}

void encapsulate_routing_and_mac(unsigned char* routing_and_mac, unsigned char shared_secrets[][KEY_SIZE], int path_len, unsigned char* id)
{
    /* padding to keep header size invariant regardless of actual path length */
    int header_padding_size = (SPHINX_MAX_PATH - path_len) * NODE_ROUT_SIZE;

    /* prepare root routing information for iteration */
    memcpy(&routing_and_mac[MAC_SIZE], &path_nodes[path_len-1]->addr, ADDR_SIZE);
    memcpy(&routing_and_mac[MAC_SIZE + ADDR_SIZE], id, MAC_SIZE);
    random_bytes(&routing_and_mac[MAC_SIZE + ADDR_SIZE + MAC_SIZE], header_padding_size);

    for (int i=path_len-1; i>=0; i--) {

        #if DEBUG
        printf("Decrypted Routing Inforation at Node %d\n", i);
        print_hex_memory(&routing_and_mac[MAC_SIZE], ENC_ROUTING_SIZE);
        #endif /* DEBUG */

        /* calculate pseudo random byte stream with shared secret */
        crypto_stream(prg_stream, ENC_ROUTING_SIZE, nonce, shared_secrets[i]);

        /* xor routing information for node i with prg stream */
        xor_backwards_inplace(&routing_and_mac[MAC_SIZE], ENC_ROUTING_SIZE, prg_stream, ENC_ROUTING_SIZE, ENC_ROUTING_SIZE);

        /* calculate mac of encrypted routng information */
        crypto_onetimeauth(routing_and_mac, &routing_and_mac[MAC_SIZE], ENC_ROUTING_SIZE, shared_secrets[i]);

        #if DEBUG
        printf("Encrypted Routing Inforamtion at Node %d\n", i);
        print_hex_memory(&routing_and_mac[MAC_SIZE], ENC_ROUTING_SIZE);
        printf("MAC of enrypted routing at Node %d\n", i);
        print_hex_memory(routing_and_mac, MAC_SIZE);
        #endif /* DEBUG */

        /* end early if last iteration */
        if (i>0) {

            /* cutt off node padding in routing_and_mac to make space for next hop address and mac */
            memmove(&routing_and_mac[ADDR_SIZE + MAC_SIZE], routing_and_mac, MAC_SIZE + ENC_ROUTING_SIZE - NODE_PADDING_SIZE);

            /* put address of node i in place for next iteration */
            memcpy(&routing_and_mac[MAC_SIZE], &path_nodes[i]->addr, ADDR_SIZE);
        }
    }
    return;
}

void encrypt_surb_and_payload(unsigned char* surb_and_payload, int path_len)
{
    for (int i=path_len-1; i>=0; i--) {

        crypto_stream(prg_stream, PRG_STREAM_SIZE, nonce, shared_secrets_send[i]);

        xor_backwards_inplace(surb_and_payload, SURB_SIZE + PAYLOAD_SIZE, prg_stream, PRG_STREAM_SIZE, SURB_SIZE + PAYLOAD_SIZE);

        #if DEBUG
        printf("enc surb at node %d\n", i);
        print_hex_memory(surb_and_payload, SURB_SIZE);
        printf("enc payload at node %d\n", i);
        print_hex_memory(&surb_and_payload[SURB_SIZE], PAYLOAD_SIZE);
        #endif /* DEBUG */
    }
    return;
}

int bulid_mix_path(struct network_node* path_nodes[], int path_len, ipv6_addr_t *start_addr, ipv6_addr_t *dest_addr)
{
    uint32_t random;
    char chosen[SPHINX_NET_SIZE] = {0};

    /* select random mix nodes */
    int i = 0;
    while (i < (path_len-1)) {
        random = random_uint32_range(0, SPHINX_NET_SIZE);

        if (chosen[random]) {
            continue;
        }

        if (ipv6_addr_equal(&network_pki[random].addr, start_addr) || ipv6_addr_equal(&network_pki[random].addr, dest_addr)) {
            chosen[random] = '1';
            continue;
        }

        path_nodes[i] = (struct network_node*) &network_pki[random];
        chosen[random] = '1';
        i++;
    }

    /* add final destination node */
    if ((path_nodes[i] = get_node(dest_addr)) == NULL) {
        puts("destination address not found in pki");
        return -1;
    }

    return 1;
}

int build_sphinx_surb(unsigned char *sphinx_surb, unsigned char *id, ipv6_addr_t *dest_addr, ipv6_addr_t *local_addr, unsigned char* public_key, unsigned char* secret_key)
{
    /* choose random number for path length */
    int path_len = random_uint32_range(3, SPHINX_MAX_PATH);

    /* builds a random path to the destination */
    if (bulid_mix_path(path_nodes, path_len, dest_addr, local_addr) < 0) {
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

int build_sphinx_header(unsigned char* sphinx_header, unsigned char* id, ipv6_addr_t* first_hop_addr, ipv6_addr_t* start_addr, ipv6_addr_t* dest_addr, unsigned char* public_key, unsigned char* secret_key)
{
    /* choose random number for path length to dest */
    int path_len_outward = random_uint32_range(3, SPHINX_MAX_PATH);

    #if DEBUG
    printf("path_len_outward = %d\n", path_len_outward);
    #endif /* DEBUG */

    /* builds a random path to the destination */
    if (bulid_mix_path(path_nodes, path_len_outward, start_addr, dest_addr) < 0) {
        puts("could not build mix path");
        return -1;
    }

    /* save address of first hop */
    memcpy(first_hop_addr, &path_nodes[0]->addr, ADDR_SIZE);

    /* precomputes the shared secrets with all nodes in path */
    calculate_shared_secrets(shared_secrets_send, path_nodes, path_len_outward, secret_key, public_key);

    #if DEBUG
    puts("shared secrets to dest");
    print_hex_memory(shared_secrets_send, KEY_SIZE * SPHINX_MAX_PATH);
    #endif /* DEBUG */

    /* calculates mac of plain text payload for authentication at destination and as message id */
    crypto_onetimeauth(id, &sphinx_header[HEADER_SIZE + SURB_SIZE], PAYLOAD_SIZE, shared_secrets_send[path_len_outward - 1]);

    #if DEBUG
    puts("MAC of plaintext Payload");
    print_hex_memory(id, MAC_SIZE);
    puts("plaintext payload");
    print_hex_memory(&sphinx_header[HEADER_SIZE + SURB_SIZE], PAYLOAD_SIZE);
    #endif /* DEBUG */

    /* precalculates the accumulated padding added at each hop */
    calculate_nodes_padding(&sphinx_header[KEY_SIZE + MAC_SIZE], shared_secrets_send, path_len_outward);

    #if DEBUG
    puts("sphinx header after node padding creation");
    print_hex_memory(sphinx_header, HEADER_SIZE);
    #endif /* DEBUG */

    /* calculates the nested encrypted routing information */
    encapsulate_routing_and_mac(&sphinx_header[KEY_SIZE], shared_secrets_send, path_len, id);

    return path_len_outward;
}


int sphinx_create_message(unsigned char* sphinx_message, ipv6_addr_t* dest_addr, char* data, size_t data_len)
{
    /* generic ecc public key of the sender (a0 in sphinx spec) */
    unsigned char public_key[KEY_SIZE];

    /* secret ecc key of the sender (x in sphinx spec) */
    unsigned char secret_key[KEY_SIZE];
    
    // irgendwann ganz global machen
    ipv6_addr_t local_addr;

    /* used to save address of first hop */
    ipv6_addr_t first_hop_addr;

    /* lenght of path to destination */
    int path_len_outward;

    /* mac of payload as message id */
    unsigned char id[MAC_SIZE];
    // was ist mit der integrity of the surb?

    /* local ipv6 addr */  // kann wenn die event sache ist wegrationalisiert werden
    get_local_ipv6_addr(&local_addr);

    /* generates an ephermal asymmetric key pair for the sender */
    crypto_box_keypair(public_key, secret_key);

    /* put public key for first hop in place */
    memcpy(sphinx_message, public_key, KEY_SIZE);

    /* put payload in place */
    memcpy(&sphinx_message[HEADER_SIZE + SURB_SIZE], data, data_len);
    memset(&sphinx_message[HEADER_SIZE + SURB_SIZE + data_len], 0, PAYLOAD_SIZE - data_len);

    path_len_outward = build_sphinx_header(sphinx_message, id, &first_hop_addr, &local_addr, dest_addr, public_key, secret_key);

    build_sphinx_surb(&sphinx_message[HEADER_SIZE], id, dest_addr, &local_addr, public_key, secret_key);

    encrypt_surb_and_payload(&sphinx_message[HEADER_SIZE], path_len_outward);

    /* change destination to first hop */
    memcpy(dest_addr, &first_hop_addr, ADDR_SIZE);

    //save_id(id);
    puts("sphinx: message sent with id");
    print_hex_memory(id, MAC_SIZE);

    #if DEBUG
    puts("Sphinx message");
    print_hex_memory(sphinx_message, SPHINX_MESSAGE_SIZE);
    #endif /* DEBUG */

    return 1;
}