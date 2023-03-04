#include "shpinx.h"

// überall unsigned weg machen

int bulid_mix_path(network_node* path_nodes[], int path_len, ipv6_addr_t *start_addr, ipv6_addr_t *dest_addr)
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

        path_nodes[i] = (network_node*) &network_pki[random];
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

void calculate_shared_secrets(unsigned char* sphinx_message, unsigned char shared_secrets[][KEY_SIZE], network_node* path_nodes[], int path_len)
{
    /* secret ecc key of the sender (x in sphinx spec) */
    unsigned char secret_key[KEY_SIZE];

    /* public keys for computing the shared secrets at each hop (a0, a1, ... in sphinx spec) */
    unsigned char public_keys[2*SPHINX_MAX_PATH][KEY_SIZE];

    /* blinding factors for each hop (b0, b1, ... in sphinx spec) */
    unsigned char blinding_factors[2*SPHINX_MAX_PATH][KEY_SIZE];

    /* used to store intermediate results */
    unsigned char buff_shared_secret[KEY_SIZE];

    /* generates an ephermal asymmetric key pair for the sender; public key for first hop is the generic public key of the sender */
    crypto_box_keypair(public_keys[0], secret_key);

    /* put public key for first hop in message */
    memcpy(sphinx_message, public_keys[0], KEY_SIZE);

    /* prepare root for calculation of public keys, shared secrets and blinding factors */

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

    #if DEBUG
    puts("DEBUG: public keys");
    print_hex_memory(public_keys, path_len*KEY_SIZE);
    #endif /* DEBUG */

    return;
}

void calculate_nodes_padding(unsigned char* nodes_padding, unsigned char shared_secrets[][KEY_SIZE], int path_len)
{
    unsigned int padding_size = 0;

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
    }

    /* cutt off last node padding to move nodes padding in place for encapsulation of routing and mac */
    memmove(&nodes_padding[MAX_NODES_PADDING - ((path_len - 1) * NODE_ROUT_SIZE)], &nodes_padding[MAX_NODES_PADDING - ((path_len) * NODE_ROUT_SIZE)], (path_len - 1) * NODE_ROUT_SIZE);
    
    return;
}

void encapsulate_routing_and_mac(unsigned char* routing_and_mac, unsigned char shared_secrets[][KEY_SIZE], network_node* path_nodes[], int path_len, unsigned char* id)
{
    /* padding to keep header size invariant regardless of actual path length */
    int header_padding_size = (SPHINX_MAX_PATH - path_len) * NODE_ROUT_SIZE;

    /* prepare root routing information for iteration */
    memcpy(&routing_and_mac[MAC_SIZE], &path_nodes[path_len-1]->addr, ADDR_SIZE);
    memcpy(&routing_and_mac[MAC_SIZE + ADDR_SIZE], id, MAC_SIZE);
    random_bytes(&routing_and_mac[MAC_SIZE + ADDR_SIZE + MAC_SIZE], header_padding_size);

    for (int i=path_len-1; i>=0; i--) {

        #if DEBUG
        printf("DEBUG: decrypted Routing Inforation at Node %d\n", i);
        print_hex_memory(&routing_and_mac[MAC_SIZE], ENC_ROUTING_SIZE);
        #endif /* DEBUG */

        /* calculate pseudo random byte stream with shared secret */
        crypto_stream(prg_stream, ENC_ROUTING_SIZE, nonce, shared_secrets[i]);

        /* xor routing information for node i with prg stream */
        xor_backwards_inplace(&routing_and_mac[MAC_SIZE], ENC_ROUTING_SIZE, prg_stream, ENC_ROUTING_SIZE, ENC_ROUTING_SIZE);

        /* calculate mac of encrypted routng information */
        crypto_onetimeauth(routing_and_mac, &routing_and_mac[MAC_SIZE], ENC_ROUTING_SIZE, shared_secrets[i]);

        #if DEBUG
        printf("DEBUG: MAC of enrypted routing at Node %d\n", i);
        print_hex_memory(routing_and_mac, MAC_SIZE);
        printf("DEBUG: encrypted Routing Inforamtion at Node %d\n", i);
        print_hex_memory(&routing_and_mac[MAC_SIZE], ENC_ROUTING_SIZE);
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

void encrypt_surb_and_payload(unsigned char* surb_and_payload, unsigned char shared_secrets[][KEY_SIZE], int path_len)
{
    for (int i=path_len-1; i>=0; i--) {

        crypto_stream(prg_stream, PRG_STREAM_SIZE, nonce, shared_secrets[i]);

        xor_backwards_inplace(surb_and_payload, SURB_SIZE + PAYLOAD_SIZE, prg_stream, PRG_STREAM_SIZE, SURB_SIZE + PAYLOAD_SIZE);
    }

    return;
}

void build_sphinx_surb(unsigned char *sphinx_surb, unsigned char shared_secrets[][KEY_SIZE], unsigned char *id, network_node* path_nodes[], int path_len_reply)
{
    #if DEBUG
    puts("DEBUG: SURB CREATION\n");
    #endif /* DEBUG */

    /* save address of first hop to surb */
    memcpy(sphinx_surb, &path_nodes[0]->addr, ADDR_SIZE);

    /* precalculates the accumulated padding added at each hop */
    calculate_nodes_padding(&sphinx_surb[ADDR_SIZE + MAC_SIZE], shared_secrets, path_len_reply);

    /* calculates the nested encrypted routing information */
    encapsulate_routing_and_mac(&sphinx_surb[ADDR_SIZE], shared_secrets, path_nodes, path_len_reply, id);

    return;
}

void build_sphinx_header(unsigned char* sphinx_header, unsigned char shared_secrets[][KEY_SIZE], unsigned char* id, network_node* path_nodes[], int path_len_dest)
{
    #if DEBUG
    puts("DEBUG: HEADER CREATION\n");
    #endif /* DEBUG */

    /* calculates mac of plain text payload for authentication at destination and as message id */
    crypto_onetimeauth(id, &sphinx_header[HEADER_SIZE + SURB_SIZE], PAYLOAD_SIZE, shared_secrets[path_len_dest - 1]);
    /* precalculates the accumulated padding added at each hop */
    calculate_nodes_padding(&sphinx_header[KEY_SIZE + MAC_SIZE], shared_secrets, path_len_dest);
    /* calculates the nested encrypted routing information */
    encapsulate_routing_and_mac(&sphinx_header[KEY_SIZE], shared_secrets, path_nodes, path_len_dest, id);

    return;
}


int sphinx_create_message(unsigned char* sphinx_message, ipv6_addr_t* dest_addr, char* data, size_t data_len)
{
    /* network path for sphinx message to destination and reply */
    network_node* path_nodes[2*SPHINX_MAX_PATH];

    /* shared secrets with nodes in path */
    unsigned char shared_secrets[2*SPHINX_MAX_PATH][KEY_SIZE];

    /* mac of payload as message id */
    unsigned char id[MAC_SIZE];
    // was ist mit der integrity of the surb?

    // irgendwann ganz global machen
    ipv6_addr_t local_addr;
    /* local ipv6 addr */  // kann wenn die event sache ist wegrationalisiert werden
    get_local_ipv6_addr(&local_addr);

    /* choose random number for path length to dest */
    int path_len_dest = random_uint32_range(3, SPHINX_MAX_PATH+1);

    /* choose random number for path length of reply */
    int path_len_reply = random_uint32_range(3, SPHINX_MAX_PATH+1);

    #if DEBUG
    printf("DEBUG: path_len_dest=%d\n\n", path_len_dest);
    printf("DEBUG: path_len_reply=%d\n\n", path_len_reply);
    #endif /* DEBUG */

    /* builds a random path to the destination and back */
    if ((bulid_mix_path(path_nodes, path_len_dest, &local_addr, dest_addr) < 0) ||
        (bulid_mix_path(&path_nodes[path_len_dest], path_len_reply, dest_addr, &local_addr)) < 0) {
        puts("error: could not build mix path");
        return -1;
    }

    /* precomputes the shared secrets with all nodes in path */
    calculate_shared_secrets(sphinx_message, shared_secrets, path_nodes, path_len_dest+path_len_reply);

    #if DEBUG
    puts("DEBUG: shared secrets");
    print_hex_memory(shared_secrets, KEY_SIZE*(path_len_dest+path_len_reply));
    #endif /* DEBUG */

    /* put payload in place */
    memcpy(&sphinx_message[HEADER_SIZE + SURB_SIZE], data, data_len);
    memset(&sphinx_message[HEADER_SIZE + SURB_SIZE + data_len], 0, PAYLOAD_SIZE - data_len);

    build_sphinx_header(sphinx_message, shared_secrets, id, path_nodes, path_len_dest);

    build_sphinx_surb(&sphinx_message[HEADER_SIZE], &shared_secrets[path_len_dest], id, &path_nodes[path_len_dest], path_len_reply);

    encrypt_surb_and_payload(&sphinx_message[HEADER_SIZE], shared_secrets, path_len_dest);

    #if DEBUG
    puts("DEBUG: sphinx message");
    print_hex_memory(sphinx_message, SPHINX_MESSAGE_SIZE);
    #endif /* DEBUG */

    /* change destination to first hop */
    memcpy(dest_addr, &path_nodes[0]->addr, ADDR_SIZE);

    //save_id(id);
    puts("sphinx: message sent with id");
    print_hex_memory(id, MAC_SIZE);

    return 1;
}