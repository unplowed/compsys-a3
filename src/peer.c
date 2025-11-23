#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>

#ifdef __APPLE__
#include "./endian.h"
#else
#include <endian.h>
#endif

#include "./peer.h"


// Global variables to be used by both the server and client side of the peer.
// Note the addition of mutexs to prevent race conditions.
NetworkAddress_t *my_address;
NetworkAddress_t** network = NULL;
uint32_t peer_count = 0;
pthread_mutex_t network_mutex = PTHREAD_MUTEX_INITIALIZER;

char currently_retrieving[10][PATH_LEN];
int retrieving_count = 0;
pthread_mutex_t retrieving_mutex = PTHREAD_MUTEX_INITIALIZER;

int c; // Used for input clearing

/* =======================
Struct for storing P2P Server
*/

typedef struct peer_response
{
    uint32_t length; // Length of payload
    uint32_t status; // Status code of the response
    uint32_t block_num; // Current block number
    uint32_t total_blocks; // Total number of blocks
    uint8_t *payload; // Pointer to the payload data
    uint8_t *block_hash; // Hash of the current block
    uint8_t *total_hash; // Hash of the total data.
} peer_response_t;

/*
 * Function to act as thread for all required client interactions. This thread 
 * will be run concurrently with the server_thread. It will start by requesting
 * the IP and port for another peer to connect to. Once both have been provided
 * the thread will register with that peer and expect a response outlining the
 * complete network. The user will then be prompted to provide a file path to
 * retrieve. This file request will be sent to a random peer on the network.
 * This request/retrieve interaction is then repeated forever.
 */ 

/*
=============================================================================
*  UTIL FUNCTIONS
============================================================================= 
*/


uint32_t network_to_host(uint8_t *bytes) 
{
    uint32_t value;
    memcpy(&value, bytes, sizeof(uint32_t));
    return ntohl(value);

}

void init_peer_response(peer_response_t *resp, uint8_t *buffer) 
{
    size_t offset = 0;

    resp->length = network_to_host(buffer + offset);
    offset += sizeof(uint32_t);

    resp->status = network_to_host(buffer + offset);
    offset += sizeof(uint32_t);

    resp->block_num = network_to_host(buffer + offset);
    offset += sizeof(uint32_t);

    resp->total_blocks = network_to_host(buffer + offset);
    offset += sizeof(uint32_t);

    resp->block_hash = malloc(SHA256_HASH_SIZE);
    memcpy(resp->block_hash, buffer + offset, SHA256_HASH_SIZE);
    offset += SHA256_HASH_SIZE;

    resp->total_hash = malloc(SHA256_HASH_SIZE);
    memcpy(resp->total_hash, buffer + offset, SHA256_HASH_SIZE);
    offset += SHA256_HASH_SIZE;

    if (resp->length > 0) 
    {
        resp->payload = malloc(resp->length);
        if(!resp->payload) 
        {
            fprintf(stderr, "Failed to allocate memory for payload\n");
            exit(EXIT_FAILURE);

        }
    }

}

void free_peer_response(peer_response_t *resp)
{
    if(resp->payload)
    {
        free(resp->payload);
        resp->payload = NULL;
    }

    if(resp->block_hash)
    {
        free(resp->block_hash);
        resp->block_hash = NULL;
    }

    if(resp->total_hash) 
    {
        free(resp->total_hash);
        resp->total_hash = NULL;
    }
}

/*
 * Signature generation: password + salt -> SHA256 hash
 */

 void get_signature (char *password, char *salt, hashdata_t *hash)
 {
    size_t password_len = strlen(password);
    size_t salt_len = strlen(salt);
    size_t combined_len = password_len + salt_len;

    char *combined = malloc(combined_len);
    if (combined == NULL) 
    {
        fprintf(stderr, "Memory allocation failed in get_signature\n");
        exit(EXIT_FAILURE);
    }

    memcpy(combined, password, password_len);
    memcpy(combined + password_len, salt, salt_len);

    get_data_sha(combined, *hash, combined_len, SHA256_HASH_SIZE);

    // Security measure -> Clear sensitive data.
    memset(combined, 0, combined_len);
    free(combined);
 }

 // Checking file existance using fopen
 int check_file_exists_and_get_size(const char* filepath, long* size)
 {
    FILE* fp = fopen(filepath, "rb");

    if(!fp) 
    {
        return 0;
    }

    fseek(fp, 0, SEEK_END);
    *size = ftell(fp);
    fclose(fp);

    return 1;
 }

/*
=============================================================================
*  NETWORK MANAGEMENT FUNCTIONALITY
============================================================================= 
*/

void add_peer_to_network(char* ip, uint32_t port, hashdata_t signature, char* salt) 
{
    network = realloc(network, sizeof(NetworkAddress_t*) * (peer_count +1));
    network[peer_count] = malloc(sizeof(NetworkAddress_t));

    memset(network[peer_count]->ip, 0, IP_LEN);
    strncpy(network[peer_count]->ip, ip, IP_LEN -1);
    network[peer_count]->port = port;
    memcpy(network[peer_count]->signature, signature, SHA256_HASH_SIZE);
    memcpy(network[peer_count]->salt, salt, SALT_LEN);

    peer_count++;
}

int find_peer_in_network(char* ip, uint32_t port, NetworkAddress_t** found_peer)
{
    for(uint32_t i = 0; i < peer_count; i++) 
    {
        if(strcmp(network[i]->ip, ip) == 0 && network[i]->port == port)
        {
            if(found_peer) *found_peer = network[i];
            return 1;
        }
    }
    return 0;
}

void get_random_peer(char* ip, uint32_t* port) 
{
    pthread_mutex_lock(&network_mutex);

    uint32_t count = 0;
    for (uint32_t i = 0; i < peer_count; i++) 
    {
        if(strcmp(network[i]->ip, my_address->ip) != 0 ||
        network[i]->port != my_address->port)
        {
            count++;

        }
    }

    if(count==0) 
    {
        pthread_mutex_unlock(&network_mutex);
        return;
    }

    uint32_t choice = rand() % count;
    uint32_t current = 0;

    for (uint32_t i = 0; i < peer_count; i++)
    {
        if(strcmp(network[i]->ip, my_address->ip) != 0 ||
        network[i]->port != my_address->port) 
        {
            if(current == choice)
            {
                strncpy(ip, network[i]->ip, IP_LEN);
                *port = network[i]->port;
                break;
            }
            current++;
        }
    }
    pthread_mutex_unlock(&network_mutex);

}

int is_file_being_retrieved(char* filepath) 
{
    pthread_mutex_lock(&retrieving_mutex);
    for(int i = 0; i < retrieving_count; i++)
    {
        if(strcmp(currently_retrieving[i], filepath) == 0) 
        {
            pthread_mutex_unlock(&retrieving_mutex);
            return 1;
        }
    }
    pthread_mutex_unlock(&retrieving_mutex);
    return 0;
}

void add_to_retrieving_list(char* filepath)
{
    pthread_mutex_lock(&retrieving_mutex);
    if(retrieving_count < 10)
    {
        strncpy(currently_retrieving[retrieving_count], filepath, PATH_LEN - 1);
        retrieving_count++;
    }
    pthread_mutex_unlock(&retrieving_mutex);
}

void remove_from_retrieving_list(char* filepath)
{
    pthread_mutex_lock(&retrieving_mutex);

    for(int i=0; i<retrieving_count; i++)
    {
        if(strcmp(currently_retrieving[i], filepath) == 0)
        {
            for(int j=i; j<retrieving_count-1; j++)
            {
                strcpy(currently_retrieving[j], currently_retrieving[j+1]);
            }
            retrieving_count--;
            break;
        }
    }
    pthread_mutex_unlock(&retrieving_mutex);
}

/* =============================================================
 * CLIENT-SIDE: SENDING REQUEST
 * Protocol: "No persistent connections --> each request gets response then closes"
 * ===========================================================/
*/

/*
* COMMAND 1: REGISTER
* Requests header only (no body) 
* Response --> List of all known peers (68 Bytes each)
 */

 void register_with_peer(char *peer_ip, int peer_port, char *password, char *salt)
 {
    hashdata_t signature;
    get_signature(password, salt, &signature);

    // DEBUG 
    printf("DEBUG REGISTER:\n");
    printf("  password='%s'\n", password);
    printf("  salt='%s'\n", salt);
    printf("  signature bytes: %02x %02x %02x %02x...\n", 
    (unsigned char)signature[0], (unsigned char)signature[1], 
    (unsigned char)signature[2], (unsigned char)signature[3]);

    printf("Connecting to server at %s:%d\n", peer_ip, peer_port);

    char port_str[PORT_STR_LEN];
    snprintf(port_str, PORT_STR_LEN, "%d", peer_port);

    int peer_fd = compsys_helper_open_clientfd(peer_ip, port_str);
    if(peer_fd < 0) 
    {
        fprintf(stderr, "Failed to connect to peer\n");
        return;
    }

    /* 
    * Build REQUETS per protocol specifications:
    * 16 bytes IP + 4 bytes port + 32 bytes signature + 4 bytes command + 4 bytes length
    */

    uint8_t message[REQUEST_HEADER_LEN];
    memset(message, 0, REQUEST_HEADER_LEN);

    // 16 bytes: IP as UTF-8
    strncpy((char*)message, my_address->ip, IP_LEN);

    // 4 bytes: Port in network byte-order
    uint32_t net_port = htonl(my_address->port);
    memcpy(message + IP_LEN, &net_port, PORT_LEN);

    // 32 bytes: Signature (salted and hashed password)
    memcpy(message + IP_LEN + PORT_LEN, signature, SHA256_HASH_SIZE);

    // 4 bytes: Command code = 1 --> (REGISTER)
    uint32_t net_command = htonl(COMMAND_REGISTER);
    memcpy(message + IP_LEN + PORT_LEN + SHA256_HASH_SIZE, &net_command, 4);

    // 4 bytes: Length = 0 --> (No body for register)
    uint32_t net_length = htonl(0);
    memcpy(message + IP_LEN + PORT_LEN + SHA256_HASH_SIZE + 4, &net_length, 4);

    compsys_helper_writen(peer_fd, message, REQUEST_HEADER_LEN);

    // Read response per protocol
    compsys_helper_state_t state;
    compsys_helper_readinitb(&state, peer_fd);

    uint8_t response_buffer[REPLY_HEADER_LEN];
    ssize_t n = compsys_helper_readnb(&state, response_buffer, REPLY_HEADER_LEN);
    if (n != REPLY_HEADER_LEN) 
    {
        fprintf(stderr, "Failed to read response header\n");
        close(peer_fd);
        return;
    }

    peer_response_t response;
    init_peer_response(&response, response_buffer);

    if (response.length > 0)
    {
        n = compsys_helper_readnb(&state, response.payload, response.length);
        if (n != response.length) 
        {
            fprintf(stderr, "Failed to read response payload\n");
            free_peer_response(&response);
            close(peer_fd);
            return;
        }
    }

    // Process --> REGISTER response: Liste of all peers (68 bytes each)
    
    if(response.status == STATUS_OK && response. payload) 
    {
        pthread_mutex_lock(&network_mutex);

        // Each peer entry --> 68 bytes (per protocol specification)
        uint32_t offset = 0;
        while (offset + PEER_ADDR_LEN <= response.length) 
        {
            // 16 bytes: IP
            char ip[IP_LEN];
            memcpy(ip, response.payload + offset, IP_LEN);
            ip[IP_LEN-1] = '\0';

            // 4 bytes: Port
            uint32_t port;
            memcpy(&port, response.payload + offset + IP_LEN, 4);
            port = ntohl(port);

            // 32 bytes: Peer-saved signature (hashed and salted)
            hashdata_t peer_signature;
            memcpy(peer_signature, response.payload + offset + IP_LEN + 4, SHA256_HASH_SIZE);

            // 16 bytes: Salt
            char peer_salt[SALT_LEN + 1];
            memcpy(peer_salt, response.payload + offset + IP_LEN + 4 + SHA256_HASH_SIZE, SALT_LEN);
            peer_salt[SALT_LEN] = '\0';

            // Updating our signature if its us
            if (strcmp(ip, my_address->ip) == 0 && port == my_address->port) 
            {
                memcpy(my_address->signature, peer_signature, SHA256_HASH_SIZE);
            }

            // Avoiding duplicates
            NetworkAddress_t* existing = NULL;
            if (!find_peer_in_network(ip, port, &existing)) 
            {
                add_peer_to_network(ip, port, peer_signature, peer_salt);
            }

            offset += PEER_ADDR_LEN;
        }

        printf("Connected peer networks: ");
        for(uint32_t i = 0; i < peer_count; i++)
        {
            printf("%s:%d%s", network[i]->ip, network[i]->port, (i < peer_count -1) ? ", " :"\n");
        }

        pthread_mutex_unlock(&network_mutex);
        }else{
            printf("Registration failed with status %d\n", response.status);
            if (response.payload)
            {
                printf("Error: %.*s\n", (int)response.length, response.payload);
            }
    }

    free_peer_response(&response);
    close(peer_fd); // Closing connecting after response

    printf("Completed server interaction, %d with status %d\n",
    COMMAND_REGISTER, response.status);

 }

typedef struct block
{
    uint32_t length; // Length of payload
    void* data;
} block_t;

/*
 * COMMAND 2: RETRIEVE
 * Request body: filename/filepath
 * Response: File data (may be multi-block if large)
 * Protocol: "Messages limited to 8196 bytes including header and body"
 */
void get_file_from_peer(char *peer_ip, int peer_port, char *to_get){
    // Regenerate signature from password to match Python's buggy verification
    hashdata_t signature;
    get_signature(my_address->password, my_address->original_salt, &signature);

    // DEBUG - 
    printf("DEBUG RETRIEVE:\n");
    printf("  password='%s'\n", my_address->password);
    printf("  original_salt='%s'\n", my_address->original_salt);
    printf("  signature bytes: %02x %02x %02x %02x...\n", 
    (unsigned char)signature[0], (unsigned char)signature[1], 
    (unsigned char)signature[2], (unsigned char)signature[3]);

    printf("Connecting to server at %s:%d\n", peer_ip, peer_port);

    add_to_retrieving_list(to_get);

    char port_str[PORT_STR_LEN];
    snprintf(port_str, PORT_STR_LEN, "%d", peer_port);
    
    int peer_fd = compsys_helper_open_clientfd(peer_ip, port_str);
    if (peer_fd < 0) {
        fprintf(stderr, "Failed to connect to peer\n");
        remove_from_retrieving_list(to_get);
        return;
    }

    // Build REQUEST per protocol
    uint32_t filepath_len = strlen(to_get);
    uint32_t message_len = REQUEST_HEADER_LEN + filepath_len;
    uint8_t* message = malloc(message_len);
    memset(message, 0, message_len);

    strncpy((char*)message, my_address->ip, IP_LEN);

    uint32_t net_port = htonl(my_address->port);
    memcpy(message + IP_LEN, &net_port, PORT_LEN);

    memcpy(message + IP_LEN + PORT_LEN, signature, SHA256_HASH_SIZE);

    // Command = 2 (RETRIEVE)
    uint32_t net_command = htonl(COMMAND_RETREIVE);
    memcpy(message + IP_LEN + PORT_LEN + SHA256_HASH_SIZE, &net_command, 4);

    // Length = filepath length
    uint32_t net_length = htonl(filepath_len);
    memcpy(message + IP_LEN + PORT_LEN + SHA256_HASH_SIZE + 4, &net_length, 4);

    // Body = filepath
    memcpy(message + REQUEST_HEADER_LEN, to_get, filepath_len);

    compsys_helper_writen(peer_fd, message, message_len);
    free(message);

    // Read RESPONSE (may be multi-block)
    compsys_helper_state_t state;
    compsys_helper_readinitb(&state, peer_fd);

    // Per protocol: "Files served/written relative to peer's directory"
    FILE *fp = fopen(to_get, "wb");
    if (fp == NULL) {
        fprintf(stderr, "Failed to open file for writing: %s\n", to_get);
        close(peer_fd);
        remove_from_retrieving_list(to_get);
        return;
    }

    size_t total_size = 0;
    hashdata_t expected_total_hash;
    int first_block = 1;
    int success = 1;
    int blocks_recieved = 0;
    block_t* data;

    // Multi-block receiving loop
    while (1) {
        uint8_t response_buffer[REPLY_HEADER_LEN];
        ssize_t n = compsys_helper_readnb(&state, response_buffer, REPLY_HEADER_LEN);
        if (n != REPLY_HEADER_LEN) {
            fprintf(stderr, "Failed to read response header\n");
            success = 0;
            break;
        }

        peer_response_t response;
        init_peer_response(&response, response_buffer);

        // Check status codes per protocol
        if (response.status != STATUS_OK) {
            if (response.length > 0) {
                n = compsys_helper_readnb(&state, response.payload, response.length);
                if (n == response.length) {
                    printf("Error from peer: %.*s\n", (int)response.length, response.payload);
                }
            }
            free_peer_response(&response);
            success = 0;
            break;
        }

        // Per protocol: "total hash is hash of total data across all blocks"
        if (first_block) {
            memcpy(expected_total_hash, response.total_hash, SHA256_HASH_SIZE);
            data = malloc(sizeof(block_t) * response.total_blocks);
            first_block = 0;
        }

        if (response.length > 0) {
            n = compsys_helper_readnb(&state, response.payload, response.length);
            if (n != response.length) {
                fprintf(stderr, "Failed to read data block\n");
                free_peer_response(&response);
                success = 0;
                break;
            }

            // Per protocol: "block hash is hash of response data in this message only"
            hashdata_t block_hash;
            get_data_sha((char*)response.payload, block_hash, response.length, SHA256_HASH_SIZE);
            if (memcmp(block_hash, response.block_hash, SHA256_HASH_SIZE) != 0) {
                fprintf(stderr, "Block %u hash mismatch\n", response.block_num);
                free_peer_response(&response);
                success = 0;
                break;
            }

            fprintf(stdout, "DEBUG\n");
            fprintf(stdout, "Recieved block %i/%i (%i bytes)\n", response.block_num, response.total_blocks, response.length);

            // fwrite(response.payload, 1, response.length, fp);
            block_t block;
            block.length = response.length;
            block.data = malloc(response.length);
            memcpy(block.data, response.payload, response.length);
            data[response.block_num] = block;
            total_size += response.length;
            blocks_recieved++;
        }

        // Check if all blocks recieved
        if (blocks_recieved == response.total_blocks) {
            free_peer_response(&response);
            break;
        }

        free_peer_response(&response);
    }

    // write data in order
    for (int i = 0; i < blocks_recieved; i++) {
      fwrite(data[i].data, 1, data[i].length, fp);
      free(data[i].data);
    }
    free(data);

    fclose(fp);
    close(peer_fd); // Protocol: close connection after response

    if (success) {
        // Verify total file hash per protocol
        hashdata_t file_hash;
        get_file_sha(to_get, file_hash, SHA256_HASH_SIZE);
        if (memcmp(file_hash, expected_total_hash, SHA256_HASH_SIZE) != 0) {
            fprintf(stderr, "Total file hash mismatch\n");
            fprintf(stderr, "Exp: ");
            for (size_t i = 0; i < SHA256_HASH_SIZE; i++) {
              fprintf(stderr, "%02x", (unsigned char)expected_total_hash[i]);
            }
            fprintf(stderr, "\nGot: ");
            for (size_t i = 0; i < SHA256_HASH_SIZE; i++) {
              fprintf(stderr, "%02x", (unsigned char)file_hash[i]);
            }
            fprintf(stderr, "\n");
            remove(to_get);
        } else {
            printf("File '%s' received successfully (%zu bytes)\n", to_get, total_size);
        }
    } else {
        remove(to_get);
    }

    remove_from_retrieving_list(to_get);
    printf("Completed server interaction code %d with status %d\n", 
           COMMAND_RETREIVE, success ? STATUS_OK : STATUS_OTHER);
}

/* ============================================================================
 * SERVER-SIDE: HANDLING REQUESTS AND SENDING RESPONSES
 * ============================================================================ */

/*
 * Send a reply per protocol specification
 * Protocol: "Messages limited to 8196 bytes total"
 */
void send_reply(int connfd, uint32_t status, uint8_t* data, uint32_t data_len) {
    // Per protocol: 8196 byte limit includes header (80 bytes)
    uint32_t max_payload = MAX_MSG_LEN - REPLY_HEADER_LEN;
    uint32_t block_count = (data_len + max_payload - 1) / max_payload;
    if (data_len == 0) block_count = 1;

    // Per protocol: "total hash is hash of total data to be sent across all blocks"
    hashdata_t total_hash;
    if (data_len > 0) {
        get_data_sha((char*)data, total_hash, data_len, SHA256_HASH_SIZE);
    } else {
        memset(total_hash, 0, SHA256_HASH_SIZE);
    }

    for (uint32_t block_idx = 0; block_idx < block_count; block_idx++) {
        uint32_t block_start = block_idx * max_payload;
        uint32_t block_size = (block_start + max_payload <= data_len) ? 
                              max_payload : (data_len - block_start);
        
        if (data_len == 0) block_size = 0;

        // Per protocol: "block hash is hash of response data in this message only"
        hashdata_t block_hash;
        if (block_size > 0) {
            get_data_sha((char*)(data + block_start), block_hash, block_size, SHA256_HASH_SIZE);
        } else {
            memset(block_hash, 0, SHA256_HASH_SIZE);
        }

        // Build RESPONSE per protocol specification
        uint8_t reply[REPLY_HEADER_LEN + max_payload];
        uint32_t offset = 0;

        // 4 bytes: Length in network byte-order
        uint32_t net_length = htonl(block_size);
        memcpy(reply + offset, &net_length, 4);
        offset += 4;

        // 4 bytes: Status code in network byte-order
        uint32_t net_status = htonl(status);
        memcpy(reply + offset, &net_status, 4);
        offset += 4;

        // 4 bytes: Block number (zero-based)
        uint32_t net_this_block = htonl(block_idx);
        memcpy(reply + offset, &net_this_block, 4);
        offset += 4;

        // 4 bytes: Total block count
        uint32_t net_block_count = htonl(block_count);
        memcpy(reply + offset, &net_block_count, 4);
        offset += 4;

        // 32 bytes: Block hash
        memcpy(reply + offset, block_hash, SHA256_HASH_SIZE);
        offset += SHA256_HASH_SIZE;

        // 32 bytes: Total hash
        memcpy(reply + offset, total_hash, SHA256_HASH_SIZE);
        offset += SHA256_HASH_SIZE;

        // Payload
        if (block_size > 0) {
            memcpy(reply + offset, data + block_start, block_size);
            offset += block_size;
        }

        printf("Sending reply %d/%d with payload length of %d bytes\n",
               block_idx + 1, block_count, block_size);

        compsys_helper_writen(connfd, reply, offset);
    }
}

/*
 * Handle COMMAND 1: REGISTER
 * Per protocol: "randomly generate a salt" for new peer
 * Response: List of all known peers
 */
void handle_register_request(int connfd, char* ip, uint32_t port, hashdata_t signature) {
    NetworkAddress_t* existing = NULL;
    pthread_mutex_lock(&network_mutex);
    
    if (find_peer_in_network(ip, port, &existing)) {
        pthread_mutex_unlock(&network_mutex);
        // Status code 2: Peer already exists
        char* error = "Peer already exists";
        send_reply(connfd, STATUS_PEER_EXISTS, (uint8_t*)error, strlen(error));
        return;
    }

    // Per protocol: "first peer to handle registering will randomly generate a salt"
    // Special case: if we're the initial peer, set up our own saved signature
    if (peer_count == 1 && my_address->salt[0] == '0') {
        char new_salt[SALT_LEN + 1];
        generate_random_salt(new_salt);
        memcpy(my_address->salt, new_salt, SALT_LEN);
        
        // Per protocol: "signature is salted and hashed again to form final saved signature"
        char combined[SHA256_HASH_SIZE + SALT_LEN];
        memcpy(combined, my_address->signature, SHA256_HASH_SIZE);
        memcpy(combined + SHA256_HASH_SIZE, new_salt, SALT_LEN);
        hashdata_t new_sig;
        get_data_sha(combined, new_sig, SHA256_HASH_SIZE + SALT_LEN, SHA256_HASH_SIZE);
        memcpy(network[0]->signature, new_sig, SHA256_HASH_SIZE);
        memcpy(network[0]->salt, new_salt, SALT_LEN);
    }

    // Generate random salt for new peer per protocol
    char new_salt[SALT_LEN + 1];
    generate_random_salt(new_salt);
    
    // Per protocol: "salt and hash signature again to form saved signature"
    char combined[SHA256_HASH_SIZE + SALT_LEN];
    memcpy(combined, signature, SHA256_HASH_SIZE);
    memcpy(combined + SHA256_HASH_SIZE, new_salt, SALT_LEN);
    hashdata_t salted_sig;
    get_data_sha(combined, salted_sig, SHA256_HASH_SIZE + SALT_LEN, SHA256_HASH_SIZE);

    add_peer_to_network(ip, port, salted_sig, new_salt);

    // Build response: list of all known peers (68 bytes each per protocol)
    uint32_t response_size = peer_count * PEER_ADDR_LEN;
    uint8_t* response = malloc(response_size);
    uint32_t offset = 0;

    for (uint32_t i = 0; i < peer_count; i++) {
        // 16 bytes: IP as UTF-8
        memset(response + offset, 0, IP_LEN);
        strncpy((char*)(response + offset), network[i]->ip, IP_LEN);
        offset += IP_LEN;

        // 4 bytes: Port in network byte-order
        uint32_t net_port = htonl(network[i]->port);
        memcpy(response + offset, &net_port, 4);
        offset += 4;

        // 32 bytes: Peer-saved signature (salted and hashed)
        memcpy(response + offset, network[i]->signature, SHA256_HASH_SIZE);
        offset += SHA256_HASH_SIZE;

        // 16 bytes: Salt
        memcpy(response + offset, network[i]->salt, SALT_LEN);
        offset += SALT_LEN;
    }

    pthread_mutex_unlock(&network_mutex);

    // Status code 1: OK
    send_reply(connfd, STATUS_OK, response, response_size);
    free(response);

    printf("Registered new peer %s:%d\n", ip, port);
    printf("Network is: ");
    pthread_mutex_lock(&network_mutex);
    for (uint32_t i = 0; i < peer_count; i++) {
        printf("%s:%d%s", network[i]->ip, network[i]->port,
               (i < peer_count - 1) ? ", " : "\n");
    }
    pthread_mutex_unlock(&network_mutex);

    // Per protocol: inform other peers using COMMAND 3
    NetworkAddress_t* new_peer = network[peer_count - 1];
    
    pthread_mutex_lock(&network_mutex);
    for (uint32_t i = 0; i < peer_count; i++) {
        if (strcmp(network[i]->ip, my_address->ip) == 0 && 
            network[i]->port == my_address->port) {
            continue;
        }
        if (strcmp(network[i]->ip, new_peer->ip) == 0 && 
            network[i]->port == new_peer->port) {
            continue;
        }

        // Send COMMAND 3: INFORM to each other peer
        char port_str[PORT_STR_LEN];
        snprintf(port_str, PORT_STR_LEN, "%d", network[i]->port);

        int sockfd = compsys_helper_open_clientfd(network[i]->ip, port_str);
        if (sockfd < 0) continue;

        uint8_t message[REQUEST_HEADER_LEN + PEER_ADDR_LEN];
        memset(message, 0, sizeof(message));

        // Request header
        strncpy((char*)message, my_address->ip, IP_LEN);
        uint32_t net_port = htonl(my_address->port);
        memcpy(message + IP_LEN, &net_port, 4);
        memcpy(message + IP_LEN + 4, my_address->signature, SHA256_HASH_SIZE);
        uint32_t net_command = htonl(COMMAND_INFORM);
        memcpy(message + IP_LEN + 4 + SHA256_HASH_SIZE, &net_command, 4);
        uint32_t net_length = htonl(PEER_ADDR_LEN);
        memcpy(message + IP_LEN + 4 + SHA256_HASH_SIZE + 4, &net_length, 4);

        // Request body: 68 bytes per protocol (IP + port + signature + salt)
        uint32_t msg_offset = REQUEST_HEADER_LEN;
        memset(message + msg_offset, 0, IP_LEN);
        strncpy((char*)(message + msg_offset), new_peer->ip, IP_LEN);
        msg_offset += IP_LEN;
        
        net_port = htonl(new_peer->port);
        memcpy(message + msg_offset, &net_port, 4);
        msg_offset += 4;
        
        memcpy(message + msg_offset, new_peer->signature, SHA256_HASH_SIZE);
        msg_offset += SHA256_HASH_SIZE;
        
        memcpy(message + msg_offset, new_peer->salt, SALT_LEN);

        compsys_helper_writen(sockfd, message, REQUEST_HEADER_LEN + PEER_ADDR_LEN);
        // Per protocol: "ONLY in case of inform do we not expect a reply"
        close(sockfd);
    }
    pthread_mutex_unlock(&network_mutex);
}

/*
 * Handle COMMAND 2: RETRIEVE
 * Per protocol: Check peer is registered and signature matches
 * Per protocol: "files served relative to peer's directory"
 * Response: File data or error message
 */
void handle_retrieve_request(int connfd, char* ip, uint32_t port, 
                             hashdata_t signature, uint8_t* payload, uint32_t payload_len) {
    NetworkAddress_t* peer = NULL;
    pthread_mutex_lock(&network_mutex);
    
    if (!find_peer_in_network(ip, port, &peer)) {
        pthread_mutex_unlock(&network_mutex);
        // Status code 3: Peer is missing
        char* error = "Peer not registered";
        send_reply(connfd, STATUS_PEER_MISSING, (uint8_t*)error, strlen(error));
        return;
    }

    // Per protocol: "provided signature must match one from registration"
    // Re-derive saved signature to compare
    char combined[SHA256_HASH_SIZE + SALT_LEN];
    memcpy(combined, signature, SHA256_HASH_SIZE);
    memcpy(combined + SHA256_HASH_SIZE, peer->salt, SALT_LEN);
    hashdata_t test_sig;
    get_data_sha(combined, test_sig, SHA256_HASH_SIZE + SALT_LEN, SHA256_HASH_SIZE);

    if (memcmp(test_sig, peer->signature, SHA256_HASH_SIZE) != 0) {
        pthread_mutex_unlock(&network_mutex);
        // Status code 4: Password mismatch
        char* error = "Invalid signature";
        send_reply(connfd, STATUS_BAD_PASSWORD, (uint8_t*)error, strlen(error));
        return;
    }

    pthread_mutex_unlock(&network_mutex);

    // Get filepath from request body
    char filepath[PATH_LEN];
    memset(filepath, 0, PATH_LEN);
    uint32_t copy_len = payload_len < PATH_LEN - 1 ? payload_len : PATH_LEN - 1;
    memcpy(filepath, payload, copy_len);

    // Per protocol: Status 5 (Bad request) if file is busy
    if (is_file_being_retrieved(filepath)) {
        char* error = "File is currently being retrieved";
        send_reply(connfd, STATUS_BAD_REQUEST, (uint8_t*)error, strlen(error));
        return;
    }

    // Per protocol: "files served relative to peer's directory"
    long file_size;
    if (!check_file_exists_and_get_size(filepath, &file_size)) {
        // Status code 5: Bad request (file doesn't exist)
        char error[256];
        snprintf(error, 256, "File does not exist: %s", filepath);
        send_reply(connfd, STATUS_BAD_REQUEST, (uint8_t*)error, strlen(error));
        return;
    }

    FILE* fp = fopen(filepath, "rb");
    if (!fp) {
        // Status code 5: Bad request (cannot open)
        char* error = "Cannot open file";
        send_reply(connfd, STATUS_BAD_REQUEST, (uint8_t*)error, strlen(error));
        return;
    }

    uint8_t* file_data = malloc(file_size);
    fread(file_data, 1, file_size, fp);
    fclose(fp);

    printf("Sending requested data from %s\n", filepath);
    // Status code 1: OK
    send_reply(connfd, STATUS_OK, file_data, file_size);
    free(file_data);
}

/*
 * Handle COMMAND 3: INFORM
 * Per protocol: "peer informing another of third peer that joined"
 * Per protocol: "do NOT expect a reply"
 * Request body: 68 bytes (IP + port + signature + salt)
 */
void handle_inform_request(uint8_t* payload) {
    // Parse 68-byte body per protocol
    char ip[IP_LEN];
    memcpy(ip, payload, IP_LEN);
    ip[IP_LEN-1] = '\0';

    uint32_t port;
    memcpy(&port, payload + IP_LEN, 4);
    port = ntohl(port);

    hashdata_t signature;
    memcpy(signature, payload + IP_LEN + 4, SHA256_HASH_SIZE);

    char salt[SALT_LEN + 1];
    memcpy(salt, payload + IP_LEN + 4 + SHA256_HASH_SIZE, SALT_LEN);
    salt[SALT_LEN] = '\0';

    pthread_mutex_lock(&network_mutex);
    NetworkAddress_t* existing = NULL;
    // Per protocol: "ensure network list does not contain duplicates"
    if (!find_peer_in_network(ip, port, &existing)) {
        add_peer_to_network(ip, port, signature, salt);
        printf("Informed of new peer %s:%d\n", ip, port);
    }
    pthread_mutex_unlock(&network_mutex);
}

/*
 * Handle incoming connection
 * Per protocol: "each request gets response then connection closes"
 */
void* handle_client_connection(void* connfd_arg) {
    int connfd = *(int*)connfd_arg;
    free(connfd_arg);

    uint8_t buffer[MAX_MSG_LEN];
    ssize_t bytes_read = recv(connfd, buffer, REQUEST_HEADER_LEN, 0);
    
    if (bytes_read < REQUEST_HEADER_LEN) {
        close(connfd);
        return NULL;
    }

    // Parse REQUEST per protocol specification
    char ip[IP_LEN];
    memcpy(ip, buffer, IP_LEN);
    ip[IP_LEN-1] = '\0';

    uint32_t port = network_to_host(buffer + IP_LEN);

    hashdata_t signature;
    memcpy(signature, buffer + IP_LEN + PORT_LEN, SHA256_HASH_SIZE);

    uint32_t command = network_to_host(buffer + IP_LEN + PORT_LEN + SHA256_HASH_SIZE);
    uint32_t length = network_to_host(buffer + IP_LEN + PORT_LEN + SHA256_HASH_SIZE + 4);

    // Read request body if present
    uint8_t* payload = NULL;
    if (length > 0) {
        payload = malloc(length);
        ssize_t total = 0;
        while (total < length) {
            ssize_t n = recv(connfd, payload + total, length - total, 0);
            if (n <= 0) break;
            total += n;
        }
        if (total != length) {
            free(payload);
            // Status code 7: Malformed
            char* error = "Malformed request";
            send_reply(connfd, STATUS_MALFORMED, (uint8_t*)error, strlen(error));
            close(connfd);
            return NULL;
        }
    }

    // Route based on command code
    if (command == COMMAND_REGISTER) {
        printf("Got registration message from %s:%d\n", ip, port);
        handle_register_request(connfd, ip, port, signature);
    } else if (command == COMMAND_INFORM) {
        printf("Got inform message from %s:%d\n", ip, port);
        handle_inform_request(payload);
        // Per protocol: "ONLY inform does not expect reply"
        // So we don't call send_reply here
    } else if (command == COMMAND_RETREIVE) {
        printf("Got request message from %s:%d\n", ip, port);
        handle_retrieve_request(connfd, ip, port, signature, payload, length);
    } else {
        // Status code 7: Malformed (unknown command)
        char* error = "Unknown command";
        send_reply(connfd, STATUS_MALFORMED, (uint8_t*)error, strlen(error));
    }

    if (payload) free(payload);
    // Per protocol: "close connection after response"
    close(connfd);
    return NULL;
}

/* ============================================================================
 * MAIN THREADS
 * ============================================================================ */

void* client_thread() {
    char peer_ip[IP_LEN];
    fprintf(stdout, "Enter peer IP to connect to: ");
    scanf("%16s", peer_ip);
    while ((c = getchar()) != '\n' && c != EOF);

    for (int i=strlen(peer_ip); i<IP_LEN; i++) {
        peer_ip[i] = '\0';
    }

    char peer_port[PORT_STR_LEN];
    fprintf(stdout, "Enter peer port to connect to: ");
    scanf("%16s", peer_port);
    while ((c = getchar()) != '\n' && c != EOF);

    for (int i=strlen(peer_port); i<PORT_STR_LEN; i++) {
        peer_port[i] = '\0';
    }

    int port = atoi(peer_port);
    
    char password[PASSWORD_LEN];
    fprintf(stdout, "Enter your password again for connections: ");
    scanf("%16s", password);
    while ((c = getchar()) != '\n' && c != EOF);
    
    for (int i=strlen(password); i<PASSWORD_LEN; i++) {
        password[i] = '\0';
    }

    register_with_peer(peer_ip, port, password, my_address->salt);

    pthread_mutex_lock(&network_mutex);
    if (peer_count == 0) {
        printf("No network was detected, shutting down client thread.\n");
        pthread_mutex_unlock(&network_mutex);
        return NULL;
    }
    pthread_mutex_unlock(&network_mutex);

    // Per protocol: "files written relative to a peer's directory"
    while (1) {
        printf("Type the name of a file to be retrieved, or 'quit' to quit:\n");
        char filepath[PATH_LEN];
        scanf("%127s", filepath);
        while ((c = getchar()) != '\n' && c != EOF);

        if (strcmp(filepath, "quit") == 0) {
            printf("Shutting down client thread.\n");
            exit(EXIT_SUCCESS);
        }

        char target_ip[IP_LEN];
        uint32_t target_port;
        get_random_peer(target_ip, &target_port);
        get_file_from_peer(target_ip, target_port, filepath);
    }

    return NULL;
}

void* server_thread() {
    char port_str[PORT_STR_LEN];
    snprintf(port_str, PORT_STR_LEN, "%d", my_address->port);

    int listenfd = compsys_helper_open_listenfd(port_str);
    if (listenfd < 0) {
        fprintf(stderr, "Failed to open listening socket on port %d\n", my_address->port);
        return NULL;
    }

    printf("Server listening on %s:%d\n", my_address->ip, my_address->port);

    while (1) {
        struct sockaddr_storage clientaddr;
        socklen_t clientlen = sizeof(clientaddr);
        
        int connfd = accept(listenfd, (struct sockaddr*)&clientaddr, &clientlen);
        if (connfd < 0) {
            fprintf(stderr, "Accept failed: %s\n", strerror(errno));
            continue;
        }

        // Per protocol: handle each request in separate thread
        pthread_t handler_thread;
        int* connfd_ptr = malloc(sizeof(int));
        *connfd_ptr = connfd;
        pthread_create(&handler_thread, NULL, handle_client_connection, connfd_ptr);
        pthread_detach(handler_thread);
    }

    return NULL;
}

/* ============================================================================
 * MAIN --> PROGRAM ENTRY
 * ============================================================================ */

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <IP> <PORT>\n", argv[0]);
        exit(EXIT_FAILURE);
    } 

    srand(time(NULL));

    my_address = (NetworkAddress_t*)malloc(sizeof(NetworkAddress_t));
    memset(my_address->ip, '\0', IP_LEN);
    memcpy(my_address->ip, argv[1], strlen(argv[1]));
    my_address->port = atoi(argv[2]);

    if (!is_valid_ip(my_address->ip)) {
        fprintf(stderr, ">> Invalid peer IP: %s\n", my_address->ip);
        exit(EXIT_FAILURE);
    }
    
    if (!is_valid_port(my_address->port)) {
        fprintf(stderr, ">> Invalid peer port: %d\n", my_address->port);
        exit(EXIT_FAILURE);
    }

    char password[PASSWORD_LEN];
    fprintf(stdout, "Create a password to proceed: ");
    scanf("%16s", password);
    while ((c = getchar()) != '\n' && c != EOF);

    for (int i=strlen(password); i<PASSWORD_LEN; i++) {
        password[i] = '\0';
    }

    // Per protocol: "hard coded salts to make debugging easier"
    char salt[SALT_LEN+1] = "0123456789ABCDEF";
    strncpy(my_address->salt, salt, SALT_LEN);
    my_address->salt[SALT_LEN-1] = '\0';
    strncpy(my_address->original_salt, salt, SALT_LEN);
    my_address->original_salt[SALT_LEN-1] = '\0';

    // Per protocol: "user-remembered passwords salted and hashed"
    hashdata_t initial_sig;
    get_signature(password, salt, &initial_sig);
    memcpy(my_address->signature, initial_sig, SHA256_HASH_SIZE);
    memcpy(my_address->user_signature, initial_sig, SHA256_HASH_SIZE);
    
    // Store password for later signature regeneration (Python compatibility)
    strncpy(my_address->password, password, PASSWORD_LEN - 1);
    my_address->password[PASSWORD_LEN - 1] = '\0';

    pthread_mutex_lock(&network_mutex);
    add_peer_to_network(my_address->ip, my_address->port, my_address->signature, salt);
    pthread_mutex_unlock(&network_mutex);

    pthread_t client_thread_id;
    pthread_t server_thread_id;
    pthread_create(&client_thread_id, NULL, client_thread, NULL);
    pthread_create(&server_thread_id, NULL, server_thread, NULL);

    pthread_join(client_thread_id, NULL);
    pthread_join(server_thread_id, NULL);

    exit(EXIT_SUCCESS);
}
