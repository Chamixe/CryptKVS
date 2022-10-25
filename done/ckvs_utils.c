#include "ckvs.h"
#include <stdio.h>
#include "util.h"
#include "string.h"

/**
 * @brief Prints the given header to the standard output,
 *
 * @param header (const struct ckvs_header*) the header to print
 */
void print_header(const ckvs_header_t* header){
    if(header == NULL){
        return;
    }
    pps_printf("CKVS Header type       : %s\n", header->header_string);
    pps_printf("CKVS Header version    : %d\n", (int)(header->version));
    pps_printf("CKVS Header table_size : %d\n", (int)(header->table_size));
    pps_printf("CKVS Header threshold  : %d\n", (int)(header->threshold_entries));
    pps_printf("CKVS Header num_entries: %d\n", (int)(header->num_entries));
}

/**
 * @brief Prints the given entry to the standard output,
 *
 * @param entry (const struct ckvs_entry*) the entry to print
 */
void print_entry(const struct ckvs_entry* entry){
    if(entry == NULL){
        return;
    }
    pps_printf("    Key   : ");
    pps_printf(STR_LENGTH_FMT(CKVS_MAXKEYLEN), entry->key);
    pps_printf("\n");
    pps_printf("    Value : off %d len %d\n", (int)(entry->value_off), (int)(entry->value_len));
    print_SHA("    Auth  ", &(entry->auth_key));
    print_SHA("    C2    ", &(entry->c2));
}

char int_to_char(const size_t i){
    char c;
    if (i < 10) c = ((char)i);
    else c = (char)(((size_t)'A') + i - 10);
    return c;
}

void hex_encode(const uint8_t *in, size_t len, char *buf){
    if(in == NULL || buf == NULL) return;
    for (size_t i = 0; i < len; ++i) {
        sprintf(buf + 2 * i, "%02x", in[i]);
    }
    buf[2 * len] = '\0';
}


void SHA256_to_string(const struct ckvs_sha *sha, char *buf){
    hex_encode(sha->sha, SHA256_DIGEST_LENGTH, buf);
}


void print_SHA(const char *prefix, const struct ckvs_sha *sha){
    if (sha == NULL) return;

    char buffer[SHA256_PRINTED_STRLEN];
    
    SHA256_to_string(sha, buffer);

    pps_printf("%-5s: %s\n", prefix, buffer);

}

int ckvs_cmp_sha(const struct ckvs_sha *a, const struct ckvs_sha *b){
    return memcmp(a->sha, b->sha, SHA256_DIGEST_LENGTH);
}

int hex_decode(const char* input, uint8_t *output){
    
}

int SHA256_from_string(const char *input, struct ckvs_sha *sha){
    
}