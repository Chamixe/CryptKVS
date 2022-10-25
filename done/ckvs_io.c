#include "error.h"
#include "ckvs.h"
#include "ckvs_io.h"
#include "stdlib.h"
#include "stdbool.h"
#include "string.h"


/*
 * creates a hash of the key 
 */ 
static uint32_t ckvs_hashkey(struct CKVS *ckvs, const char *key){

    unsigned char *md = malloc(SHA_DIGEST_LENGTH);
    if (md == NULL)
    {
        return ERR_OUT_OF_MEMORY;
    }
    
    SHA256(key, strlen(key), md);

    uint32_t hash = *(uint32_t*)md;

    free(md);
    return hash & (ckvs->header.table_size - 1);
}



int ckvs_find_entry(struct CKVS *ckvs, const char *key, const struct ckvs_sha *auth_key, struct ckvs_entry **e_out){

    M_REQUIRE_NON_NULL(ckvs);
    M_REQUIRE_NON_NULL(key);
    M_REQUIRE_NON_NULL(auth_key);
    M_REQUIRE_NON_NULL(e_out);



    size_t i = ckvs_hashkey(ckvs, key);
    size_t n = 0;
    //L'indice de la clé dans le tableau d'entrees
    int key_ind = -1;
    while(n < ckvs->header.table_size && key_ind < 0){
        if(strncmp(ckvs->entries[i].key, key, CKVS_MAXKEYLEN) == 0){
            key_ind = (int)i;
        }
        n += 1;
        i = (i + 1) & (ckvs->header.table_size - 1);
    }

    if (n == ckvs->header.table_size){
        return ERR_KEY_NOT_FOUND;
    }

    if(ckvs_cmp_sha(&(ckvs->entries[key_ind].auth_key), auth_key) == 0){
        *e_out = &(ckvs->entries[key_ind]);
    }
    else{
        return ERR_DUPLICATE_ID;
    }

    return ERR_NONE;
}

/**
 * @brief Checks if the argument is a power of 2
 * 
 * @param size 
 * @return true if size is a power of 2
 * @return false if it isn't
 */
static bool is_power_of_2(const uint32_t size){
    uint32_t sum = 0;
    for(uint32_t i = 0; i < 32; i++){
        sum += (size >> i) & ((uint32_t)1);
    }
    return sum == 1;
}

int ckvs_open(const char *filename, struct CKVS *ckvs){

    M_REQUIRE_NON_NULL(filename);
    M_REQUIRE_NON_NULL(ckvs);


    FILE* f = fopen(filename, "r+w");
    if(f == NULL) {
        return ERR_IO;
    }
    ckvs->file = f;

    size_t r = fread(&(ckvs->header), sizeof(ckvs_header_t), 1, f);
    if (r == 0) {
        fclose(f);
        return ERR_IO;
    }
    
    if(strncmp(ckvs->header.header_string, CKVS_HEADERSTRING_PREFIX, strlen(CKVS_HEADERSTRING_PREFIX))){
        fclose(f);
        return ERR_CORRUPT_STORE;
    }
        
    if((ckvs->header).version != 1){
        fclose(f);
        return ERR_CORRUPT_STORE;
    }
        

    if(!is_power_of_2(ckvs->header.table_size)){
        fclose(f);
        return ERR_CORRUPT_STORE;
    }

    ckvs->entries = calloc(ckvs->header.table_size, sizeof(ckvs_entry_t));
    if (ckvs->entries == NULL)
    {
        fclose(f);
        return ERR_OUT_OF_MEMORY;
    }
    

    for(size_t i = 0; i < ckvs->header.table_size; i++){
        size_t l = fread(&(ckvs->entries[i]), sizeof(ckvs_entry_t), 1, f);
        if (l == 0) {
            fclose(f);
            free(ckvs->entries);
            return ERR_IO;
        }
    }
    
    return ERR_NONE;

}


void ckvs_close(struct CKVS *ckvs){

    if (ckvs != NULL && ckvs->file != NULL) {
        fclose(ckvs->file);
        free(ckvs->entries);
        ckvs->entries = NULL;
        ckvs->file = NULL;
    }

}

int read_value_file_content(const char* filename, char** buffer_ptr, size_t* buffer_size){

    M_REQUIRE_NON_NULL(filename);
    M_REQUIRE_NON_NULL(buffer_ptr);
    M_REQUIRE_NON_NULL(buffer_size);

    FILE* f = fopen(filename, "rb");
    
    if(f == NULL){
        return ERR_INVALID_FILENAME;
    }

    int seek_err = fseek(f, 0L, SEEK_END);
    if(seek_err != 0){
        fclose(f);
        return ERR_IO;
    }
    long size = ftell(f);

    int seek_err_2 = fseek(f, 0L, SEEK_SET);
    if(seek_err_2 != 0){
        fclose(f);
        return ERR_IO;
    }

    char* buffer = malloc((size_t)size + 1); // + 1 pour le \0
    if (buffer == NULL){
        fclose(f);
        return ERR_OUT_OF_MEMORY;
    }
    size_t l = fread(buffer, 1, size, f);
    if(l < size){
        free(buffer);
        fclose(f);
        return ERR_IO;
    }

    buffer[size] = '\0';
    *buffer_ptr = buffer;

    *buffer_size = (size_t)size;
    
    fclose(f);
    return ERR_NONE;

}


/**
 * @brief Writes the idx entry of the database in the file
 * 
 * @param ckvs 
 * @param idx 
 * @return int 
 */
static int ckvs_write_entry_to_disk(struct CKVS *ckvs, uint32_t idx){

    size_t offset = sizeof(ckvs_header_t) + idx * sizeof(ckvs_entry_t);
    int err_seek = fseek(ckvs->file, (long)offset, SEEK_SET);
    if(err_seek != 0){
        return ERR_IO;
    }
    size_t size_wrote = fwrite(&(ckvs->entries[idx]), sizeof(ckvs_entry_t), 1, ckvs->file);
    
    if(size_wrote != 1){
        return ERR_IO;
    }

    return ERR_NONE;
}

/**
 * @brief Writes in the file the incremented num entries
 * 
 * @param ckvs 
 * @return int 
 */
static int ckvs_increment_num_entries(struct CKVS *ckvs){
    ckvs->header.num_entries += 1;
    int err_seek = fseek(ckvs->file, 0L, SEEK_SET);
    if(err_seek != 0){
        return ERR_IO;
    }
    size_t size_wrote = fwrite(&ckvs->header, sizeof(ckvs_header_t), 1, ckvs->file);

    if(size_wrote != 1){
        return ERR_IO;
    }

    return ERR_NONE;
}

int ckvs_write_encrypted_value(struct CKVS *ckvs, struct ckvs_entry *e, 
    const unsigned char *buf, uint64_t buflen){

    M_REQUIRE_NON_NULL(buf);
    M_REQUIRE_NON_NULL(ckvs);
    M_REQUIRE_NON_NULL(e);
    
    if(ckvs->file == NULL){
        return ERR_IO;
    }

    int err_seek = fseek(ckvs->file, 0L, SEEK_END);

    if(err_seek != 0){
        return ERR_IO;
    }

    long value_off = ftell(ckvs->file);
    int err_write = fwrite(buf, 1, buflen, ckvs->file);
    if(err_write != buflen) {
        return ERR_IO;
    }

    e->value_off = (uint64_t)value_off;
    e->value_len = buflen;

    uint32_t idx = e - ckvs->entries;

    err_write = ckvs_write_entry_to_disk(ckvs, idx);
    if(err_write != ERR_NONE){
        return err_write;
    }

    return ERR_NONE;
}


int ckvs_new_entry(struct CKVS *ckvs, const char *key, struct ckvs_sha *auth_key, struct ckvs_entry **e_out){
    
    M_REQUIRE_NON_NULL(ckvs);
    M_REQUIRE_NON_NULL(key);
    M_REQUIRE_NON_NULL(auth_key);
    M_REQUIRE_NON_NULL(e_out);

    M_REQUIRE(strlen(key) <= CKVS_MAXKEYLEN, ERR_INVALID_ARGUMENT, "The key is too big");
    M_REQUIRE(ckvs->header.num_entries < ckvs->header.threshold_entries, ERR_MAX_FILES, "Too many entries");

    //Is there already the entry or problem reading entries
    int err_entry = ckvs_find_entry(ckvs, key, auth_key, e_out);
    if(err_entry != ERR_KEY_NOT_FOUND){
        if(err_entry == ERR_NONE) return ERR_DUPLICATE_ID;
        return err_entry;
    }

    //Finding the indice of the new entry
    size_t i = (size_t)ckvs_hashkey(ckvs, key);
    size_t n = 0;
    while(strlen(ckvs->entries[i].key) != 0 && n < ckvs->header.table_size){
        i = (i + 1) & (ckvs->header.table_size - 1);
        n += 1;
    }
    if(n == ckvs->header.table_size){
        return ERR_MAX_FILES; //All entries are full
    }

    //Creating the entry and initalizing it
    strncpy(ckvs->entries[i].key, key, CKVS_MAXKEYLEN);
    memcpy(&ckvs->entries[i].auth_key, auth_key, sizeof(ckvs_sha_t));
    ckvs->entries[i].value_len = 0;
    ckvs->entries[i].value_off = 0;
    ckvs_increment_num_entries(ckvs);

    //Writing the entry in the file
    int err_write = ckvs_write_entry_to_disk(ckvs, i);
    if(err_write != ERR_NONE){
        return err_write;
    }
    *e_out = &(ckvs->entries[i]);

    return ERR_NONE;
}

