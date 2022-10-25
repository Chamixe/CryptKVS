#include <stdio.h>
#include "error.h"
#include "ckvs_local.h"
#include "ckvs_utils.h"
#include "ckvs.h"
#include <stdlib.h>
#include "ckvs_io.h"
#include "ckvs_crypto.h"
#include "openssl/evp.h"
#include "openssl/rand.h"

#define M_ARGS(n_args, required_n) \
        if (n_args < required_n) { \
            return ERR_NOT_ENOUGH_ARGUMENTS; \
        } \
        if (n_args > required_n) { \
            return ERR_TOO_MANY_ARGUMENTS; \
        }

/**
 * @brief frees and closes a ckvs
 *
 * @param ckvs
 */
void desintegrate(struct CKVS *ckvs)
{
    ckvs_close(ckvs);
    free(ckvs);
}


/**
 * @brief Opens the CKVS database at the given filename and executes the 'stats' command,
 * ie. prints information about the database.
 *
 * @param filename (const char*) the path to the CKVS database to open
 * @return int, an error code
 */
int ckvs_local_stats(const char* filename, int optargc, char* optargv[])
{
    M_REQUIRE_NON_NULL(filename);
    M_ARGS(optargc, 0);

    struct CKVS *ckvs = malloc(sizeof(struct CKVS));
    if (ckvs == NULL)
    {
        return ERR_OUT_OF_MEMORY;
    }
    

    int err_open = ckvs_open(filename, ckvs);
    if(err_open != ERR_NONE){
        free(ckvs);
        return err_open;
    }

    print_header(&(ckvs->header));
    for (size_t i = 0; i < CKVS_FIXEDSIZE_TABLE; i++)
    {
        if (strlen(ckvs->entries[i].key)){
            print_entry(&ckvs->entries[i]);
        }
    }
    desintegrate(ckvs);

    return ERR_NONE;
}


int ckvs_local_getset(const char *filename, const char *key, const char *pwd, const char *set_value)
{

    M_REQUIRE_NON_NULL(filename);
    M_REQUIRE_NON_NULL(key);
    M_REQUIRE_NON_NULL(pwd);
    
    struct CKVS *ckvs = malloc(sizeof(struct CKVS));
    if (ckvs == NULL)
    {
        return ERR_OUT_OF_MEMORY;
    }
    
    int err_read = ckvs_open(filename, ckvs);
    if (err_read != ERR_NONE)
    {
        desintegrate(ckvs);
        return err_read;
    }

    struct ckvs_memrecord *record = malloc(sizeof(struct ckvs_memrecord));
    if (record == NULL)
    {
        desintegrate(ckvs);
        return ERR_OUT_OF_MEMORY;
    }
    

    int err_encrypt = ckvs_client_encrypt_pwd(record, key, pwd);

    if (err_encrypt != ERR_NONE)
    {
        desintegrate(ckvs);
        free(record);
        return err_encrypt;
    }
    
    struct ckvs_entry *entry;

    int err_find = ckvs_find_entry(ckvs, key, &(record->auth_key), &entry);
    if (err_find != ERR_NONE)
    {
        desintegrate(ckvs);
        free(record);
        return err_find;
    }

    if (set_value != NULL)
    {
        if (RAND_bytes(entry->c2.sha, SHA256_DIGEST_LENGTH) != 1)
        {
            desintegrate(ckvs);
            free(record);
            return ERR_IO;
        }
    }
    
    
    int err_compute = ckvs_client_compute_masterkey(record, &(entry->c2));
    if (err_compute != ERR_NONE)
    {
        desintegrate(ckvs);
        free(record);
        return err_compute;
    }


    if (set_value == NULL) //here we make the difference between get and set.
    {

        //is there no value in the entry found
        if(entry->value_len == 0){
            desintegrate(ckvs);
            free(record);
            return ERR_NO_VALUE;
        }

        FILE* f = fopen(filename, "r+w");
        int err_seek = fseek(f, (long)(entry->value_off), SEEK_SET);

        if (err_seek != 0)
        {
            desintegrate(ckvs);
            free(record);
            return ERR_CORRUPT_STORE;
        }
        unsigned char *input = malloc(entry->value_len);
        if (input == NULL)
        {
            desintegrate(ckvs);
            free(record);
            return ERR_OUT_OF_MEMORY;
        }
        
        size_t err_read_l = fread(input, 1, entry->value_len, f);
        if (err_read_l != (size_t)(entry->value_len))
        {
            desintegrate(ckvs);
            free(record);
            free(input);
            return ERR_IO;
        }
        
        unsigned char *outbuf = malloc((size_t)(entry->value_len) + EVP_MAX_BLOCK_LENGTH + 1);
        if (outbuf == NULL)
        {
            desintegrate(ckvs);
            free(record);
            free(input);
            return ERR_OUT_OF_MEMORY;
        }
        
        size_t outbuflen;
        int err_crypt = ckvs_client_crypt_value(record, 0, input, entry->value_len, outbuf, &outbuflen);    
        if (err_crypt != ERR_NONE)
        {
            desintegrate(ckvs);
            free(record);
            free(input);
            free(outbuf);
            return err_crypt;
        }
        outbuf[outbuflen] = '\0';
        pps_printf("%s", outbuf);
        free(input);
        free(outbuf);
        desintegrate(ckvs);
        free(record);
    }
    else
    {
        char *crypted_value = malloc(strlen(set_value) + EVP_MAX_BLOCK_LENGTH + 1);
        if (crypted_value == NULL)
        {
            desintegrate(ckvs);
            free(record);
            return ERR_OUT_OF_MEMORY;
        }
        
        size_t bufflen;
        int err_crypt = ckvs_client_crypt_value(record, 1, set_value, strlen(set_value) + 1, crypted_value, &bufflen);
        crypted_value[bufflen] = '\0';
        

        if (err_crypt != ERR_NONE)
        {
            free(record);
            free(crypted_value);
            desintegrate(ckvs);

            return err_crypt;
        }
        int err_write_encrypt = ckvs_write_encrypted_value(ckvs, entry, crypted_value, (uint64_t)bufflen);
        if (err_write_encrypt != ERR_NONE)
        {
            free(record);
            free(crypted_value);
            desintegrate(ckvs);

            return err_write_encrypt;
        }

        free(record);
        desintegrate(ckvs);
        free(crypted_value);
    }

    return ERR_NONE;
}

int ckvs_local_get(const char* filename, int optargc, char* optargv[]){
    
    M_REQUIRE_NON_NULL(filename);
    M_ARGS(optargc, 2);
    char* key = optargv[0];
    char* pwd = optargv[1];
    M_REQUIRE_NON_NULL(key);
    M_REQUIRE_NON_NULL(pwd);
    
    return ckvs_local_getset(filename, key, pwd, NULL);

}

int ckvs_local_set(const char* filename, int optargc, char* optargv[]){
    M_REQUIRE_NON_NULL(filename);
    M_ARGS(optargc, 3);
    char* key = optargv[0];
    char* pwd = optargv[1];
    char* valuefilename = optargv[2];
    M_REQUIRE_NON_NULL(key);
    M_REQUIRE_NON_NULL(pwd);
    M_REQUIRE_NON_NULL(valuefilename);

    char *buffer_ptr;
    size_t buffer_size;

    int err_read = read_value_file_content(valuefilename, &buffer_ptr, &buffer_size);

    if (err_read != ERR_NONE)
    {
        return err_read;
    }

    int err_getset = ckvs_local_getset(filename, key, pwd, buffer_ptr);
    free(buffer_ptr);
    return err_getset;
}

int ckvs_local_new(const char* filename, int optargc, char* optargv[]){
    M_REQUIRE_NON_NULL(filename);
    M_ARGS(optargc, 2);
    char* key = optargv[0];
    char* pwd = optargv[1];
    M_REQUIRE_NON_NULL(key);
    M_REQUIRE_NON_NULL(pwd);

    struct CKVS *ckvs = malloc(sizeof(struct CKVS));
    if (ckvs == NULL)
    {
        return ERR_OUT_OF_MEMORY;
    }
    
    int err_read = ckvs_open(filename, ckvs);
    if (err_read != ERR_NONE)
    {
        desintegrate(ckvs);
        return err_read;
    }

    struct ckvs_memrecord *record = malloc(sizeof(struct ckvs_memrecord));
    if (record == NULL)
    {
        desintegrate(ckvs);
        return ERR_OUT_OF_MEMORY;
    }
    

    int err_encrypt = ckvs_client_encrypt_pwd(record, key, pwd);

    if (err_encrypt != ERR_NONE)
    {
        desintegrate(ckvs);
        free(record);
        return err_encrypt;
    }
    
    ckvs_entry_t *entry;
    int err_new_entry = ckvs_new_entry(ckvs, key, &record->auth_key, &entry);
    if (err_new_entry != ERR_NONE){
        desintegrate(ckvs);
        free(record);
        return err_new_entry;
    }


    desintegrate(ckvs);
    free(record);

    return ERR_NONE;

}