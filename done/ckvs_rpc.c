/**
 * @file ckvs_rpc.c
 * @brief RPC handling using libcurl
 * @author E. Bugnion
 *
 * Includes example from https://curl.se/libcurl/c/getinmemory.html
 */
#include <stdlib.h>

#include "ckvs_rpc.h"
#include "error.h"
#include "util.h"
#include "ckvs_utils.h"

/**
 * ckvs_curl_WriteMemoryCallback -- lifted from https://curl.se/libcurl/c/getinmemory.html
 *
 * @brief Callback that gets called when CURL receives a message.
 * It writes the payload inside ckvs_connection.resp_buf.
 * Note that it is already setup in ckvs_rpc_init.
 *
 * @param contents (void*) content received by CURL
 * @param size (size_t) size of an element of of content. Always 1
 * @param nmemb (size_t) number of elements in content
 * @param userp (void*) points to a ckvs_connection (set with the CURLOPT_WRITEDATA option)
 * @return (size_t) the number of written bytes, or 0 if an error occured
 */
static size_t ckvs_curl_WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    struct ckvs_connection *conn = (struct ckvs_connection *)userp;

    char *ptr = realloc(conn->resp_buf, conn->resp_size + realsize + 1);
    if(!ptr) {
        /* out of memory! */
        debug_printf("not enough memory (realloc returned NULL)\n");
        return 0;
    }

    conn->resp_buf = ptr;
    memcpy(&(conn->resp_buf[conn->resp_size]), contents, realsize);
    conn->resp_size += realsize;
    conn->resp_buf[conn->resp_size] = 0;

    return realsize;
}


int ckvs_rpc_init(struct ckvs_connection *conn, const char *url)
{
    M_REQUIRE_NON_NULL(conn);
    M_REQUIRE_NON_NULL(url);
    bzero(conn, sizeof(*conn));

    conn->url  = url;
    conn->curl = curl_easy_init();
    if (conn->curl == NULL) {
        return ERR_OUT_OF_MEMORY;
    }
    curl_easy_setopt(conn->curl, CURLOPT_WRITEFUNCTION, ckvs_curl_WriteMemoryCallback);
    curl_easy_setopt(conn->curl, CURLOPT_WRITEDATA, (void *)conn);

    return ERR_NONE;
}

void ckvs_rpc_close(struct ckvs_connection *conn)
{
    if (conn == NULL)
        return;

    if (conn->curl) {
        curl_easy_cleanup(conn->curl);
    }
    if (conn->resp_buf) {
        free(conn->resp_buf);
    }
    bzero(conn, sizeof(*conn));
}

int ckvs_rpc(struct ckvs_connection *conn, const char *GET)
{   
    if(conn == NULL || GET == NULL) return ERR_INVALID_ARGUMENT;
    //concatenates url
    const size_t url_len = strlen(conn->url);
    const size_t get_len = strlen(GET);
    char* url = malloc(url_len + get_len + 1);
    if(url == NULL) return ERR_OUT_OF_MEMORY;
    strncpy(url, conn->url, url_len);
    strncpy(url + url_len, GET, get_len);
    url[url_len + get_len] = '\0';
    CURLcode ret = curl_easy_setopt(conn->curl, CURLOPT_URL, url);
    if(ret == CURLE_OUT_OF_MEMORY) {
        free(url);
        return ERR_OUT_OF_MEMORY;
    }

    //call the function
    ret = curl_easy_perform(conn->curl);

    //traiter les erreurs
    if(ret == CURLE_BAD_FUNCTION_ARGUMENT) {
        free(url);
        return ERR_INVALID_ARGUMENT;
    }
    if(ret == CURLE_OUT_OF_MEMORY){
        free(url);
        return ERR_OUT_OF_MEMORY;
    }
    if(ret != CURLE_OK){
        free(url);
        return ERR_TIMEOUT;
    }

    return ERR_NONE;
}


