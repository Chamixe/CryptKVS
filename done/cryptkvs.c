/*
 * cryptkvs -- main ; argument parsing and dispatch ; etc.
 */

#include <stdio.h>
#include "../provided/error.h"
#include "../provided/ckvs_local.h"
#include "../provided/ckvs_utils.h"
#include "ckvs_client.h"

#define N_COMMANDS sizeof(commands) / sizeof(struct ckvs_command_mapping)
#define HTTP "http://"
#define HTTPS "https://"
#define HTTP_LEN 7
#define HTTPS_LEN 8


//pointer on functions "ckvs_local_COMMAND()"
typedef int (*ckvs_command)(const char*, int, char*);

/*
 * name : name of the command 
 * dscrp : description of the command
 * fc : the function linked to the command
 */ 
struct ckvs_command_mapping
{
    const char* name;
    const char* dscrp;
    ckvs_command lf;
    ckvs_command cf;
};

//an array of ckvs_command_mapping that associates every command to it's usage and it's corresponding function
const static struct ckvs_command_mapping commands[] = 
{{"stats", "cryptkvs <database> stats", ckvs_local_stats, ckvs_client_stats}, 
{"get", "cryptkvs <database> get <key> <password>", ckvs_local_get, ckvs_client_get}, 
{"set", "cryptkvs <database> set <key> <password> <filename>", ckvs_local_set, ckvs_client_set}, 
{"new", "cryptkvs <database> new <key> <password>", ckvs_local_new, ckvs_client_set},
};



/* *************************************************** *
 * TODO WEEK 09-11: Add then augment usage messages    *
 * *************************************************** */

/* *************************************************** *
 * TODO WEEK 04-07: add message                        *
 * TODO WEEK 09: Refactor usage()                      *
 * *************************************************** */
static void usage(const char *execname, int err)
{
    if (err == ERR_INVALID_COMMAND) {
        pps_printf("Available commands:\n");
        for(size_t i = 0; i < N_COMMANDS; i++){
            pps_printf("%s\n", commands[i].dscrp);
        }
        pps_printf("\n");
    } else if (err >= 0 && err < ERR_NB_ERR) {
        pps_printf("%s exited with error: %s\n\n\n", execname, ERR_MESSAGES[err]);
    } else {
        pps_printf("%s exited with error: %d (out of range)\n\n\n", execname, err);
    }
}


/* *************************************************** *
 * TODO WEEK 04-11: Add more commands                  *
 * TODO WEEK 09: Refactor ckvs_local_*** commands      *
 * *************************************************** */
/**
 * @brief Runs the command requested by the user in the command line, or returns ERR_INVALID_COMMAND if the command is not found.
 *
 * @param argc (int) the number of arguments in the command line
 * @param argv (char*[]) the arguments of the command line, as passed to main()
 */
int ckvs_do_one_cmd(int argc, char *argv[])
{   
    if(argc < 3){
        return ERR_INVALID_COMMAND;
    }
    const char* db_filename = argv[1];
    const char* cmd = argv[2];
    const size_t cmd_len = strlen(cmd);

    size_t i = 0;
    ckvs_command function = NULL;
    while(i < N_COMMANDS && function == NULL){
        if(strncmp(commands[i].name, cmd, strlen(cmd)) == 0){
            if(!strncmp(cmd, HTTP, HTTP_LEN) || !strncmp(cmd, HTTPS, HTTPS_LEN))
                function = commands[i].cf;
            else
                function = commands[i].lf;
        }
        i += 1;
    }
    
    if(function == NULL){
        return ERR_INVALID_COMMAND;
    }
    
    int err_cmd = function(db_filename, argc - 3, argv + 3);
    return err_cmd;

}



#ifndef FUZZ
/**
 * @brief main function, runs the requested command and prints the resulting error if any.
 */
int main(int argc, char *argv[])
{


    int ret = ckvs_do_one_cmd(argc, argv);
    if (ret != ERR_NONE) {
        usage(argv[0], ret);
    }
    return ret;
}
#endif
