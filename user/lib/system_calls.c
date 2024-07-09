#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "./sys_call_numbers_header.h"
#include "../../lib/max_parameters.h"
#include "../../lib/reference_monitor_states.h"
#include "../../lib/user_error_code.h"

#define printf_red(format, ...)             \
    do {                                    \
        printf("\x1b[31m");                 \
        printf(format, ##__VA_ARGS__);      \
        printf("\x1b[0m");                  \
    } while (0)

#define printf_green(format, ...)           \
    do {                                    \
        printf("\x1b[32m");                 \
        printf(format, ##__VA_ARGS__);      \
        printf("\x1b[0m");                  \
    } while (0)

#define printf_debug(format, ...)           \
    do {                                    \
        printf("\x1b[33m");                 \
        printf(format, ##__VA_ARGS__);      \
        printf("\x1b[0m");                  \
    } while (0)


void manage_error_msg(){
    switch(errno){
        case EGENERAL:
            printf_red("Something went wrong. Check dmesg for more information.\n");
            break;
        case EWRONG_PW:
            printf_red("Error: wrong password given.\n");
            break;
        case EINAPPROPRIATE_EUID:
            printf_red("Error: inappropriate EUID.\n");
            break;        
        case EPATH:
            printf_red("Error: invalid path.\n");
            break;        
        case EINVALID_MONITOR_STATE:
            printf_red("Error: current monitor state doesn't permit reconfigurtion.\n");
            break;        
        case EINVALID_NEW_MONITOR_STATE:
            printf_red("Error: invalid new monitor state.\n");
            break;        
    }
}


int get_paths(char *pass, int paths_num_to_retrieve){

    printf("Retrieving paths...\n");
    char **paths;
    int i;
    int ret;

    paths = malloc(sizeof(char*) * paths_num_to_retrieve);
    for (i = 0; i< paths_num_to_retrieve; i++){
        paths[i] = (char*) malloc(sizeof(char) * MAX_PATH_LEN);
        strcpy(paths[i],"");
    }

    ret = syscall(SYS_GET, pass, paths, paths_num_to_retrieve);
    if (ret < 0){
        manage_error_msg(ret);
        return -1;
    }

    printf_green("Retrieved %d path(s):\n", ret);
    for (i = 0; i< ret; i++){
        printf("paths[%d] = %s\n", i, paths[i]);
    }
    for (i = 0; i< paths_num_to_retrieve; i++){
       free(paths[i]);
    }
    free(paths);
}


int add_path(char *pass, char *new_path){

    printf("adding path: %s\n", new_path);
	int ret = syscall(SYS_ADD, pass, new_path);
    if (ret < 0){
        manage_error_msg(ret);
        return -1;
    }

    printf_green("Path added successfully\n");
}

int rm_path(char *pass, char* path){
    int ret;
    printf("removing path: %s\n", path);
	ret = syscall(SYS_RM, pass,path);
    if (ret < 0){
        manage_error_msg(ret);
        return -1;
    }

    printf_green("Path removed successfully\n");
}


int change_monitor_password(char *old_pass, char *new_pass){
    int ret;
    printf("changing password...\n");
	ret = syscall(SYS_CHANGE_PASS, old_pass, new_pass);
    if (ret < 0){
        manage_error_msg(ret);
        return ret;
    }

    printf_green("Password changed successfully\n");
    return 0;
}

int change_monitor_state(char *pass, unsigned char new_state){
    int ret;

    if (new_state > (OFF | ON | RECOFF | RECON) ||
            new_state < 0){
        printf_red("Error: invalid new monitor state.\n");
        return -1;
    }

    printf("changing state...\n");
	ret = syscall(SYS_CHANGE_STATE, pass, new_state);
    if (ret < 0){
        manage_error_msg(ret);
        return ret;
    }

    printf_green("State changed successfully\n");
    return 0;
}
