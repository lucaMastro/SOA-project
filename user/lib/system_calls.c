#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#include "./sys_call_numbers_header.h"
#include "../../lib/max_parameters.h"
#include "../../lib/reference_monitor_states.h"


int get_paths(char *pass, int paths_num_to_retrieve){

    printf("retrieving all paths...\n");
    char *paths[paths_num_to_retrieve];
    int i;
    int ret;
    for (i = 0; i< paths_num_to_retrieve; i++){
        paths[i] = (char*) malloc(sizeof(char) * MAX_PATH_LEN);
        strcpy(paths[i],"");
    }

    ret = syscall(SYS_GET, pass, paths, paths_num_to_retrieve);
    if (ret < 0){
        printf("Error in get_paths systemcall\n");
        return -1;
    }

    printf("Retrieved %d paths:\n", ret);
    for (i = 0; i< ret; i++){
        printf("paths[%d] = %s\n", i, paths[i]);
    }
    for (i = 0; i< paths_num_to_retrieve; i++){
       free(paths[i]);
    }
}


int add_path(char *pass, char *new_path){

    printf("adding path: %s\n", new_path);
	int ret = syscall(SYS_ADD, pass, new_path);
    if (ret < 0){
        printf("something went wrong adding path\n");
        return -1;
    }

    printf("path added successfully\n");
}

int rm_path(char *pass, char* path){
    int ret;
    printf("removing path: %s\n", path);
	/* ret = syscall(SYS_RM, pass, new_path); */
	ret = syscall(SYS_RM, pass,path);
    if (ret < 0){
        printf("something went wrong removing path\n");
        return -1;
    }

    printf("path removed successfully\n");
}


int change_monitor_password(char *old_pass, char *new_pass){
    int ret;
    printf("changing password...\n");
	/* ret = syscall(SYS_RM, pass, new_path); */
	ret = syscall(SYS_CHANGE_PASS, old_pass, new_pass);
    if (ret < 0){
        printf("something went wrong changing password\n");
        return ret;
    }

    printf("password changed successfully\n");
    return 0;
}

int change_monitor_state(char *pass, unsigned char new_state){
    int ret;

    if (new_state > (OFF | ON | RECOFF | RECON) ||
            new_state < 0){
        printf("error: invalid monitor state given\n");
        return -1;
    }

    printf("changing state...\n");
	ret = syscall(SYS_CHANGE_STATE, pass, new_state);
    if (ret < 0){
        printf("something went wrong changing state\n");
        return ret;
    }

    printf("state changed successfully\n");
    return 0;
}
