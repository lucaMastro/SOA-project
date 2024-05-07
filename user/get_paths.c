
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

/*
    @TODO: add the hidden way to get the password
*/

#define SYS_ADD             134
#define SYS_GET             156
#define SYS_RM              174
#define SYS_CHANGE_PASS     177



int get_paths(char *hash){

    printf("\n\nRetrieving all paths...\n");
    int paths_to_retrieve = 5;
    char *paths[paths_to_retrieve];
    int i;
    for (i = 0; i< paths_to_retrieve; i++){
        paths[i] = (char*) malloc(sizeof(char)*256);
        strcpy(paths[i],"");
    }

    syscall(SYS_GET, hash, paths, paths_to_retrieve);
    for (i = 0; i< paths_to_retrieve; i++){
        printf("paths[%d] = %s\n", i, paths[i]);
    }
    for (i = 0; i< paths_to_retrieve; i++){
       free(paths[i]);
    }
}


int main(int argc, char** argv){
    int ret;

    char hash[65];
    char new_hash[65];
    char new_path[256];
    char *static_new_path, *static_new_path_2;
    int len;

    seteuid(0);
    setegid(0);
    char *new_plain_text = "asd";
    get_paths(new_plain_text);

    return 0;

}

