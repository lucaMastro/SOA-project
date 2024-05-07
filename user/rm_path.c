#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

/*
    @TODO: add the hidden way to get the password
*/

#define SYS_RM              174


int rm_path(char *hash, char* path){
    int ret;
    printf("removing path: %s\n", path);
	/* ret = syscall(SYS_RM, hash, new_path); */
	ret = syscall(SYS_RM, hash,path);
    if (ret < 0){
        printf("something went wrong removing path\n");
        return -1;
    }

    printf("path removed successfully\n");
}



int main(int argc, char** argv){
    int ret;

    char hash[65];
    char new_hash[65];
    char *new_path;
    char *static_new_path, *static_new_path_2;
    int len;

    if (argc < 2){
        printf("[*] usage: %s <path_to_rm>\n", argv[0]);
        return -1;
    }

    seteuid(0);
    setegid(0);

    new_path = (char*) argv[1];
    rm_path(new_hash, new_path);

    return 0;

}
