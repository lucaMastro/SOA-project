
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



int add_path(char *hash, char *new_path){

    printf("adding path: %s\n", new_path);
	int ret = syscall(SYS_ADD, hash, new_path);
    if (ret < 0){
        printf("something went wrong adding path\n");
        return -1;
    }

    printf("path added successfully\n");
}

int main(int argc, char** argv){
    int ret;

    char *new_path;

    if (argc < 2){
        printf("[*] usage: %s <path_to_add>\n", argv[0]);
        return -1;
    }

    seteuid(0);
    setegid(0);
    char *new_plain_text = "asd";

    new_path = (char*) argv[1];
    add_path(new_plain_text, new_path);

    return 0;

}
