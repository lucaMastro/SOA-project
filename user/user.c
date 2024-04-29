
#include <string.h>
#include <unistd.h>
#include <stdio.h>

/*
    @TODO: add the hidden way to get the password
*/

int main(int argc, char** argv){
    int ret;

    char hash[65];
    char plain_text[256];
    char new_path[256];
    int len;
    printf("reference monitor password: ");
    scanf("%s", plain_text);

    printf("path to add: ");
    scanf("%s", new_path);


    len = strlen(plain_text);

	ret = syscall(174, plain_text, len, hash);
    if (ret < 0){
        printf("something went wrong hashing password\n");
        return -1;
    }

    printf("hashed password: %s\nadding new path: %s\n", hash, new_path);

	ret = syscall(134, hash, new_path);
    if (ret < 0){
        printf("something went wrong adding path\n");
        return -1;
    }

    printf("path added successfully\n");
    return 0;

}
