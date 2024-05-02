
#include <string.h>
#include <unistd.h>
#include <stdio.h>

/*
    @TODO: add the hidden way to get the password
*/

#define SYS_ADD     134
#define SYS_HASH    156
#define SYS_GET     174

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

	ret = syscall(SYS_HASH, plain_text, len, hash);
    if (ret < 0){
        printf("something went wrong hashing password\n");
        return -1;
    }

    printf("hashed password: %s\nadding new path: %s\n", hash, new_path);
    fflush(stdout);

	ret = syscall(SYS_ADD, hash, new_path);
    if (ret < 0){
        printf("something went wrong adding path\n");
        return -1;
    }

    printf("path added successfully\n");


    printf("\n\nRetrieving all paths...\n");
    int paths_to_retrieve = 5;
    char **paths[paths_to_retrieve];
    int i;
    for (i = 0; i< paths_to_retrieve; i++){
        paths[i] = (char*) malloc(sizeof(char)*256);
    }

    syscall(SYS_GET, "dontcare", paths, paths_to_retrieve);
    for (i = 0; i< paths_to_retrieve; i++){
        printf("paths[%d] = %s\n", i, paths[i]);
    }
    for (i = 0; i< paths_to_retrieve; i++){
       free(paths[i]);
    }


    return 0;

}
