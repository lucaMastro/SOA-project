
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

/*
    @TODO: add the hidden way to get the password
*/

#define SYS_ADD     134
#define SYS_HASH    156
#define SYS_GET     174
#define SYS_RM      177



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

int add_path(char *hash, char *new_path){

    printf("adding path: %s\n", new_path);
	int ret = syscall(SYS_ADD, hash, new_path);
    if (ret < 0){
        printf("something went wrong adding path\n");
        return -1;
    }

    printf("path added successfully\n");
}

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
    char new_path[256];
    char *static_new_path, *static_new_path_2;
    int len;
    /* char plain_text[256]; */
    /* printf("reference monitor password: "); */
    /* scanf("%s", plain_text); */
    char *plain_text = "asd";

    len = strlen(plain_text);

	ret = syscall(SYS_HASH, plain_text, len, hash);
    if (ret < 0){
        printf("something went wrong hashing password\n");
        return -1;
    }

    printf("hashed password: %s\n", hash);
    fflush(stdout);



    get_paths(hash);

    /* printf("\npath to add: "); */
    /* scanf("%s", new_path); */

    add_path(hash,"../../prova.txt");
    add_path(hash,"../../prova2.txt");
    add_path(hash,"../../prova3.txt");
    get_paths(hash);


    rm_path(hash, "../../prova2.txt");
    get_paths(hash);
    rm_path(hash, "../../prova2.txt");
    rm_path(hash, "../../prova3.txt");
    get_paths(hash);
    rm_path(hash, "../../prova.txt");
    get_paths(hash);

    rm_path(hash, "../hash_sha256");
    get_paths(hash);

    return 0;

}
