
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


int change_monitor_password(char *old_pass, char *new_pass){
    int ret;
    printf("changing password...\n");
	/* ret = syscall(SYS_RM, hash, new_path); */
	ret = syscall(SYS_CHANGE_PASS, old_pass, new_pass);
    if (ret < 0){
        printf("something went wrong changing password\n");
        return ret;
    }

    printf("password changed successfully\n");
    return 0;
}


int main(int argc, char** argv){
    int ret;

    char hash[65];
    char new_hash[65];
    char new_path[256];
    char *static_new_path, *static_new_path_2;
    int len;
    /* char plain_text[256]; */
    /* printf("reference monitor password: "); */
    /* scanf("%s", plain_text); */

    seteuid(0);
    setegid(0);
    char *plain_text = "asd";
    char *new_plain_text = "lol";
    len = strlen(plain_text);


    change_monitor_password(plain_text, new_plain_text);
    get_paths(new_plain_text);

    /* printf("\npath to add: "); */
    /* scanf("%s", new_path); */

    add_path(new_plain_text, "../../prova.txt");
    /* add_path(new_hash,"../../prova2.txt"); */
    /* add_path(new_hash,"../../prova3.txt"); */
    /* get_paths(new_hash); */


    /* rm_path(new_hash, "../../prova2.txt"); */
    get_paths(new_plain_text);
    /* rm_path(new_hash, "../../prova2.txt"); */
    /* rm_path(new_hash, "../../prova3.txt"); */
    /* get_paths(new_hash); */
    rm_path(new_plain_text, "../../prova.txt");
    /* get_paths(new_hash); */

    /* rm_path(new_hash, "../hash_sha256"); */
    get_paths(new_plain_text);

    return 0;

}
