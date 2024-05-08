
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

/*
    @TODO: add the hidden way to get the password
*/
#define SYS_CHANGE_PASS     177



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
    /* char plain_text[256]; */
    /* printf("reference monitor password: "); */
    /* scanf("%s", plain_text); */
    /* char new_plain_text[256]; */
    /* printf("new reference monitor password: "); */
    /* scanf("%s", new_plain_text); */

    seteuid(0);
    setegid(0);
    char *plain_text = "asd";
    char *new_plain_text = "lol";

    change_monitor_password(plain_text, new_plain_text);

    return 0;

}
