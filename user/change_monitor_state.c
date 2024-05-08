
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

/*
    @TODO: add the hidden way to get the password
*/

#define SYS_CHANGE_STATE    178




int change_monitor_state(char *pass, unsigned char new_state){
    int ret;
    printf("changing state...\n");
	/* ret = syscall(SYS_RM, hash, new_path); */
	ret = syscall(SYS_CHANGE_STATE, pass, new_state);
    if (ret < 0){
        printf("something went wrong changing state\n");
        return ret;
    }

    printf("state changed successfully\n");
    return 0;
}


int main(int argc, char** argv){
    int ret;
    unsigned char new_state;
    /* char plain_text[256]; */
    /* printf("reference monitor password: "); */
    /* scanf("%s", plain_text); */

    seteuid(0);
    setegid(0);
    char *plain_text = "asd";

    new_state = 3;

    change_monitor_state(plain_text, new_state);

    return 0;

}
