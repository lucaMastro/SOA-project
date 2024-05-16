#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include "./lib/input_password.h"
#include "./lib/system_calls.h"
#include "../lib/max_parameters.h"



int main(int argc, char** argv){
    int ret;
    char *path_to_rm;
    int paths_to_retrieve;
    char *endptr;

    char old_password[MAX_PASS_LEN] = {0};
    char new_password[MAX_PASS_LEN] = {0};
    char new_password_conf[MAX_PASS_LEN] = {0};

    printf("Give me old monitor password: ");
    get_pass(old_password, MAX_PASS_LEN);

    printf("Give me new monitor password: ");
    get_pass(new_password, MAX_PASS_LEN);

    printf("Give me again new monitor password: ");
    get_pass(new_password_conf, MAX_PASS_LEN);

    if (strcmp(new_password, new_password_conf) != 0){
        printf("error: new passwords are different\n");
        return -1;
    }


    change_monitor_password(old_password, new_password);
    return 0;
}
