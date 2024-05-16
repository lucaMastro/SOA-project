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

    if (argc < 2){
        printf("[*] usage: %s <path_to_rm>\n", argv[0]);
        return -1;
    }

    char password[MAX_PASS_LEN] = {0};
    printf("Give me monitor password: ");
    get_pass(password, MAX_PASS_LEN);

    path_to_rm = (char*) argv[1];
    rm_path(password, path_to_rm);

    return 0;
}
