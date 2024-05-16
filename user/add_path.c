#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include "./lib/input_password.h"
#include "./lib/system_calls.h"
#include "../lib/max_parameters.h"



int main(int argc, char** argv){
    int ret;
    char *new_path;

    if (argc < 2){
        printf("[*] usage: %s <path_to_add>\n", argv[0]);
        return -1;
    }

    char password[MAX_PASS_LEN] = {0};
    printf("Give me monitor password: ");
    get_pass(password, MAX_PASS_LEN);

    new_path = (char*) argv[1];
    add_path(password, new_path);

    return 0;
}
