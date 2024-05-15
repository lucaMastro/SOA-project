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

    if (argc < 2){
        printf("[*] usage: %s <num_of_paths_to_retrieve>\n", argv[0]);
        return -1;
    }

    char password[MAX_PASS_LEN] = {0};
    printf("Give me monitor password: ");
    get_pass(password, MAX_PASS_LEN);


    paths_to_retrieve = (int) strtol(argv[1], &endptr, 10);
    if (*endptr != '\0'){
        printf("error: invalid integer given\n");
        return -1;
    }

    seteuid(0);
    setegid(0);

    get_paths(password, paths_to_retrieve);
    return 0;
}
