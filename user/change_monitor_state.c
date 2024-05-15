#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include "./lib/input_password.h"
#include "./lib/system_calls.h"
#include "../lib/max_parameters.h"
#include "../lib/reference_monitor_states.h"



int main(int argc, char** argv){
    int ret;
    char *new_monitor_state;
    unsigned char new_monitor_state_value;

    if (argc < 2){
        printf("[*] usage: %s <new_monitor_state>\n", argv[0]);
        return -1;
    }

    char password[MAX_PASS_LEN] = {0};
    printf("Give me monitor password: ");
    get_pass(password, MAX_PASS_LEN);

    seteuid(0);
    setegid(0);

    new_monitor_state = (char*) argv[1];

    if (strcmp(new_monitor_state, "ON") == 0
            || strcmp(new_monitor_state, "on") == 0) {
        new_monitor_state_value = ON;
    }
    else if (strcmp(new_monitor_state, "OFF") == 0 ||
            strcmp(new_monitor_state, "off") == 0) {
        new_monitor_state_value = OFF;
    }
    else if (strcmp(new_monitor_state, "RECON") == 0 ||
            strcmp(new_monitor_state, "recon") == 0) {
        new_monitor_state_value = RECON;
    }
    else if (strcmp(new_monitor_state, "RECOFF") == 0 ||
            strcmp(new_monitor_state, "recoff") == 0) {
        new_monitor_state_value = RECOFF;
    }
    else{
        new_monitor_state_value = INVALID_STATE;
    }

    change_monitor_state(password, new_monitor_state_value);

    return 0;
}


