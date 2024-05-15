#ifndef SYSTEM_CALLS_H

#define SYSTEM_CALLS_H

int get_paths(char *pass, int paths_num_to_retrieve);
int add_path(char *pass, char *new_path);
int rm_path(char *pass, char* path);
int change_monitor_password(char *old_pass, char *new_pass);
int change_monitor_state(char *pass, unsigned char new_state);

#endif
