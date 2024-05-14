
#ifndef REFERECE_MONITOR_H
#define REFERECE_MONITOR_H

#include "../../lib/hash_helper.h"
#include "../../lib/max_parameters.h"
#include "../../lib/reference_monitor_states.h"


typedef struct _reference_monitor_t {
    unsigned char state;
    // this will keep sha256 pass
    char hashed_pass[HASH_SIZE];
    spinlock_t lock;
    struct dentry **filtered_paths;
    int filtered_paths_len;
    int (*add_path)(const char *new_path);
    int (*rm_path)(const char *path);
    char* (*get_path)(int index);
    void (*set_state)(unsigned char state);
} reference_monitor_t;



typedef struct _deferred_work_t {
    pid_t tgid;
    pid_t pid;
    uid_t uid;
    uid_t euid;
    char command_path[MAX_PATH_LEN];
    // since it will be stored on a file, i will trace the hex represantation of the hash
    char command_hash[HASH_SIZE * 2 + 1];
    struct work_struct the_work;
} deferred_work_t;

#endif
