#ifndef MAX_LEN
#define MAX_LEN 256
#endif

#ifndef HASH_SIZE
#define HASH_SIZE 32
#endif


#ifndef DEFERRED_WORK_H
#define DEFERRED_WORK_H


typedef struct _deferred_work_t {
    pid_t tgid;
    pid_t pid;
    uid_t uid;
    uid_t euid;
    char command_path[MAX_LEN];
    // since it will be stored on a file, i will trace the hex represantation of the hash
    char command_hash[HASH_SIZE * 2 + 1];
    struct work_struct the_work;
} deferred_work_t;
#endif
