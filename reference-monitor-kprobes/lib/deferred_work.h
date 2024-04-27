#ifndef DEFERRED_WORK_H
#define DEFERRED_WORK_H


typedef struct _deferred_work_t {
    pid_t tgid;
    pid_t pid;
    uid_t uid;
    uid_t euid;
    char *command_path;
    char command_hash[32];
} deferred_work_t;
#endif
