
#ifndef REFERECE_MONITOR_H
#define REFERECE_MONITOR_H

enum monitor_state_t {ON, OFF,RECON, RECOFF };


typedef struct _reference_monitor_t {
    enum monitor_state_t state;
    // this will keep sha256 pass
    char hashed_pass[32];
    spinlock_t lock;
    char **paths;
    int paths_len;
    int (*add_path)(const char *new_path);
    int (*rm_path)(const char *path);
} reference_monitor_t;
#endif
