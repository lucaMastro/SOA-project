
#ifndef REFERECE_MONITOR_H
#define REFERECE_MONITOR_H

/*
    2 bits: least relevants. The least relevant one is about filterning activity: 0 doesnt filter, 1 filter.
    The other one is about reconfiguration: 0 cannot reconfigure, 1 can
*/
#define OFF     0x0 // 00
#define ON      0x1 // 01
#define RECOFF  0x2 // 10
#define RECON   0x3 // 11


typedef struct _reference_monitor_t {
    unsigned char state;
    // this will keep sha256 pass
    char hashed_pass[32];
    spinlock_t lock;
    char **paths;
    int paths_len;
    int (*add_path)(const char *new_path);
    int (*rm_path)(const char *path);
} reference_monitor_t;
#endif
