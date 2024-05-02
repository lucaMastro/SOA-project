
#ifndef SYS_CALL_HELPER

#define SYS_CALL_HELPER

#define MAX_FREE 15


typedef struct _sys_call_helper_t {

    unsigned long **hacked_syscall_tbl;
    /* indexes to use starting from hacked syscall table to reach ni_syscalls */
    int free_entries[MAX_FREE];
    /* how many free entries has been found? */
    int free_entries_count;
    /* which index was the last used to register a new syscall?? */
    int last_entry_used;
    /* register a new syscall: */
    int (*install_syscall)(unsigned long*);
    /* uninstall all syscalls: */
    void (*uninstall_syscalls)(void);


} sys_call_helper_t;



#endif
