#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/errno.h>
#include <linux/device.h>
#include <linux/kprobes.h>
#include <linux/mutex.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/interrupt.h>
#include <linux/time.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <asm/page.h>
#include <asm/cacheflush.h>
#include <asm/apic.h>
#include <linux/syscalls.h>
#include <linux/string.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <linux/unistd.h>
#include <linux/syscalls.h>
#include <linux/namei.h>
#include <crypto/skcipher.h>
#include <linux/scatterlist.h>
#include <linux/fs_struct.h>
#include <linux/mm_types.h>

#include "../lib/syscall_helper.h"
#include "../reference-monitor-kprobes/lib/reference_monitor.h"
#include "../lib/module_lad.h"
#include "../lib/user_error_code.h"


extern reference_monitor_t reference_monitor;
extern sys_call_helper_t sys_call_helper;

#define MODNAME "Sys_call installer"

#define CHECK_EUID 1


static int installed_syscall[MAX_FREE];
module_param_array(installed_syscall,int, NULL, 0444);
MODULE_PARM_DESC(installed_syscall, "Installed syscall entries");

/* --------------------------------------------------------- */
/* this function works with kernel addresses only: */

int check_password(char *pass_plaintext,ssize_t len){
    char digest[HASH_SIZE + 1];
    int ret;
    // compute hash invoke kmalloc: BEWARE TO INVOKE OUTSIDE CRITICAL SECTIONS
    ret = compute_hash(pass_plaintext, len, digest);
    if (ret != 0){
        printk("%s: error computing hash\n", MODNAME);
        return -1;
    }
    digest[HASH_SIZE] = '\0';

    /* ----------- CRITICAL SECTION ------------ */
    spin_lock(&(reference_monitor.lock));
    ret = strcmp(digest, reference_monitor.hashed_pass);
    spin_unlock(&(reference_monitor.lock));
    /* ----------- CRITICAL SECTION END ------------ */

    return ret;
}

/* --------------------------------------------------------- */
/* ----------SYSCALL DEFINITION -----------------*/
__SYSCALL_DEFINEx(2, _add_path, char* __user, monitor_pass, char* __user, new_path){

    int ret;
    char *user_pass;
    char *k_new_path;
    ssize_t len;
    int euid;

    /* euid check: */
    euid = current->cred->euid.val;
    if (CHECK_EUID && euid != 0)
    {
        printk("%s: inappropriate effective euid: %d in add_path\n", MODNAME, euid);
        return -EINAPPROPRIATE_EUID;
    }

    // this counts the '\0'. It has to be excluded in password check
    len = strnlen_user(monitor_pass, MAX_PASS_LEN);
    if (len > MAX_PASS_LEN){
        printk("DEBUG: strnlen returned len > MAX_PASS_LEN: %ld > %d\n", len, MAX_PASS_LEN);
        return -EWRONG_PW;
    }
    user_pass = (char*) kmalloc(sizeof(char) * len, GFP_KERNEL);
    if (user_pass == NULL){
        printk("%s: error allocating buffer for pass digest\n", MODNAME);
        return -1;
    }

    ret = copy_from_user(user_pass, monitor_pass, len);
	if(ret != 0) {
        printk("%s: error: copy_from_user compare passwd\n",MODNAME);
        return -1;
    }

    /* checking password: */
    ret = check_password(user_pass, len - 1);
    kfree(user_pass);
    if (ret != 0){
        printk("%s: error: wrong monitor password in add_path.\n",MODNAME);
        return -EWRONG_PW;
    }

    // new_len
    len = strnlen_user(new_path, MAX_PATH_LEN);
    k_new_path = (char*) kmalloc(sizeof(char) * len, GFP_KERNEL);
    if (k_new_path == NULL){
        printk("%s: error allocating buffer for pass digest\n", MODNAME);
        return -1;
    }
    ret = copy_from_user(k_new_path, new_path, len);
	if(ret != 0) {
        printk("%s: error: copy_from_user k_new_path\n",MODNAME);
        return -1;
    }

    /* ----------- CRITICAL SECTION ------------ */
    spin_lock(&(reference_monitor.lock));

    /* adding path */
    ret = reference_monitor.add_path(k_new_path);
    kfree(k_new_path);
    if (ret < 0){
	    spin_unlock(&(reference_monitor.lock));
        printk("%s: error adding path:\n",MODNAME);
        return ret;
    }
    spin_unlock(&(reference_monitor.lock));
    /* ----------- CRITICAL SECTION END ------------ */

    printk("%s: path added successfully\n",MODNAME);
    return 0;

}
static unsigned long sys_add_path = (unsigned long) __x64_sys_add_path;

/* ----------------------------------------------*/

/*
    returns number of path delivered to user
*/
__SYSCALL_DEFINEx(3, _get_paths, char* __user, monitor_pass, char** __user, buffer, int, max_num_of_path_to_retrieve){
    int i, min, ret;
    char *user_pass;
    ssize_t len;
    char *current_path;
    int euid;
    int tmp_paths_len;
    char __user * tmp;

    int buf_size;
    char **paths_snapshot;

    /* euid check: */
    euid = current->cred->euid.val;
    if (CHECK_EUID && euid != 0)
    {
        printk("%s: inappropriate effective euid: %d in get_paths\n", MODNAME, euid);
        return -EINAPPROPRIATE_EUID;
    }

    // this counts the '\0'. It has to be excluded in password check
    len = strnlen_user(monitor_pass, MAX_PASS_LEN);
    if (len > MAX_PASS_LEN){
        printk("DEBUG: strnlen returned len > MAX_PASS_LEN: %ld > %d\n", len, MAX_PASS_LEN);
        return -1;
    }

    user_pass = (char*) kmalloc(sizeof(char) * len, GFP_KERNEL);
    if (user_pass == NULL){
        printk("%s: error allocating buffer for pass digest\n", MODNAME);
        return -1;
    }

    ret = copy_from_user(user_pass, monitor_pass, len);
	if(ret != 0) {
        printk("%s: error: copy_from_user compare passwd\n",MODNAME);
        return -1;
    }

    /* checking password: */
    ret = check_password(user_pass, len - 1);
    if (ret != 0){
        printk("%s: error: wrong monitor password in get_paths\n",MODNAME);
        return -EWRONG_PW;
    }

    /*
        buffer will be initialized with the minimal size between the user param and
        the actual size of the reference_monitor.paths_len. This value is
        needed just to inizialize a properly buffer outsite the critical section.
        In the critical section, another check on the size is required to compute a
        minimal value between the buff_size and the paths_len size.
        if meanwhile
            rm path occurs: this buffer will not be fullfilled
            add path occurs: this buffer will not keep all the paths
    */
    tmp_paths_len = reference_monitor.filtered_paths_len;
    buf_size = max_num_of_path_to_retrieve < tmp_paths_len ? max_num_of_path_to_retrieve : tmp_paths_len;
    paths_snapshot = (char**) kmalloc(sizeof(char*) * buf_size, GFP_KERNEL);
    if (paths_snapshot == NULL){
        printk("%s: error allocating buffer for paths\n", MODNAME);
        return -1;
    }
    for (i=0; i < buf_size; i++){
        paths_snapshot[i] = (char*) kmalloc(sizeof(char) * MAX_PATH_LEN, GFP_KERNEL);
        if (paths_snapshot[i] == NULL){
            printk("%s: error allocating buffer[%d] for paths\n", MODNAME, i);
            return -1;
        }
    }

    /* ----------- CRITICAL SECTION ------------ */
    spin_lock(&(reference_monitor.lock));
    min = reference_monitor.filtered_paths_len < buf_size ? reference_monitor.filtered_paths_len : buf_size;

    for (i=0; i < min; i++){
        current_path = reference_monitor.get_path(i);
        snprintf(paths_snapshot[i], MAX_PATH_LEN, "%s", current_path);
        kfree(current_path);
    }
    spin_unlock(&(reference_monitor.lock));
    /* ----------- CRITICAL SECTION END ------------ */

    // need now to copy_to_user
    for (i=0; i < min; i++){
        current_path = paths_snapshot[i];

        ret = get_user(tmp, buffer + i);
        if (ret > 0){
            printk("%s: error retrieving destination user address for %s\n", MODNAME, current_path);
        }
        ret = copy_to_user(tmp, current_path, strlen(current_path));
        if (ret > 0){
            printk("%s: not fully deliver %s\n", MODNAME, current_path);
        }
    }
    kfree(paths_snapshot);
    return min;

}
static unsigned long sys_get_paths = (unsigned long) __x64_sys_get_paths;

/* ----------------------------------------------*/

__SYSCALL_DEFINEx(2, _rm_path, char* __user, monitor_pass, char* __user, path_to_remove){

    int ret;
    char *user_pass;
    char *k_path_to_remove;
    ssize_t len;
    int euid;

    /* euid check: */
    euid = current->cred->euid.val;
    if (CHECK_EUID && euid != 0)
    {
        printk("%s: inappropriate effective euid: %d in rm_path,\n", MODNAME, euid);
        return -EINAPPROPRIATE_EUID;
    }

    // this counts the '\0'. It has to be excluded in password check
    len = strnlen_user(monitor_pass, MAX_PASS_LEN);
    if (len > MAX_PASS_LEN){
        printk("DEBUG: strnlen returned len > MAX_PASS_LEN: %ld > %d\n", len, MAX_PASS_LEN);
        return -1;
    }
    user_pass = (char*) kmalloc(sizeof(char) * len, GFP_KERNEL);
    if (user_pass == NULL){
        printk("%s: error allocating buffer for pass digest\n", MODNAME);
        return -1;
    }

    ret = copy_from_user(user_pass, monitor_pass, len);
	if(ret != 0) {
        printk("%s: error: copy_from_user compare passwd\n",MODNAME);
        return -1;
    }

    /* checking password: */
    ret = check_password(user_pass, len - 1);
    kfree(user_pass);
    if (ret != 0){
        printk("%s: error: wrong monitor password in rm_paths\n",MODNAME);
        return -EWRONG_PW;
    }

    len = strnlen_user(path_to_remove, MAX_PATH_LEN);
    k_path_to_remove = (char*) kmalloc(sizeof(char) * len, GFP_KERNEL);
    if (k_path_to_remove == NULL){
        printk("%s: error allocating buffer for path to remove\n", MODNAME);
        return -1;
    }

    ret = copy_from_user(k_path_to_remove, path_to_remove, len);
	if(ret != 0) {
        printk("%s: error: copy_from_user k_path_to_remove\n",MODNAME);
        return -1;
    }


    /* ----------- CRITICAL SECTION ------------ */
	spin_lock(&(reference_monitor.lock));
     /* removing path */
    ret = reference_monitor.rm_path(k_path_to_remove);
    kfree(k_path_to_remove);
    if (ret < 0){
	    spin_unlock(&(reference_monitor.lock));
        printk("%s: error removing path\n",MODNAME);
        return ret;
    }
    spin_unlock(&(reference_monitor.lock));
    /* ----------- CRITICAL SECTION END ------------ */

    printk("%s: path removed successfully\n",MODNAME);
    return 0;

}
static unsigned long sys_rm_path = (unsigned long) __x64_sys_rm_path;

/* ----------------------------------------------*/


__SYSCALL_DEFINEx(2, _change_monitor_password, char*, old_pass, char*, new_pass){

    int ret;
    char *old_pass_k;
    char *new_pass_k;
    char new_hash[HASH_SIZE];
    ssize_t len;
    int euid;

    /* euid check: */
    euid = current->cred->euid.val;
    if (CHECK_EUID && euid != 0)
    {
        printk("%s: inappropriate effective euid: %d in change_monitor_password\n", MODNAME, euid);
        return -EINAPPROPRIATE_EUID;
    }

    // this counts the '\0'. It has to be excluded in password check
    len = strnlen_user(old_pass, MAX_PASS_LEN);
    if (len > MAX_PASS_LEN){
        printk("DEBUG: strnlen returned len > MAX_PASS_LEN: %ld > %d\n", len, MAX_PASS_LEN);
        return -1;
    }
    old_pass_k = (char*) kmalloc(sizeof(char) * len, GFP_KERNEL);
    if (old_pass_k == NULL){
        printk("%s: error allocating buffer for pass digest\n", MODNAME);
        return -1;
    }

    ret = copy_from_user(old_pass_k, old_pass, len);
	if(ret != 0) {
        printk("%s: error: copy_from_user compare passwd\n",MODNAME);
        return -1;
    }

    new_pass_k = (char*) kmalloc(sizeof(char) * len, GFP_KERNEL);
    if (new_pass_k == NULL){
        printk("%s: error allocating buffer for pass digest\n", MODNAME);
        return -1;
    }
    // this counts the '\0'. It has to be excluded in password check
    len = strnlen_user(new_pass, MAX_PASS_LEN);
    if (len > MAX_PASS_LEN){
        printk("DEBUG: strnlen returned len > MAX_PASS_LEN: %ld > %d\n", len, MAX_PASS_LEN);
        return -1;
    }

    ret = copy_from_user(new_pass_k, new_pass, len);
	if(ret != 0) {
        printk("%s: error: copy_from_user compare passwd\n",MODNAME);
        return -1;
    }

     /* checking password: */
    ret = check_password(old_pass_k, len - 1);
    kfree(old_pass_k);
    if (ret != 0){
        printk("%s: error: wrong monitor password in change_monitor_password\n",MODNAME);
        return -EWRONG_PW;
    }

    ret = compute_hash(new_pass_k, len - 1, new_hash);
    kfree(new_pass_k);
    if (ret != 0){
        printk("%s: error: hashing new password\n",MODNAME);
        return -1;
    }

    /* ----------- CRITICAL SECTION ------------ */
	spin_lock(&(reference_monitor.lock));
    /* updating password: */
    memcpy(reference_monitor.hashed_pass, new_hash, HASH_SIZE);
	spin_unlock(&(reference_monitor.lock));
    /* ----------- CRITICAL SECTION END ------------ */


    printk("%s: password changed successfully\n", MODNAME);

    return 0;

}
static unsigned long sys_change_monitor_password = (unsigned long) __x64_sys_change_monitor_password;

/* ----------------------------------------------*/

__SYSCALL_DEFINEx(2, _change_monitor_state, char* __user, monitor_pass, unsigned char, new_state){
    int ret;
    char *user_pass;
    ssize_t len;
    int euid;

    /* euid check: */
    euid = current->cred->euid.val;
    if (CHECK_EUID && euid != 0)
    {
        printk("%s: inappropriate effective euid: %d in change_monitor_state\n", MODNAME, euid);
        return -EINAPPROPRIATE_EUID;
    }
    // this counts the '\0'. It has to be excluded in password check
    len = strnlen_user(monitor_pass, MAX_PASS_LEN);
    if (len > MAX_PASS_LEN){
        printk("DEBUG: strnlen returned len > MAX_PASS_LEN: %ld > %d\n", len, MAX_PASS_LEN);
        return -1;
    }
    user_pass = (char*) kmalloc(sizeof(char) * len, GFP_KERNEL);
    if (user_pass == NULL){
        printk("%s: error allocating buffer for pass digest\n", MODNAME);
        return -1;
    }

    ret = copy_from_user(user_pass, monitor_pass, len);
	if(ret != 0) {
        printk("%s: error: copy_from_user compare passwd\n",MODNAME);
        return -1;
    }

    /* checking password: */
    ret = check_password(user_pass, len - 1);
    kfree(user_pass);
    if (ret != 0){
        printk("%s: error: wrong monitor password in change_monitor_state\n",MODNAME);
        return -EWRONG_PW;
    }

    /* ----------- CRITICAL SECTION ------------ */
    spin_lock(&(reference_monitor.lock));
    ret = reference_monitor.set_state(new_state);
    if (ret < 0){
        spin_unlock(&(reference_monitor.lock));
        printk("%s error: something went wrong changing state\n", MODNAME);
        return ret;
    }
    spin_unlock(&(reference_monitor.lock));
    /* ----------- CRITICAL SECTION END ------------ */
    return 0;

}
static unsigned long sys_change_monitor_state = (unsigned long) __x64_sys_change_monitor_state;

/* ----------------------------------------------*/



int init_module(void) {
    int index;

    printk("%s: initializing. There are %d slot avaiable to install new syscalls\n",MODNAME, sys_call_helper.free_entries_count);

    index = sys_call_helper.install_syscall((unsigned long *) sys_add_path);
    printk("%s: installed sys_add at %d\n",MODNAME, index);
    index = sys_call_helper.install_syscall((unsigned long *) sys_get_paths);
    printk("%s: installed sys_get_paths at %d\n",MODNAME, index);
    index = sys_call_helper.install_syscall((unsigned long *) sys_rm_path);
    printk("%s: installed sys_rm_path at %d\n",MODNAME, index);
    index = sys_call_helper.install_syscall((unsigned long *) sys_change_monitor_password);
    printk("%s: installed sys_change_monitor_password at %d\n",MODNAME, index);
    index = sys_call_helper.install_syscall((unsigned long *) sys_change_monitor_state);
    printk("%s: installed sys_change_monitor_state at %d\n",MODNAME, index);

    for (index = 0; index <= sys_call_helper.last_entry_used; index ++){
        installed_syscall[index] = sys_call_helper.free_entries[index];
    }

    return 0;

}

void cleanup_module(void) {

    sys_call_helper.uninstall_syscalls();
    printk("%s: shutting down\n",MODNAME);

}
