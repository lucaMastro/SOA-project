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

#include "../Linux-sys_call_table-discoverer/lib/syscall_helper.h"
#include "../reference-monitor-kprobes/lib/reference_monitor.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Luca Mastrobattista");
MODULE_DESCRIPTION("see the README file");

extern reference_monitor_t reference_monitor;
extern sys_call_helper_t sys_call_helper;

#define MODNAME "Sys_call installer"

#define HASH_FUNC "sha256"
#define HASH_SIZE 32
#define MAX_PASS_LEN 256
#define CHECK_EUID 0


/* --------------------------------------------------------- */
/* those functions works with kernel addresses only: */

int compute_hash(char *input_string, int input_size, char *output_buffer) {
    struct crypto_shash *tfm;
    struct shash_desc *desc;
    int ret;

    printk("%s: compute_hash start\n",MODNAME);
    tfm = crypto_alloc_shash(HASH_FUNC, 0, 0);
    if (IS_ERR(tfm)) {
        printk("%s: error initializing transform\n", MODNAME);
        return PTR_ERR(tfm);
    }

    desc = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (desc == NULL) {
        printk("%s: error initializing hash description\n", MODNAME);
        crypto_free_shash(tfm);
        return -ENOMEM;
    }

    desc->tfm = tfm;

    ret = crypto_shash_digest(desc, input_string, input_size, output_buffer);
    if (ret < 0) {
        printk("%s: error initializing hash computation\n", MODNAME);
        kfree(desc);
        crypto_free_shash(tfm);
        return ret;
    }

    kfree(desc);
    crypto_free_shash(tfm);

    return 0;
}


int check_password(char *pass_plaintext,ssize_t len){
    char digest[HASH_SIZE + 1];
    int ret;
    ret = compute_hash(pass_plaintext, len, digest);
    if (ret != 0){
        printk("%s: error computing hash\n", MODNAME);
        return -1;
    }
    digest[HASH_SIZE] = '\0';
    return strcmp(digest, reference_monitor.hashed_pass);
}

/*
   @TODO: add checks on euid
*/


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
        return -1;
    }

    // this counts the '\0'. It has to be excluded in password check
    len = strnlen_user(monitor_pass, MAX_PASS_LEN);
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
        return -1;
    }

    /* adding path */
    len = strnlen_user(new_path, MAX_PASS_LEN);
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

    ret = reference_monitor.add_path(k_new_path);
    kfree(k_new_path);
    if (ret < 0){
        printk("%s: error adding path\n",MODNAME);
        return -2;
    }

    printk("%s: path added successfully\n",MODNAME);
    return 0;

}
static unsigned long sys_add_path = (unsigned long) __x64_sys_add_path;

/* ----------------------------------------------*/


__SYSCALL_DEFINEx(3, _get_paths, char* __user, monitor_pass, char** __user, buffer, int, max_num_of_path_to_retrieve){
    int i, min, ret;
    char *user_pass;
    ssize_t len;
    int euid;
    char *current_path;

    /* euid check: */
    euid = current->cred->euid.val;
    if (CHECK_EUID && euid != 0)
    {
        printk("%s: inappropriate effective euid: %d in get_paths\n", MODNAME, euid);
        return -1;
    }
    // this counts the '\0'. It has to be excluded in password check
    len = strnlen_user(monitor_pass, MAX_PASS_LEN);
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
        return -1;
    }

    min = max_num_of_path_to_retrieve < reference_monitor.filtered_paths_len ? max_num_of_path_to_retrieve : reference_monitor.filtered_paths_len;

    for (i=0; i < min; i++){
        current_path = reference_monitor.get_path(i);
        ret = copy_to_user(buffer[i], current_path, strlen(current_path));
        if (ret > 0){
            printk("%s: not fully deliver %s\n", MODNAME, current_path);
        }
        kfree(current_path);
    }

    return 0;

}
static unsigned long sys_get_paths = (unsigned long) __x64_sys_get_paths;

/* ----------------------------------------------*/

__SYSCALL_DEFINEx(2, _rm_path, char* __user, monitor_pass, char* __user, path_to_remove){

    int ret;
    char *user_pass;
    ssize_t len;
    int euid;

    /* euid check: */
    euid = current->cred->euid.val;
    if (CHECK_EUID && euid != 0)
    {
        printk("%s: inappropriate effective euid: %d in rm_path\n", MODNAME, euid);
        return -1;
    }

    // this counts the '\0'. It has to be excluded in password check
    len = strnlen_user(monitor_pass, MAX_PASS_LEN);
    user_pass = (char*) kmalloc(sizeof(char) * len, GFP_KERNEL);
    if (user_pass == NULL){
        printk("%s: error allocating buffer for pass digest\n", MODNAME);
        return -1;
    }

    ret = copy_from_user(user_pass, monitor_pass, len);
    kfree(user_pass);
	if(ret != 0) {
        printk("%s: error: copy_from_user compare passwd\n",MODNAME);
        return -1;
    }
    /* checking password: */
    ret = check_password(user_pass, len - 1);
    if (ret != 0){
        printk("%s: error: wrong monitor password in rm_paths\n",MODNAME);
        return -1;
    }
    /* removing path */
    ret = reference_monitor.rm_path(path_to_remove);
    if (ret < 0){
        printk("%s: error removing path\n",MODNAME);
        return -2;
    }

    printk("%s: path removed successfully\n",MODNAME);
    return 0;

}
static unsigned long sys_rm_path = (unsigned long) __x64_sys_rm_path;

/* ----------------------------------------------*/


__SYSCALL_DEFINEx(2, _change_monitor_password, char*, old_pass, char*, new_pass){

    int ret;
    char *old_pass_k;
    char *new_pass_k;
    ssize_t len;
    int euid;

    /* euid check: */
    euid = current->cred->euid.val;
    if (CHECK_EUID && euid != 0)
    {
        printk("%s: inappropriate effective euid: %d in change_monitor_password\n", MODNAME, euid);
        return -1;
    }

    // this counts the '\0'. It has to be excluded in password check
    len = strnlen_user(old_pass, MAX_PASS_LEN);
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
    /* checking password: */
    ret = check_password(old_pass_k, len - 1);
    kfree(old_pass_k);
    if (ret != 0){
        printk("%s: error: wrong monitor password in change_password\n",MODNAME);
        return -1;
    }

    // this counts the '\0'. It has to be excluded in password check
    len = strnlen_user(new_pass, MAX_PASS_LEN);
    new_pass_k = (char*) kmalloc(sizeof(char) * len, GFP_KERNEL);
    if (new_pass_k == NULL){
        printk("%s: error allocating buffer for pass digest\n", MODNAME);
        return -1;
    }

    ret = copy_from_user(new_pass_k, new_pass, len);
	if(ret != 0) {
        printk("%s: error: copy_from_user compare passwd\n",MODNAME);
        return -1;
    }

    /* updating password: */
    ret = compute_hash(new_pass_k, len - 1, reference_monitor.hashed_pass);
    kfree(new_pass_k);
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
        printk("%s: inappropriate effective euid: %d in get_paths\n", MODNAME, euid);
        return -1;
    }
    // this counts the '\0'. It has to be excluded in password check
    len = strnlen_user(monitor_pass, MAX_PASS_LEN);
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
        printk("%s: error: wrong monitor password in get_paths\n",MODNAME);
        return -1;
    }

    reference_monitor.set_state(new_state);

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

    return 0;

}

void cleanup_module(void) {

    sys_call_helper.uninstall_syscalls();
    printk("%s: shutting down\n",MODNAME);

}
