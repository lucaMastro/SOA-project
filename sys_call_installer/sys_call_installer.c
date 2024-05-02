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


/*
   @TODO: move to a copy_from_user && copy_to_user representation
   @TODO: add checks on euid
*/


/* --------------------------------------------------------- */
/* ----------SYSCALL DEFINITION -----------------*/
__SYSCALL_DEFINEx(2, _add_path, char* __user, monitor_pass, char* __user, new_path){

    int ret;
    char user_pass[HASH_SIZE * 2 + 1];
    char current_pass[HASH_SIZE * 2 + 1];

    ret = copy_from_user(user_pass, monitor_pass, HASH_SIZE * 2);
    user_pass[HASH_SIZE * 2] = '\0';
	if(ret != 0) {
        printk("%s: error: copy_from_user compare passwd\n",MODNAME);
        return -1;
    }
    /* checking password: */
    bin2hex(current_pass, reference_monitor.hashed_pass, HASH_SIZE);
    current_pass[HASH_SIZE * 2] = '\0';

    if (strcmp(user_pass, current_pass) != 0){
        printk("%s: error: wrong monitor password in add_path:\n%s.\n%s.\n",MODNAME, user_pass, current_pass);
        return -1;
    }

    /* adding path */
    ret = reference_monitor.add_path(new_path);
    if (ret < 0){
        printk("%s: error adding path\n",MODNAME);
        return -2;
    }

    printk("%s: path added successfully\n",MODNAME);
    return 0;

}
static unsigned long sys_add_path = (unsigned long) __x64_sys_add_path;

/* ----------------------------------------------*/

__SYSCALL_DEFINEx(3, _compute_hash, char* __user, plain_text,int, input_size, char* __user, output_buffer){
    char hash[HASH_SIZE];
    int ret;
    int min;

    char *plain_text_k;
    char output_buffer_k[HASH_SIZE * 2 + 1];

    min = input_size <= strlen(plain_text) ? input_size : strlen(plain_text);
    plain_text_k = (char*) kmalloc(sizeof(char) * min + 1, GFP_KERNEL);
    if (plain_text_k == NULL) {
        printk("%s: error allocating memory in compute hash\n", MODNAME);
    }
    ret = copy_from_user(plain_text_k, plain_text, min);
	if(ret != 0) {
        printk("%s: error: copy_from_user hashing plain_text\n",MODNAME);
        return -1;
    }
    plain_text_k[min] = '\0';

    ret = compute_hash(plain_text_k, min, hash);

    bin2hex(output_buffer_k, hash, HASH_SIZE);
    /* return hex_hash; */
    output_buffer_k[HASH_SIZE * 2] = '\0';

    copy_to_user(output_buffer, output_buffer_k, HASH_SIZE * 2 + 1);
    return 0;
}
static unsigned long sys_compute_hash = (unsigned long) __x64_sys_compute_hash;

/* ----------------------------------------------*/

__SYSCALL_DEFINEx(3, _get_paths, char* __user, monitor_pass, char** __user, buffer, int, max_num_of_path_to_retrieve){
    int i, min, ret;
    char user_pass[HASH_SIZE * 2 + 1];
    char current_pass[HASH_SIZE * 2 + 1];

    ret = copy_from_user(user_pass, monitor_pass, HASH_SIZE * 2);
	if(ret != 0) {
        printk("%s: error: copy_from_user compare passwd\n",MODNAME);
        return -1;
    }
    user_pass[HASH_SIZE * 2] = '\0';
    /* checking password: */
    bin2hex(current_pass, reference_monitor.hashed_pass, HASH_SIZE);
    current_pass[HASH_SIZE * 2] = '\0';
    if (strcmp(user_pass, current_pass) != 0){
        printk("%s: error: wrong monitor password in add_path\n",MODNAME);
        return -1;
    }

    min = max_num_of_path_to_retrieve < reference_monitor.paths_len ? max_num_of_path_to_retrieve : reference_monitor.paths_len;

    for (i=0; i < min; i++){
        copy_to_user(buffer[i], reference_monitor.paths[i], strlen(reference_monitor.paths[i]));
    }

    return 0;

}
static unsigned long sys_get_paths = (unsigned long) __x64_sys_get_paths;

/* ----------------------------------------------*/

__SYSCALL_DEFINEx(2, _rm_path, char*, monitor_pass, char*, path_to_remove){

    int ret;
    char user_pass[HASH_SIZE * 2 + 1];
    char current_pass[HASH_SIZE * 2 + 1];

    ret = copy_from_user(user_pass, monitor_pass, HASH_SIZE * 2);
    user_pass[2 * HASH_SIZE] = '\0';
	if(ret != 0) {
        printk("%s: error: copy_from_user compare passwd\n",MODNAME);
        return -1;
    }
    /* checking password: */
    bin2hex(current_pass, reference_monitor.hashed_pass, HASH_SIZE);
    current_pass[2 * HASH_SIZE] = '\0';
    if (strcmp(user_pass, current_pass) != 0){
        printk("%s: error: wrong monitor password in remove_path\n",MODNAME);
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
int init_module(void) {
    int index;
    printk("%s: initializing. There are %d slot avaiable to install new syscalls\n",MODNAME, sys_call_helper.free_entries_count);

    index = sys_call_helper.install_syscall((unsigned long *) sys_add_path);
    printk("%s: installed sys_add at %d\n",MODNAME, index);
    index = sys_call_helper.install_syscall((unsigned long *) sys_compute_hash);
    printk("%s: installed sys_compute_hash at %d\n",MODNAME, index);
    index = sys_call_helper.install_syscall((unsigned long *) sys_get_paths);
    printk("%s: installed sys_get_paths at %d\n",MODNAME, index);
    index = sys_call_helper.install_syscall((unsigned long *) sys_rm_path);
    printk("%s: installed sys_rm_path at %d\n",MODNAME, index);

    return 0;

}

void cleanup_module(void) {

    sys_call_helper.uninstall_syscalls();
    printk("%s: shutting down\n",MODNAME);

}
