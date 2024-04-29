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

int compute_hash(char *input_string, int input_size, char *output_buffer) {
    printk("%s: compute_hash start\n",MODNAME);
    struct crypto_shash *tfm;
    struct shash_desc *desc;
    int ret;

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
   @TODO: find a way to define the syscall number such that user can use it to invoke syscall
*/

/* ----------SYSCALL DEFINITION -----------------*/
__SYSCALL_DEFINEx(2, _add_path, char*, monitor_pass, char*, new_path){

    int ret;
    /* checking password: */
    char current_pass[HASH_SIZE * 2];
    bin2hex(current_pass, reference_monitor.hashed_pass, HASH_SIZE);

    if (strcmp(current_pass, monitor_pass) != 0){
        printk("%s: error: wrong monitor pass password\n",MODNAME);
        return -1;
    }

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

__SYSCALL_DEFINEx(3, _compute_hash, char*, plain_text,int, input_size, char*, output_buffer){
    char hash[HASH_SIZE];
    printk("%s: asked %s on %s of size %d\n", MODNAME, HASH_FUNC, plain_text, input_size);
    int ret = compute_hash(plain_text, input_size, hash);
    printk("%s: asked %s on %s of size %d\n", MODNAME, HASH_FUNC, plain_text, input_size);

    bin2hex(output_buffer, hash, HASH_SIZE);
    /* return hex_hash; */
    output_buffer[HASH_SIZE * 2] = '\0';
    return 0;
}
static unsigned long sys_compute_hash = (unsigned long) __x64_sys_compute_hash;

/* ----------------------------------------------*/



int init_module(void) {

    printk("%s: initializing. There are %d slot avaiable to install new syscalls\n",MODNAME, sys_call_helper.free_entries_count);

    sys_call_helper.install_syscall(sys_add_path);
    sys_call_helper.install_syscall(sys_compute_hash);
    printk("%s: installed sys_add\n",MODNAME);

    return 0;

}

void cleanup_module(void) {

    sys_call_helper.uninstall_syscalls();
    printk("%s: shutting down\n",MODNAME);

}
