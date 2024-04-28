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


#include <linux/namei.h>
#include <crypto/skcipher.h>
#include <linux/scatterlist.h>
#include <linux/fs_struct.h>
#include <linux/mm_types.h>










#include "lib/reference_monitor.h"
#include "lib/deferred_work.h"

#define target_func "do_filp_open" //you should modify this depending on the kernel version
//#define target_func "__x64_sys_open" //you should modify this depending on the kernel version

#define AUDIT if(1)

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Francesco Quaglia <francesco.quaglia@uniroma2.it>");
MODULE_DESCRIPTION("see the README file");

#define MODNAME "Reference monitor"
#define PASS_FILE "/home/luca/Scrivania/shared/hash_sha256"





static reference_monitor_t reference_monitor;

#define MAX_LEN 256

const char *dmesg_path="/run/log/journal/34806022a1ad45778b55aa795580cc74/system.journal";

struct open_flags {
	int open_flag;
	umode_t mode;
	int acc_mode;
	int intent;
	int lookup_flags;
};



char* get_full_path(int dfd, char *user_path) {
	struct path path_struct;
	char *tpath;
	char *path;
	int flag;
    int ret;
	unsigned int lookup_flags;

	tpath=kmalloc(MAX_LEN,GFP_KERNEL);
	if(tpath == NULL)
        return NULL;

    lookup_flags = LOOKUP_FOLLOW;
	ret = user_path_at(dfd, user_path, lookup_flags, &path_struct);
	if(ret){
		//printk("%s: error finding user full path for %s: %d", MODNAME, user_path, ret);
		kfree(tpath);
		return NULL;
	}

	path = d_path(&path_struct, tpath, MAX_LEN);
	//kfree(tpath);
	return path;
}







static int sys_open_wrapper(struct kprobe *ri, struct pt_regs *regs){

    // parsing parameters
    int dfd = (int) regs -> di;
    struct filename *file_name =(struct filename*) regs -> si;
    struct open_flags *op = (struct open_flags*) (regs -> dx);

    int flags = op -> open_flag;
    //umode_t mode = op -> mode;

    const char *path = (const char*) file_name -> name;
    if (strcmp(dmesg_path, path) == 0)
        return 0;

    const char *usr_path = (const char*) file_name -> uptr;
    // if not write mode, just return
    if(!(flags & O_RDWR) && !(flags & O_WRONLY) )  return 0;


    // getting full path:
    char *full_path = get_full_path(dfd, usr_path);
    if (full_path == NULL){
        full_path = path;
    }


    int i;
    char *curr_path;
    for (i = 0; i < reference_monitor.paths_len; i++){
        curr_path = reference_monitor.paths[i];
        if (strcmp(full_path, curr_path) == 0 ){


            op -> open_flag = O_RDONLY;
            regs -> dx = (unsigned long)op;
	        printk("%s: path: %s will be rejected",MODNAME, path);
            return 0;
        }
    }








	//printk("%s: request on behalf of user %d - euid %d (current paths is: %s)\n",MODNAME,current->cred->uid.val,current->cred->euid.val,paths);

	/* if(current->cred->uid.val == 0 || corrector){ */
	/* 	printk("%s: need black list search\n",MODNAME); */
	/* 	for(i=0; black_list[i] != NULL; i++){ */
	/* 		if(strcmp(black_list[i],current->comm) == 0 ){ */
	/* 			AUDIT */
	/* 			printk("%s: current couple <program,UID> is black listed in the UID domain - execve rejected\n",MODNAME);//the domin can include EUID specification depedning in the value of 'corrector' */
	/* 			goto reject; */
	/* 		} */
	/* 	} */
	/* 	AUDIT */
	/* 	printk("%s: current couple <program,UID> can run %s according to domain specification - finally executing the requested execve \n",MODNAME,paths); */

	/* } */

	return 0;

/* reject: */
/* 	regs->di = (unsigned long)NULL; */
/* 	return 0; */

}








static int add_path(const char *new_path){
    reference_monitor.paths_len++;
    reference_monitor.paths = krealloc(reference_monitor.paths, (reference_monitor.paths_len) * sizeof(char *), GFP_KERNEL);

    if (reference_monitor.paths == NULL)
    {
        printk("%s: error allocating memory for paths.", MODNAME);
        return -1;
    }

    reference_monitor.paths[reference_monitor.paths_len - 1] = kmalloc(strlen(new_path), GFP_KERNEL);
    if (reference_monitor.paths[reference_monitor.paths_len - 1] == NULL)
    {
        printk("%s: error allocating memory for new path.", MODNAME);
        return -1;
    }

    strcpy(reference_monitor.paths[reference_monitor.paths_len - 1], new_path);
    return 0;
}

static int read_pass_file(void){
    ssize_t bytes_read;
    struct file * f = NULL;
    // starting position
    loff_t pos = 0;

    // open the file for reading it
    f = filp_open(PASS_FILE, O_RDONLY, 0);
    if (IS_ERR(f)) {
        printk("%s: error opening password file", MODNAME);
        return -1;
    }

    bytes_read = kernel_read(f, reference_monitor.hashed_pass, 32, &pos);
    if (bytes_read < 0) {
        printk("%s: error reading password file", MODNAME);
        filp_close(f, NULL);
        return -1;
    }

    filp_close(f, NULL);
    return 0;
}


static int compute_hash(char *input_string, int input_size, char *output_buffer) {
    struct crypto_shash *tfm;
    struct shash_desc *desc;
    int ret;

    tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm)) {
        printk("%s: error initializing transform", MODNAME);
        return PTR_ERR(tfm);
    }

    desc = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (desc == NULL) {
        printk("%s: error initializing hash description", MODNAME);
        crypto_free_shash(tfm);
        return -ENOMEM;
    }

    desc->tfm = tfm;

    ret = crypto_shash_digest(desc, input_string, input_size, output_buffer);
    printk("%s: hash return: %d",MODNAME, ret);
    if (ret < 0) {
        printk("%s: error initializing hash computation", MODNAME);
        kfree(desc);
        crypto_free_shash(tfm);
        return ret;
    }

    kfree(desc);
    crypto_free_shash(tfm);

    return 0;
}



static struct kprobe kp = {
    .symbol_name = target_func,
    .pre_handler = sys_open_wrapper,
};



static int init_reference_monitor(void) {
	int ret;
	printk("%s: initializing",MODNAME);
	ret = register_kprobe(&kp);
    if (ret < 0) {
        printk("%s: kprobe registering failed, returned %d",MODNAME,ret);
        return ret;
    }

    // init reference_monitor struct
    reference_monitor.state = ON;
    reference_monitor.paths_len = 1;
    reference_monitor.paths = kmalloc( (reference_monitor.paths_len) * sizeof(char *), GFP_KERNEL);
    if (reference_monitor.paths == NULL){
        printk("%s: error initializing paths.",MODNAME);
        return -1;
    }
    reference_monitor.paths[reference_monitor.paths_len - 1] = PASS_FILE;

    // init the password:
    ret = read_pass_file();
    if (ret < 0) {
        printk("%s: error in reading pass file", MODNAME);
        return ret;
    }

    /* char hash[32]; */
    /* compute_hash("prova", 5, hash); */
    /* char hex_hash[64]; */
    /* bin2hex(hex_hash, hash, 32); */
    /* printk("%s: hex_hash: %s",MODNAME, hex_hash); */
    /* bin2hex(hex_hash, reference_monitor.hashed_pass, 32); */
    /* printk("%s: hex_hash: %s",MODNAME, hex_hash); */


    printk("%s: adding dummy path to module: /home/luca/Scrivania/prova.txt",MODNAME);
    add_path("/home/luca/Scrivania/prova.txt");
    printk_ratelimited("%s: done",MODNAME);


	return 0;
}



static void exit_reference_monitor(void) {
    unregister_kprobe(&kp);
    //Be carefull, this unregister assumes that none will need to run the hook function after this nodule
    //is unmounted
    printk("%s: hook module unloaded", MODNAME);
    kfree(reference_monitor.paths);
}
module_init(init_reference_monitor);
module_exit(exit_reference_monitor);
