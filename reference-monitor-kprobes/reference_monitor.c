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





reference_monitor_t reference_monitor;

#define MAX_LEN 256

const char *dmesg_path="/run/log/journal/34806022a1ad45778b55aa795580cc74/system.journal";

struct open_flags {
	int open_flag;
	umode_t mode;
	int acc_mode;
	int intent;
	int lookup_flags;
};




/* stack overflow:
    https://stackoverflow.com/questions/61500432/relative-path-to-absolute-path-in-linux-kernel
*/

int get_user_full_path(const char *filename, ssize_t len, char *output_buffer){
    struct path path;
    int dfd=AT_FDCWD;
    char *ret_ptr=NULL;
    int error = -EINVAL,flag=0;
    unsigned int lookup_flags = 0;
    char *tpath=kmalloc(1024,GFP_KERNEL);
    if ((flag & ~(AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT)) != 0)
    {
        kfree(tpath);
        return error;
    }
    if (!(flag & AT_SYMLINK_NOFOLLOW))
        lookup_flags |= LOOKUP_FOLLOW;

    error = user_path_at(dfd, filename, lookup_flags, &path);
    if (error)
    {
        kfree(tpath);
        return error;
    }
    ret_ptr = d_path(&path, tpath, 1024);
    sprintf(output_buffer, ret_ptr, strlen(ret_ptr));
    kfree(tpath);
    return 0;
}


/* char* get_absolute_path(const char *path, char *absolute_path) { */
/*     int ret; */
/*     struct path path_struct; */
/*     //char *absolute_path = (char*) kmalloc(sizeof(char) * MAX_LEN,GFP_KERNEL); */
/*     ret = kern_path(path, LOOKUP_FOLLOW, &path_struct); */
/*     printk("%s: kern_path returned: %px; ret: %d\n",MODNAME, &path,ret); */
/*     char *ap = d_path(&path_struct, absolute_path, MAX_LEN); */
/*     printk("%s: d path returned: %px vs %px; %s\n",MODNAME, ap, absolute_path, ap); */
/*     return ap; */
/* } */



int sys_open_wrapper(struct kprobe *ri, struct pt_regs *regs){

    int i;
    char *curr_path;
    // parsing parameters
    int dfd;
    int flags;
    const char *path;
    const char *usr_path;
    char full_path[MAX_LEN];
    int ret;

    struct filename *file_name =(struct filename*) regs -> si;
    struct open_flags *op = (struct open_flags*) (regs -> dx);

    dfd = (int) regs -> di;
    flags = op -> open_flag;
    //umode_t mode = op -> mode;

    path = (const char*) file_name -> name;
    if (strcmp(dmesg_path, path) == 0)
        return 0;

    usr_path = (const char*) file_name -> uptr;
    // if not write mode, just return
    if(!(flags & O_RDWR) && !(flags & O_WRONLY) )  return 0;

    /* printk("%s: name: %s && %px; uptr: %s && %px", MODNAME, path, path, usr_path, usr_path); */

    // getting full path:
    ret = get_user_full_path(usr_path, strlen(usr_path), full_path);
    /* ret = get_user_full_path(path, strlen(usr_path), full_path); */
    if (ret < 0) {
        /* printk("%s: error in get_user_full_path with name: %s and uptr %s\neuid: %d\n", MODNAME, path, usr_path, current->cred->euid.val); */
        sprintf(full_path, path, strlen(path));
    }

    /* printk("%s: ------------path: %s\n", MODNAME, full_path); */
    /* printk("%s: name: %s, uptr: %s\n", MODNAME, path, usr_path); */

    /* struct path path_struct; */
    /* //char *absolute_path = (char*) kmalloc(sizeof(char) * MAX_LEN,GFP_KERNEL); */
    /* char absolute_path[MAX_LEN]; */
    /* char *ap = get_absolute_path(path, absolute_path); */
    /* printk("%s: d path returned: %px vs %px; %s\n",MODNAME, ap, absolute_path, ap); */


    for (i = 0; i < reference_monitor.paths_len; i++){
        curr_path = reference_monitor.paths[i];
        if (strcmp(full_path, curr_path) == 0 ){

            op -> open_flag = O_RDONLY;
	        printk("%s: write on path: %s has been rejected\n",MODNAME, full_path);
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


int add_path(const char __user *new_path){
    /*
        @TODO: check if already present into the list
        @TODO: prevent adding the-file path
    */
    int ret;
    int len;
    char full_path[MAX_LEN];

    ret = get_user_full_path(new_path, strlen(new_path), full_path);
    printk("%s: user_full_path: %s. error: %d\n", MODNAME, full_path, ret);
    reference_monitor.paths_len++;
    reference_monitor.paths = krealloc(reference_monitor.paths, (reference_monitor.paths_len) * sizeof(char *), GFP_KERNEL);
    if (reference_monitor.paths == NULL)
    {
        printk("%s: error allocating memory for paths.\n", MODNAME);
        return -1;
    }

    len = strlen(new_path);
    reference_monitor.paths[reference_monitor.paths_len - 1] = kmalloc(len, GFP_KERNEL);
    if (reference_monitor.paths[reference_monitor.paths_len - 1] == NULL)
    {
        printk("%s: error allocating memory for new path.\n", MODNAME);
        return -1;
    }

    sprintf(reference_monitor.paths[reference_monitor.paths_len - 1], full_path, len);
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
        printk("%s: error opening password file\n", MODNAME);
        return -1;
    }

    bytes_read = kernel_read(f, reference_monitor.hashed_pass, 32, &pos);
    if (bytes_read < 0) {
        printk("%s: error reading password file\n", MODNAME);
        filp_close(f, NULL);
        return -1;
    }

    filp_close(f, NULL);
    return 0;
}






static struct kprobe kp = {
    .symbol_name = target_func,
    .pre_handler = sys_open_wrapper,
};



static int init_reference_monitor(void) {
	int ret;
	printk("%s: initializing\n",MODNAME);
	ret = register_kprobe(&kp);
    if (ret < 0) {
        printk("%s: kprobe registering failed, returned %d\n",MODNAME,ret);
        return ret;
    }

    // init reference_monitor struct
    reference_monitor.state = ON;
    reference_monitor.paths_len = 1;
    reference_monitor.paths = kmalloc( (reference_monitor.paths_len) * sizeof(char *), GFP_KERNEL);
    if (reference_monitor.paths == NULL){
        printk("%s: error initializing paths.\n",MODNAME);
        return -1;
    }
    reference_monitor.paths[reference_monitor.paths_len - 1] = PASS_FILE;
    reference_monitor.add_path = add_path;

    // init the password:
    ret = read_pass_file();
    if (ret < 0) {
        printk("%s: error in reading pass file\n", MODNAME);
        return ret;
    }

    /* char hash[32]; */
    /* compute_hash("prova", 5, hash); */
    /* char hex_hash[64]; */
    /* bin2hex(hex_hash, hash, 32); */
    /* printk("%s: hex_hash: %s",MODNAME, hex_hash); */
    /* bin2hex(hex_hash, reference_monitor.hashed_pass, 32); */
    /* printk("%s: hex_hash: %s",MODNAME, hex_hash); */


    /* printk("%s: adding dummy path to module: /home/luca/Scrivania/prova.txt",MODNAME); */
    /* reference_monitor.add_path("/home/luca/Scrivania/prova.txt"); */
    printk("%s: done\n",MODNAME);

	return 0;
}



static void exit_reference_monitor(void) {
    unregister_kprobe(&kp);
    //Be carefull, this unregister assumes that none will need to run the hook function after this nodule
    //is unmounted
    printk("%s: hook module unloaded\n", MODNAME);
    kfree(reference_monitor.paths);
}
module_init(init_reference_monitor);
module_exit(exit_reference_monitor);


EXPORT_SYMBOL(reference_monitor);

