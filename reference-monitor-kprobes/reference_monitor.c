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

#include "lib/reference_monitor.h"
#include "lib/deferred_work.h"

#define target_func "do_filp_open" //you should modify this depending on the kernel version
//#define target_func "__x64_sys_open" //you should modify this depending on the kernel version

#define AUDIT if(1)

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Francesco Quaglia <francesco.quaglia@uniroma2.it>");
MODULE_DESCRIPTION("see the README file");

#define MODNAME "Reference monitor"



char *black_list[] = {"/home/luca/Scrivania/prova.txt", NULL ,"su", NULL}; //the list of programs root cannot use to spawn others - being root is still admitted excluding 'su' from the list


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

static int sys_open_wrapper(struct kprobe *ri, struct pt_regs *regs){

    // parsing parametersG
    int dfd = (int) regs -> di;
    struct filename *file_name =(struct filename*) regs -> si;
    struct open_flags *op = (struct open_flags*) (regs -> dx);

    int flags = op -> open_flag;
    //umode_t mode = op -> mode;

    const char *path = (const char*) file_name -> name;
    if (strcmp(dmesg_path, path) == 0)
        return 0;

    int write_mode = (flags & O_WRONLY || flags & O_RDWR);

	printk("%s: path: %s, dfd: %d; flags: %d, write_mode: %d;",MODNAME, path, dfd, flags, write_mode);

    int i;
    char *curr_path;
    for (i = 0; i < reference_monitor.paths_len; i++){
        curr_path = reference_monitor.paths[i];
        if (strcmp(path, curr_path) == 0 && write_mode){
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
    reference_monitor.paths = krealloc(reference_monitor.paths, (reference_monitor.paths_len + 1) * sizeof(char *), GFP_KERNEL);
    reference_monitor.paths[reference_monitor.paths_len - 1] = kmalloc(strlen(new_path), GFP_KERNEL);
    // always a more element
    reference_monitor.paths[reference_monitor.paths_len] = NULL;
    strcpy(reference_monitor.paths[reference_monitor.paths_len - 1], new_path);
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
    reference_monitor.paths_len = 0;
    reference_monitor.paths = kmalloc( (reference_monitor.paths_len + 1) * sizeof(char *), GFP_KERNEL);
    reference_monitor.paths[reference_monitor.paths_len + 1] = NULL;

    printk("%s: adding dummy path to module: /home/luca/Scrivania/prova.txt",MODNAME);
    add_path("/home/luca/Scrivania/prova.txt");

	return 0;
}



static void exit_reference_monitor(void) {
    unregister_kprobe(&kp);
    //Be carefull, this unregister assumes that none will need to run the hook function after this nodule
    //is unmounted
    printk("%s: hook module unloaded", MODNAME);
}
module_init(init_reference_monitor);
module_exit(exit_reference_monitor);
