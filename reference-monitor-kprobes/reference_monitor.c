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
#define IS_MON_ON() reference_monitor.state & 0x1
#define IS_REC_ON() reference_monitor.state & 0x2

const char *dmesg_path="/run/log/journal/";

struct open_flags {
	int open_flag;
	umode_t mode;
	int acc_mode;
	int intent;
	int lookup_flags;
};


int isDir(const char *filename){
    struct path path;
    int error;
    struct inode *inode;

    error = kern_path(filename,LOOKUP_FOLLOW, &path);
    if(error)
        return -1;

    inode = path.dentry -> d_inode;
    return S_ISDIR(inode->i_mode);
}



struct dentry *get_dentry_from_path(const char *path){
    struct path file_path;
    int ret;
    ret = kern_path(path, 0, &file_path);
    /* ret = kern_path(full_path, 0, &file_path); */
    if (ret != 0){
        /* printk("%s: error: for %s filename_lookup is %d\n", MODNAME, path, ret); */
        return NULL;
    }

    return file_path.dentry;
}





/*
   returns position of dentry found, otherwise -1
*/
int find_already_present_path(struct dentry *dentry_to_find){
    int i;
    struct dentry *curr;
    for (i = 0; i < reference_monitor.filtered_paths_len; i++){
        curr = reference_monitor.filtered_paths[i];
        if (curr -> d_inode == dentry_to_find-> d_inode)
        {
            break;
        }
    }
    return i >= reference_monitor.filtered_paths_len ? -1 : i;
}



char *full_path_from_dentry(struct dentry *dentry) {
    char *path = kmalloc(MAX_LEN, GFP_KERNEL);
    struct dentry *parent = dentry -> d_parent;
    const char *name = dentry->d_name.name;
    int name_len = strlen(name);
    int path_len = name_len;
    const char *parent_name;
    int parent_name_len;

    if (!path)
        return NULL;

    memcpy(path, name, name_len);

    /*
        parent of root is root itself. Using following condition, the add of starting '//' is prevented:
        in fact, the loop adds <parent_name>/, but if parent is '/' itself, it will add '//'.
        With this condition, last iteration will be with parent -> d_parent == '/', meaning that not
        initial '/' will be in the path at the end of loop.
    */
    while (parent != parent -> d_parent) {
        parent_name = parent->d_name.name;
        parent_name_len = strlen(parent_name);

        if (path_len + parent_name_len + 2 > MAX_LEN) {
            kfree(path);
            return NULL; // Il percorso è troppo lungo
        }

        // Costruisci il percorso completo aggiungendo il nome della directory genitore
        memmove(path + parent_name_len + 1, path, path_len + 1);
        memcpy(path, parent_name, parent_name_len);
        path[parent_name_len] = '/';
        path_len += parent_name_len + 1;

        dentry = parent;
        parent = dentry -> d_parent;
    }

    // adding starting '/':
    memmove(path + 1, path, path_len + 1);
    path[0] = '/';

    return path;
}



/**************************************************/
int global_checker(struct dentry *d_path){

    const char *path;
    struct dentry *parent;
    char *full_path;



    // scan all dparent tree:
    parent = d_path -> d_parent;
    while (d_path != parent) {
        if (find_already_present_path(d_path) >= 0 ){
            full_path = full_path_from_dentry(d_path);
            printk("%s: found path %s in filtered list for path %s. Write operation will be rejected. This may cause a SEGFAULT\n",MODNAME, full_path, path);
            kfree(full_path);
            return 1;
        }
        d_path = parent;
        parent = d_path -> d_parent;
    }
	return 0;
}


/**************************************************/



int sys_open_wrapper(struct kprobe *ri, struct pt_regs *regs){

    /* int dfd; */
    int flags;
    int write_mode = O_RDWR | O_WRONLY;
    int creat_mode = O_CREAT | O_TMPFILE;
    struct filename *file_name =(struct filename*) regs -> si;
    struct open_flags *op = (struct open_flags*) (regs -> dx);
    const char *path;
    struct dentry *d_path;

    flags = op -> open_flag;
    /* umode_t mode = op -> mode; */
    /* dfd = (int) regs -> di; */

    if (strstr(file_name -> name, dmesg_path) != NULL)
        return 0;

    // if not write mode or state is *off, just return
    if (
         (!(flags & write_mode) && !(flags & creat_mode)) ||
         ! (IS_MON_ON())
        )
    {
        return 0;
    }


    path = (const char*) file_name -> name;
    if (strstr(path, dmesg_path) != NULL)
        return 0;

    /* printk("DEBUG: path in global: %s\n", path); */
    d_path = get_dentry_from_path(path);
    if (d_path == NULL){
        /* printk("%s: failed getting dentry from path %s\n",MODNAME, path); */
        return 0;
    }

    /* printk("DEBUG: path in sys_wrapper: %s\n", file_name -> name); */
    if (global_checker(d_path)){
        op -> open_flag = O_RDONLY;
        /* printk("%s: write on path: %s has been rejected\n",MODNAME, path); */
        return 0;
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


int unlink_wrapper(struct kprobe *ri, struct pt_regs *regs){
    struct filename *filename =(struct filename*) regs -> si;
    const char *path;
    struct dentry *d_path;

    path = (const char*) filename -> name;
    if (strstr(path, dmesg_path) != NULL)
        return 0;

    /* printk("DEBUG: path in global: %s\n", path); */
    d_path = get_dentry_from_path(path);
    if (d_path == NULL){
        /* printk("%s: failed getting dentry from path %s\n",MODNAME, path); */
        return 0;
    }
    if (global_checker(d_path)){
        regs -> si = (long unsigned int) NULL;
        /* printk("%s: write on path: %s has been rejected\n",MODNAME, path); */
        return 0;
    }
    return 0;
}

int rmdir_wrapper(struct kprobe *ri, struct pt_regs *regs){
    /* int dfd = (int) regs -> di; */
    struct filename *filename =(struct filename*) regs -> si;
    const char *path;
    struct dentry *d_path;

    path = (const char*) filename -> name;
    if (strstr(path, dmesg_path) != NULL)
        return 0;

    /* printk("DEBUG: path in global: %s\n", path); */
    d_path = get_dentry_from_path(path);
    if (d_path == NULL){
        /* printk("%s: failed getting dentry from path %s\n",MODNAME, path); */
        return 0;
    }
    if (global_checker(d_path)){
        regs -> si = (long unsigned int) NULL;
        /* printk("%s: write on path: %s has been rejected\n",MODNAME, path); */
        return 0;
    }
    return 0;
}

/*
    the correct inode and dentry don't exist yet. Then check the path without the last
    token: /a/seuqence/of/token.
*/
int mkdir_wrapper(struct kprobe *ri, struct pt_regs *regs){
    struct filename *filename =(struct filename*) regs -> si;

    const char *path;
    char *reduced_path;
    char *curr;

    struct dentry *d_path;

    /* printk("DEBUG: mkdir con path: %s\n", filename -> name); */
    path = (const char*) filename -> name;
    if (strstr(path, dmesg_path) != NULL)
        return 0;

    reduced_path = kstrdup(path, GFP_KERNEL);
    /* note: start from len - 2, because last char may be a '/', but it has be to excluded
        /some/path/ ---> /some
    */
    for (curr = reduced_path + strlen(reduced_path) - 2; curr != reduced_path; curr--){
        if (*curr == '/'){
            // make substitution
            *curr = '\0';
            break;
        }
    }

    d_path = get_dentry_from_path(reduced_path);
    if (d_path == NULL){
        /* printk("%s: failed getting dentry from path %s\n",MODNAME, path); */
        return 0;
    }
    kfree(reduced_path);

    if (global_checker(d_path)){
        regs -> si = (long unsigned int) NULL;
        return 0;
    }
    return 0;
}

/*************************************************************************************/


int add_path(const char *new_path){
    /*
        @TODO: prevent adding the-file path
    */
    int already_present_path;
    struct dentry *dentry;

    // checking monitor state:
    // cantinue only if 2nd bit is 1
    if (! (IS_REC_ON())){
        printk("%s: cannot reconfigure monitor\n", MODNAME);
        return -1;
    }

    dentry = get_dentry_from_path(new_path);
    if (dentry == NULL){
        printk("%s: failed getting dentry from path %s\n", MODNAME, new_path);
        return -1;
    }

    // checking if already present:
    already_present_path = find_already_present_path(dentry);
    if (already_present_path >= 0){
        printk("%s: error: path already present: %s\n",MODNAME, full_path_from_dentry(dentry));
        return -1;
    }

    reference_monitor.filtered_paths_len++;
    reference_monitor.filtered_paths = krealloc(reference_monitor.filtered_paths, (reference_monitor.filtered_paths_len) * sizeof(struct dentry *), GFP_KERNEL);
    if (reference_monitor.filtered_paths == NULL)
    {
        printk("%s: error allocating memory for paths.\n", MODNAME);
        return -1;
    }

    reference_monitor.filtered_paths[reference_monitor.filtered_paths_len - 1] = dentry;
    return 0;
}


int rm_path(const char *path_to_remove){
    int already_present_path;
    struct dentry *last_element;
    struct dentry *d_path_to_remove = get_dentry_from_path(path_to_remove);


    // checking monitor state:
    if (!(IS_REC_ON())){
        printk("%s: cannot reconfigure monitor\n", MODNAME);
        return -1;
    }

    if (d_path_to_remove == NULL){
        printk("%s: error: retrieving dentry from %s\n",MODNAME, path_to_remove);
        return -1;
    }

    // checking if already present:
    already_present_path = find_already_present_path(d_path_to_remove);
    if (already_present_path < 0){
        printk("%s: error: path not present\n",MODNAME);
        return -1;
    }

    /*
        [a b c d e ] ---> [a b x d e]
        i just need to move "e" where c was: [a b e d]. I don't care about order
    */
    // checking if i didnt remove the last element
    if (already_present_path != reference_monitor.filtered_paths_len - 1){
        last_element = reference_monitor.filtered_paths[reference_monitor.filtered_paths_len - 1];
        reference_monitor.filtered_paths[already_present_path] = last_element;
    }

    // free last element
    dput(reference_monitor.filtered_paths[reference_monitor.filtered_paths_len - 1]);
    reference_monitor.filtered_paths_len--;
    reference_monitor.filtered_paths = krealloc(reference_monitor.filtered_paths, (reference_monitor.filtered_paths_len) * sizeof(struct dentry *), GFP_KERNEL);
    if (reference_monitor.filtered_paths == NULL)
    {
        printk("%s: error freeding memory for paths.\n", MODNAME);
        return -1;
    }

    return 0;
}


char *get_path(int index){
    return full_path_from_dentry(reference_monitor.filtered_paths[index]);
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



void set_state(unsigned char state){
    // sanifying input: keep last 2 bits
    state &= 0x3;
    reference_monitor.state = state;
}




static struct kprobe kp = {
    .symbol_name = target_func,
    .pre_handler = sys_open_wrapper,
};

static struct kprobe kp_unlink = {
        .symbol_name =  "do_unlinkat",
        .pre_handler = unlink_wrapper,
};

static struct kprobe kp_rmdir = {
        .symbol_name =  "do_rmdir",
        .pre_handler = rmdir_wrapper,
};

static struct kprobe kp_mkdir = {
        .symbol_name =  "do_mkdirat",
        .pre_handler = mkdir_wrapper,
};


static int init_reference_monitor(void) {
	int ret;
    struct dentry *pass_file_dentry;
	printk("%s: initializing\n",MODNAME);
	ret = register_kprobe(&kp);
    if (ret < 0) {
        printk("%s: kprobe registering failed, returned %d\n",MODNAME,ret);
        return ret;
    }
	ret = register_kprobe(&kp_unlink);
    if (ret < 0) {
        printk("%s: kprobe unlink registering failed, returned %d\n",MODNAME,ret);
        return ret;
    }
    ret = register_kprobe(&kp_rmdir);
    if (ret < 0) {
        printk("%s: kprobe rmdir registering failed, returned %d\n",MODNAME,ret);
        return ret;
    }
    ret = register_kprobe(&kp_mkdir);
    if (ret < 0) {
        printk("%s: kprobe mkdir registering failed, returned %d\n",MODNAME,ret);
        return ret;
    }

    // init reference_monitor struct
    reference_monitor.state = RECON;
    reference_monitor.filtered_paths_len = 1;
    reference_monitor.filtered_paths = kmalloc( sizeof(struct dentry *), GFP_KERNEL);
    if (reference_monitor.filtered_paths == NULL){
        printk("%s: error initializing paths.\n",MODNAME);
        return -1;
    }
    pass_file_dentry = get_dentry_from_path(PASS_FILE);
    if (pass_file_dentry == NULL){
        printk("%s: error retrieving dentry of pass_file\n", MODNAME);
        return -1;
    }
    reference_monitor.filtered_paths[0] = pass_file_dentry;

    reference_monitor.add_path = add_path;
    reference_monitor.rm_path = rm_path;
    reference_monitor.get_path = get_path;
    /* reference_monitor.check_monitor_state = check_monitor_state; */
    reference_monitor.set_state = set_state;

    // init the password:
    ret = read_pass_file();
    if (ret < 0) {
        printk("%s: error in reading pass file\n", MODNAME);
        return ret;
    }

    printk("%s: done\n",MODNAME);

	return 0;
}



static void exit_reference_monitor(void) {
    unregister_kprobe(&kp);
    unregister_kprobe(&kp_mkdir);
    unregister_kprobe(&kp_rmdir);
    unregister_kprobe(&kp_unlink);
    //Be carefull, this unregister assumes that none will need to run the hook function after this nodule
    //is unmounted
    printk("%s: hook module unloaded\n", MODNAME);
    kfree(reference_monitor.filtered_paths);
}
module_init(init_reference_monitor);
module_exit(exit_reference_monitor);


EXPORT_SYMBOL(reference_monitor);

