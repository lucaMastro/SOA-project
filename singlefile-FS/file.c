#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/timekeeping.h>
#include <linux/time.h>
#include <linux/buffer_head.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uio.h>
#include "singlefilefs.h"


static DEFINE_MUTEX(write_lock);

ssize_t onefilefs_read(struct file * filp, char __user * buf, size_t len, loff_t * off) {

    struct buffer_head *bh = NULL;
    struct inode * the_inode = filp->f_inode;
    uint64_t file_size = i_size_read(the_inode);
    int ret;
    loff_t offset;
    int block_to_read;//index of the block to be read from device

    //this operation is not synchronized
    //*off can be changed concurrently
    //add synchronization if you need it for any reason

    //check that *off is within boundaries
    if (*off >= file_size)
        return 0;
    else if (*off + len > file_size)
        len = file_size - *off;

    //determine the block level offset for the operation
    offset = *off % DEFAULT_BLOCK_SIZE;
    //just read stuff in a single block - residuals will be managed at the applicatin level
    if (offset + len > DEFAULT_BLOCK_SIZE)
        len = DEFAULT_BLOCK_SIZE - offset;

    //compute the actual index of the the block to be read from device
    block_to_read = *off / DEFAULT_BLOCK_SIZE + 2; //the value 2 accounts for superblock and file-inode on device

    /* printk("%s: read operation must access block %d of the device",MOD_NAME, block_to_read); */

    bh = (struct buffer_head *)sb_bread(filp->f_path.dentry->d_inode->i_sb, block_to_read);
    if(!bh){
	return -EIO;
    }
    ret = copy_to_user(buf,bh->b_data + offset, len);
    *off += (len - ret);
    brelse(bh);

    return len - ret;

}


struct dentry *onefilefs_lookup(struct inode *parent_inode, struct dentry *child_dentry, unsigned int flags) {

    struct onefilefs_inode *FS_specific_inode;
    struct super_block *sb = parent_inode->i_sb;
    struct buffer_head *bh = NULL;
    struct inode *the_inode = NULL;

    /* printk("%s: running the lookup inode-function for name %s",MOD_NAME,child_dentry->d_name.name); */

    if(!strcmp(child_dentry->d_name.name, UNIQUE_FILE_NAME)){

        //get a locked inode from the cache
        the_inode = iget_locked(sb, 1);
        if (!the_inode)
            return ERR_PTR(-ENOMEM);

        //already cached inode - simply return successfully
        if(!(the_inode->i_state & I_NEW))
            return child_dentry;

        //this work is done if the inode was not already cached
        inode_init_owner(current->cred->user_ns, the_inode, NULL, S_IFREG );
        the_inode->i_mode = S_IFREG | S_IRUSR | S_IRGRP | S_IROTH | S_IWUSR | S_IWGRP | S_IXUSR | S_IXGRP | S_IXOTH;
        the_inode->i_fop = &onefilefs_file_operations;
        the_inode->i_op = &onefilefs_inode_ops;

        //just one link for this file
        set_nlink(the_inode,1);

        //now we retrieve the file size via the FS specific inode, putting it into the generic inode
        bh = (struct buffer_head *)sb_bread(sb, SINGLEFILEFS_INODES_BLOCK_NUMBER );
        if(!bh){
            iput(the_inode);
            return ERR_PTR(-EIO);
        }
        FS_specific_inode = (struct onefilefs_inode*)bh->b_data;
        the_inode->i_size = FS_specific_inode->file_size;
        brelse(bh);

        d_add(child_dentry, the_inode);
        dget(child_dentry);

        //unlock the inode to make it usable
        unlock_new_inode(the_inode);

        return child_dentry;
    }

    return NULL;
}


/**********************************************************/
ssize_t onefilefs_write(struct file * filp, const char __user * buf, size_t len, loff_t * off) {

    struct buffer_head *bh = NULL;
    struct inode * the_inode = filp->f_inode;
    int ret;
    loff_t offset;
    int block_to_write; // index of the block to be written from device
    uint64_t file_size = i_size_read(the_inode);

    //determine the block level offset for the operation
    offset = file_size % DEFAULT_BLOCK_SIZE;

    //compute the actual index of the the block to be written from device
    block_to_write = file_size / DEFAULT_BLOCK_SIZE + 2; //the value 2 accounts for superblock and file-inode on device

    /* printk("%s: write operation must access block %d of the device",MOD_NAME, block_to_write); */

    bh = (struct buffer_head *)sb_bread(filp->f_path.dentry->d_inode->i_sb, block_to_write);
    if(!bh)
        return -EIO;

    ret = copy_from_user(bh->b_data + file_size, buf, len);
    brelse(bh);

    // updating size:
    file_size += len - ret;
    // also on the inode
    i_size_write(the_inode, file_size);
    return len - ret;
}



ssize_t onefilefs_write_iter(struct kiocb *iocb, struct iov_iter *from) {

    struct file *filp = iocb->ki_filp;
    char *buf= from->kvec->iov_base;
    size_t len = from->kvec->iov_len;

    struct buffer_head *bh = NULL;
    struct inode * the_inode = filp->f_inode;
    loff_t offset;
    int block_to_write; // index of the block to be written from device
    ssize_t in_block_len;

    uint64_t file_size = i_size_read(the_inode);

    mutex_lock(&write_lock);
    while (len != 0){
        //determine the block level offset for the operation
        offset = file_size % DEFAULT_BLOCK_SIZE;

        //compute the actual index of the the block to be written from device
        block_to_write = file_size / DEFAULT_BLOCK_SIZE + 2; //the value 2 accounts for superblock and file-inode on device

        // bytes to be written in the current block
        in_block_len = offset + len > DEFAULT_BLOCK_SIZE ? DEFAULT_BLOCK_SIZE - offset : len;


        bh = (struct buffer_head *)sb_bread(the_inode->i_sb, block_to_write);
        if(!bh)
            return -EIO;

        memcpy(bh->b_data + offset, buf, in_block_len);
        //write immediately on disk
        sync_dirty_buffer(bh);
        brelse(bh);

        // updating size:
        file_size += in_block_len;
        // also on the inode
        i_size_write(the_inode, file_size);
        // updating data if cross block write
        buf += in_block_len;
        len -= in_block_len;
    }
    mutex_unlock(&write_lock);
    return len;
}

//look up goes in the inode operations
const struct inode_operations onefilefs_inode_ops = {
    .lookup = onefilefs_lookup,
};


/*
    Since file has to be written by kernel, file_operations has to define the .write_iter function
    instead of the .write one as said here:
    https://stackoverflow.com/questions/71013101/kernel-space-write-a-file
    according to documentation, the signature for this function is:
    ssize_t (*write_iter) (struct kiocb *, struct iov_iter *);
*/
const struct file_operations onefilefs_file_operations = {
    .owner = THIS_MODULE,
    .read = onefilefs_read,
    .write_iter = onefilefs_write_iter,
};
