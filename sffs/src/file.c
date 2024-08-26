#include "fs.h"

#include <asm-generic/fcntl.h>
#include <linux/buffer_head.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/minmax.h>
#include <linux/mnt_idmapping.h>
#include <linux/mutex.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/uio.h>
#include <linux/version.h>

extern struct inode_operations fs_inode_ops;
struct file_operations fs_file_operations = {
    .owner = THIS_MODULE,
    .read = fs_read,
    .open = fs_open,
    // write_iter instead of write for enabling the writing in Kernel-space
    .write_iter = fs_write_iter,
};

static DEFINE_MUTEX(fs_lock);

struct dentry *fs_lookup(struct inode *parent_inode, struct dentry *child_dentry, unsigned int flags) {
  struct fs_inode *fs_specific_inode = NULL;
  struct super_block *sb = parent_inode->i_sb;
  struct buffer_head *bh = NULL;
  struct inode *the_inode = NULL;

  if (strcmp(child_dentry->d_name.name, UNIQUE_FILE_NAME))
    return NULL;

  // Get locked inode from the cache
  the_inode = iget_locked(sb, 1);
  if (the_inode == NULL)
    return ERR_PTR(-ENOMEM);
  // Aldread cached inode; return successfully
  if (!(the_inode->i_state & I_NEW))
    return child_dentry;

    // inode was not cached
#if LINUX_VERSION_CODE > KERNEL_VERSION(6, 1, 0)
  inode_init_owner(&nop_mnt_idmap, the_inode, NULL, S_IFDIR);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
  inode_init_owner(sb->s_user_ns, the_inode, NULL, S_IFDIR);
#else
  inode_init_owner(the_inode, NULL, S_IFDIR);
#endif

  the_inode->i_mode = S_IFREG | S_IRUSR | S_IRGRP | S_IROTH | S_IWUSR | S_IWGRP | S_IXUSR | S_IXGRP | S_IXOTH;
  the_inode->i_fop = &fs_file_operations;
  the_inode->i_op = &fs_inode_ops;

  // Set one link for this file
  set_nlink(the_inode, 1);

  // Retrieving the file size via the fs specific inode, putting it into the generic inode
  bh = (struct buffer_head *)sb_bread(sb, FS_INODES_BLOCK_NUMBER);
  if (bh == NULL) {
    pr_err("%s: sb_bread failed in fs_lookup\n", MODNAME);
    iput(the_inode);
    return ERR_PTR(-EIO);
  }
  fs_specific_inode = (struct fs_inode *)bh->b_data;
  the_inode->i_size = fs_specific_inode->file_size;
  brelse(bh);

  d_add(child_dentry, the_inode);
  dget(child_dentry);

  // Unlock the inode to make it usable
  unlock_new_inode(the_inode);

  return child_dentry;
}

ssize_t fs_read(struct file *filp, char __user *buf, size_t len, loff_t *off) {
  struct buffer_head *bh = NULL;
  uint64_t file_size = 0;
  int ret = 0;
  loff_t offset;
  int block_to_read = 0;

  mutex_lock(&fs_lock);
  file_size = i_size_read(file_inode(filp));

  // Check that offset is within boundaries
  if (*off >= file_size) {
    mutex_unlock(&fs_lock);
    return 0;
  }

  if (*off + len > file_size)
    len = file_size - *off;

  // Determine the block level offset for the operation
  offset = *off % DEFAULT_BLOCK_SIZE;

  // Read stuff in a single block; residual will be managed at the application level
  if (offset + len > DEFAULT_BLOCK_SIZE)
    len = DEFAULT_BLOCK_SIZE - offset;

  // Compute the actual index of the block to be read from the device
  block_to_read = *off / DEFAULT_BLOCK_SIZE + 2; // +2 is for superblock and fileroot inode

  bh = (struct buffer_head *)sb_bread(filp->f_path.dentry->d_inode->i_sb, block_to_read);
  if (bh == NULL) {
    pr_err("%s: sb_bread failed in fs_read\n", MODNAME);
    mutex_unlock(&fs_lock);
    return -EIO;
  }
  ret = copy_to_user(buf, bh->b_data + offset, len);
  *off += (len - ret);
  brelse(bh);

  mutex_unlock(&fs_lock);

  return len - ret;
}

int fs_open(struct inode *inode, struct file *file) {
  if (file->f_flags & (O_CREAT | O_TRUNC)) {
    pr_err("%s: fs_open not permitted\n", MODNAME);
    return -EPERM;
  }
  return 0;
}

ssize_t fs_write_iter(struct kiocb *iocb, struct iov_iter *from) {
  struct file *file = iocb->ki_filp;
  struct buffer_head *bh = NULL;
  loff_t file_size = i_size_read(file_inode(file));
  loff_t offset_in_block = file_size;
  size_t bytes_to_write = iov_iter_count(from);
  size_t remaining_bytes = bytes_to_write;
  void *buffer = NULL;
  int current_block = 0;
  ssize_t ret = 0;

  // Lock operations
  mutex_lock(&fs_lock);

  current_block = file_size / DEFAULT_BLOCK_SIZE + 2; // + 2 is for superblock + inode
  offset_in_block = file_size % DEFAULT_BLOCK_SIZE;   // offset inside the current block

  // Write crosses block boundaries
  if (bytes_to_write > DEFAULT_BLOCK_SIZE - offset_in_block)
    remaining_bytes = DEFAULT_BLOCK_SIZE - offset_in_block;

  buffer = kmalloc(bytes_to_write, GFP_ATOMIC);
  if (buffer == NULL) {
    pr_err("%s: kmalloc for buffer failed in fs_write_iter\n", MODNAME);
    ret = -ENOMEM;
    goto exit;
  }

  if (copy_from_iter(buffer, bytes_to_write, from) != bytes_to_write) {
    pr_err("%s: copy_from_iter failed in fs_write_iter\n", MODNAME);
    ret = -EFAULT;
    goto exit;
  }

  // Write crosses block boundaries
  if (bytes_to_write > DEFAULT_BLOCK_SIZE - offset_in_block) {
    current_block += 1; // go to next block
    offset_in_block = 0;
  }

  // Get buffer head for the block
  bh = sb_bread(file->f_path.dentry->d_inode->i_sb, current_block);
  if (bh == NULL) {
    pr_err("%s: sb_bread failed in fs_write_iter\n", MODNAME);
    ret = -EIO;
    goto exit;
  }

  // Copy data from temp buffer to buffer head
  memcpy(bh->b_data + offset_in_block, buffer, bytes_to_write);

  // Needs to be flushed
  mark_buffer_dirty(bh);
  sync_dirty_buffer(bh);

  i_size_write(file_inode(file), file_size + bytes_to_write);
  mark_inode_dirty(file_inode(file));
  iocb->ki_pos += ret;

exit:
  // Unlock
  mutex_unlock(&fs_lock);
  if (buffer)
    kfree(buffer);
  if (bh)
    brelse(bh);
  return ret;
}
