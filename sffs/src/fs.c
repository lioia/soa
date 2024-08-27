#include "fs.h"

#include <linux/buffer_head.h>
#include <linux/compiler.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE > KERNEL_VERSION(5, 15, 0)
#include <linux/mnt_idmapping.h>
#endif
#include <linux/printk.h>
#include <linux/time64.h>
#include <linux/timekeeping.h>
#include <linux/types.h>

struct super_operations fs_super_ops = {};
struct dentry_operations fs_dentry_ops = {};
struct inode_operations fs_inode_ops = {
    .lookup = fs_lookup,
};
struct file_operations fs_dir_operations = {
    .owner = THIS_MODULE,
    .iterate_shared = fs_iterate,
};

void fs_kill_sb(struct super_block *s) {
  kill_block_super(s);
  pr_info("%s: fs unmount successful\n", MODNAME);
}

struct dentry *fs_mount(struct file_system_type *fs_type, int flags, const char *dev_name, void *data) {
  struct dentry *ret;
  ret = mount_bdev(fs_type, flags, dev_name, data, fs_fill_sb);
  if (unlikely(IS_ERR(ret)))
    pr_err("%s: mount_bdev failed in fs_mount\n", MODNAME);

  pr_info("%s: fs mount successful\n", MODNAME);
  return ret;
}

int fs_fill_sb(struct super_block *sb, void *data, int silent) {
  struct inode *root_inode = NULL;
  struct buffer_head *bh = NULL;
  struct fs_sb_info *sb_disk = NULL;
  struct timespec64 curr_time;
  uint64_t magic;

  sb->s_magic = MAGIC;

  bh = sb_bread(sb, SB_BLOCK_NUMBER);
  if (sb == NULL) {
    pr_err("%s: sb_bread failed in fs_fill_sb\n", MODNAME);
    return -EIO;
  }
  sb_disk = (struct fs_sb_info *)bh->b_data;
  magic = sb_disk->magic;
  brelse(bh);

  // Check magic number
  if (magic != sb->s_magic) {
    pr_err("%s: magic number not equal to expected value in fs_fill_sb\n", MODNAME);
    return -EBADF;
  }

  // FS specific data
  sb->s_fs_info = NULL;
  // Set custom operations
  sb->s_op = &fs_super_ops;

  // Get root inode from cache
  root_inode = iget_locked(sb, FS_ROOT_INODE_NUMBER);
  if (root_inode == NULL) {
    pr_err("%s: iget_locked failed in fs_fill_sb\n", MODNAME);
    return -ENOMEM;
  }

// Set root user as owner of the FS root
#if LINUX_VERSION_CODE > KERNEL_VERSION(6, 1, 0)
  inode_init_owner(&nop_mnt_idmap, root_inode, NULL, S_IFDIR);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
  inode_init_owner(sb->s_user_ns, root_inode, NULL, S_IFDIR);
#else
  inode_init_owner(root_inode, NULL, S_IFDIR);
#endif
  root_inode->i_sb = sb;
  root_inode->i_op = &fs_inode_ops;
  root_inode->i_fop = &fs_dir_operations;
  // Update Access Permissions
  root_inode->i_mode = S_IFDIR | S_IRUSR | S_IRGRP | S_IROTH | S_IWUSR | S_IWGRP | S_IXUSR | S_IXGRP | S_IXOTH;

  // Baseline alignment of the FS timestamp to the current time
  ktime_get_real_ts64(&curr_time);
#if LINUX_VERSION_CODE > KERNEL_VERSION(6, 6, 0)
  root_inode->__i_ctime = curr_time;
#else
  root_inode->i_ctime = curr_time;
#endif
#if LINUX_VERSION_CODE > KERNEL_VERSION(6, 7, 0)
  root_inode->__i_atime = curr_time;
  root_inode->__i_mtime = curr_time;
#else
  root_inode->i_atime = curr_time;
  root_inode->i_mtime = curr_time;
#endif

  // No inode from device is needed
  // Root of fs is an in memory object
  root_inode->i_private = NULL;

  sb->s_root = d_make_root(root_inode);
  if (sb->s_root == NULL) {
    pr_err("%s: d_make_root failed in fs_fill_sb\n", MODNAME);
    return -ENOMEM;
  }

  sb->s_root->d_op = &fs_dentry_ops;

  // Unlock the inode to make it usable
  unlock_new_inode(root_inode);

  return 0;
}
