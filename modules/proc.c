/*
 * proc.c - following example 5.1 from the LKMPG,
 * updated for Kernel version 4.15 using
 * http://pointer-overloading.blogspot.com/
 * 2013/09/linux-creating-entry-in-proc-file.html
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#define procfs_name "helloworld"

static int
proc_show(struct seq_file *m, void *v) {
        seq_printf(m, "Hello (proc) world\n");
        return 0;
}

static int
proc_open(struct inode *inode, struct file *file)
{
        return single_open(file, proc_show, NULL);
}

static const struct file_operations pfops = {
        .owner = THIS_MODULE,
        .open = proc_open,
        .read = seq_read,
        .llseek = seq_lseek,
        .release = single_release,
};

int
init_module(void)
{
        proc_create(procfs_name, 0644, NULL, &pfops);

        printk(KERN_INFO "/proc/%s created\n", procfs_name);

        return 0;
}

void cleanup_module()
{
        remove_proc_entry(procfs_name, NULL);
        printk(KERN_INFO "/proc/%s removed\n", procfs_name);
}

MODULE_LICENSE("GPL");
