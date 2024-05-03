#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/ioctl.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <asm/io.h>
#include <linux/slab.h>

#define DEVICE_NAME "ioctl_device"
#define MAJOR_NUM 100
#define IOCTL_INVALIDATE_TLB _IOW(MAJOR_NUM, 0, unsigned long)

static int device_open(struct inode *inode, struct file *file) {
    return 0;
}

static int device_release(struct inode *inode, struct file *file) {
    return 0;
}

static inline void invlpg(unsigned long addr) {
    asm volatile("invlpg (%0)" ::"r" (addr) : "memory");
    asm volatile ("clflush (%0)" :: "r"(addr));
}


static long device_ioctl(struct file *file, unsigned int ioctl_num, unsigned long ioctl_param) {
    switch (ioctl_num)
    {
        case IOCTL_INVALIDATE_TLB:
            {
                unsigned long hva;
                if (copy_from_user(&hva, (unsigned long *)ioctl_param, sizeof(unsigned long))) {
                    return -EFAULT; // Handle copy_from_user error
                }
                invlpg(hva);
                break;
            }
    }

    return 0;
}

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = device_ioctl,
    .open = device_open,
    .release = device_release,
};

static int __init helper1(void) {
    int ret;
    ret = register_chrdev(MAJOR_NUM, DEVICE_NAME, &fops);
    if (ret < 0) {
        printk(KERN_ALERT "Registering char device failed with %d\n", ret);
        return ret;
    }
    printk(KERN_INFO "Device created successfully\n");
    return 0;
}

static void __exit helper2(void) {
    unregister_chrdev(MAJOR_NUM, DEVICE_NAME);
    printk(KERN_INFO "Device unregistered successfully\n");
}

module_init(helper1);
module_exit(helper2);

MODULE_LICENSE("GPL");

