#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/proc_fs.h>
#include <linux/mm_types.h>
#include <linux/page-flags.h>
#include <linux/swapops.h>

#define DEVICE_NAME "proc_mem_reader"
#define MAX_READ_SIZE 4096

struct mem_read_request {
    pid_t pid;          // 目标进程PID
    unsigned long vaddr; // 虚拟地址
    size_t size;        // 读取大小
};

static int major_number;
static struct class *mem_reader_class = NULL;
static struct device *mem_reader_device = NULL;

// 通过虚拟地址获取物理地址
static phys_addr_t get_phys_addr(pid_t pid, unsigned long vaddr)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    struct page *page;
    phys_addr_t paddr = 0;
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    
    // 根据PID查找任务结构
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!task) {
        return 0;
    }
    
    // 获取进程内存管理结构
    mm = get_task_mm(task);
    if (!mm) {
        return 0;
    }
    
    // 查找虚拟内存区域
    vma = find_vma(mm, vaddr);
    if (!vma || vaddr < vma->vm_start) {
        mmput(mm);
        return 0;
    }
    
    // 页表查询
    pgd = pgd_offset(mm, vaddr);
    if (pgd_none(*pgd) || pgd_bad(*pgd)) {
        mmput(mm);
        return 0;
    }
    
    p4d = p4d_offset(pgd, vaddr);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) {
        mmput(mm);
        return 0;
    }
    
    pud = pud_offset(p4d, vaddr);
    if (pud_none(*pud) || pud_bad(*pud)) {
        mmput(mm);
        return 0;
    }
    
    pmd = pmd_offset(pud, vaddr);
    if (pmd_none(*pmd) || pmd_bad(*pmd)) {
        mmput(mm);
        return 0;
    }
    
    pte = pte_offset_map(pmd, vaddr);
    if (!pte || !pte_present(*pte)) {
        pte_unmap(pte);
        mmput(mm);
        return 0;
    }
    
    // 获取物理页
    page = pte_page(*pte);
    if (!page) {
        pte_unmap(pte);
        mmput(mm);
        return 0;
    }
    
    // 计算物理地址
    paddr = page_to_phys(page) | (vaddr & ~PAGE_MASK);
    
    pte_unmap(pte);
    mmput(mm);
    
    return paddr;
}

// 读取指定进程内存
static ssize_t proc_mem_read(struct file *filp, char __user *buf, 
                           size_t count, loff_t *f_pos)
{
    struct mem_read_request req;
    phys_addr_t phys_addr;
    void __iomem *virt_addr;
    unsigned char kernel_buf[MAX_READ_SIZE];
    size_t read_size;
    int ret = 0;
    
    // 从用户空间获取请求参数
    if (copy_from_user(&req, buf, sizeof(req))) {
        return -EFAULT;
    }
    
    // 限制单次读取大小
    read_size = min_t(size_t, req.size, MAX_READ_SIZE);
    
    // 获取物理地址
    phys_addr = get_phys_addr(req.pid, req.vaddr);
    if (!phys_addr) {
        return -EFAULT;
    }
    
    // 将物理地址映射到内核虚拟地址空间
    virt_addr = ioremap_cache(phys_addr, read_size);
    if (!virt_addr) {
        return -EFAULT;
    }
    
    // 从映射的内存中复制数据到内核缓冲区
    memcpy_fromio(kernel_buf, virt_addr, read_size);
    
    // 将数据复制到用户空间
    if (copy_to_user(buf, kernel_buf, read_size)) {
        ret = -EFAULT;
        goto out;
    }
    
    ret = read_size;

out:
    // 解除映射
    iounmap(virt_addr);
    return ret;
}

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .read = proc_mem_read,
};

static int __init mem_reader_init(void)
{
    // 动态分配主设备号
    major_number = register_chrdev(0, DEVICE_NAME, &fops);
    if (major_number < 0) {
        return major_number;
    }
    
    // 创建设备类
    mem_reader_class = class_create(THIS_MODULE, "mem_reader");
    if (IS_ERR(mem_reader_class)) {
        unregister_chrdev(major_number, DEVICE_NAME);
        return PTR_ERR(mem_reader_class);
    }
    
    // 创建设备节点
    mem_reader_device = device_create(mem_reader_class, NULL, 
                                    MKDEV(major_number, 0), NULL, DEVICE_NAME);
    if (IS_ERR(mem_reader_device)) {
        class_destroy(mem_reader_class);
        unregister_chrdev(major_number, DEVICE_NAME);
        return PTR_ERR(mem_reader_device);
    }
    
    return 0;
}

static void __exit mem_reader_exit(void)
{
    device_destroy(mem_reader_class, MKDEV(major_number, 0));
    class_unregister(mem_reader_class);
    class_destroy(mem_reader_class);
    unregister_chrdev(major_number, DEVICE_NAME);
}

module_init(mem_reader_init);
module_exit(mem_reader_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Process Memory Reader Driver for Android");
