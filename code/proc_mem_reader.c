/* proc_mem_reader.c - 进程内存读取驱动实现 */
#include "proc_mem_reader.h"  // 包含自定义头文件
#include <linux/err.h>        // 错误处理宏
#include <linux/slab.h>       // 内存分配
#include <linux/version.h>    // 内核版本检查

/* 全局变量定义 */
int major_number;
struct class *mem_reader_class;
struct device *mem_reader_device;

/* 虚拟地址转物理地址实现 */
static phys_addr_t get_phys_addr(pid_t pid, unsigned long vaddr) {
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    struct page *page;
    phys_addr_t paddr = 0;
    pgd_t *pgd; p4d_t *p4d; pud_t *pud; pmd_t *pmd; pte_t *pte;

    /* 1. 根据PID获取进程任务结构 */
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!task) {
        printk(KERN_ERR "PID %d not found\n", pid);
        return 0;
    }

    /* 2. 获取内存管理结构并检查VM区域 */
    mm = get_task_mm(task);
    if (!mm) {
        printk(KERN_ERR "Failed to get mm_struct\n");
        return 0;
    }

    vma = find_vma(mm, vaddr);
    if (!vma || vaddr < vma->vm_start) {
        mmput(mm);
        printk(KERN_ERR "Invalid VMA for 0x%lx\n", vaddr);
        return 0;
    }

    /* 3. 页表遍历查询 */
    pgd = pgd_offset(mm, vaddr);
    if (pgd_none(*pgd) || pgd_bad(*pgd)) goto page_error;

    p4d = p4d_offset(pgd, vaddr);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) goto page_error;

    pud = pud_offset(p4d, vaddr);
    if (pud_none(*pud) || pud_bad(*pud)) goto page_error;

    pmd = pmd_offset(pud, vaddr);
    if (pmd_none(*pmd) || pmd_bad(*pmd)) goto page_error;

    pte = pte_offset_map(pmd, vaddr);
    if (!pte || !pte_present(*pte)) {
        pte_unmap(pte);
        goto page_error;
    }

    /* 4. 计算物理地址 */
    page = pte_page(*pte);
    if (!page) {
        pte_unmap(pte);
        goto page_error;
    }
    paddr = page_to_phys(page) | (vaddr & ~PAGE_MASK);

    pte_unmap(pte);
    mmput(mm);
    return paddr;

page_error:
    mmput(mm);
    printk(KERN_ERR "Page table lookup failed for 0x%lx\n", vaddr);
    return 0;
}

/* 设备读操作实现 */
static ssize_t proc_mem_read(struct file *filp, char __user *buf, 
                           size_t count, loff_t *f_pos) {
    struct mem_read_request req;
    phys_addr_t phys_addr;
    void __iomem *virt_addr;
    unsigned char *kernel_buf;
    size_t read_size;
    int ret = -EFAULT;

    /* 1. 参数检查 */
    if (count < sizeof(req)) {
        printk(KERN_ERR "Buffer too small\n");
        return -EINVAL;
    }

    /* 2. 从用户空间获取请求 */
    if (copy_from_user(&req, buf, sizeof(req))) {
        printk(KERN_ERR "copy_from_user failed\n");
        return -EFAULT;
    }

    /* 3. 验证请求参数 */
    if (req.size > MAX_READ_SIZE || req.size == 0) {
        printk(KERN_ERR "Invalid size %zu\n", req.size);
        return -EINVAL;
    }
    read_size = min_t(size_t, req.size, MAX_READ_SIZE);

    /* 4. 分配内核缓冲区 */
    kernel_buf = kmalloc(read_size, GFP_KERNEL);
    if (!kernel_buf) return -ENOMEM;

    /* 5. 物理地址转换与内存映射 */
    phys_addr = get_phys_addr(req.pid, req.vaddr);
    if (!phys_addr) goto free_buf;

    virt_addr = ioremap_cache(phys_addr, read_size);
    if (!virt_addr) {
        printk(KERN_ERR "ioremap failed for 0x%llx\n", phys_addr);
        goto free_buf;
    }

    /* 6. 数据拷贝 */
    memcpy_fromio(kernel_buf, virt_addr, read_size);
    if (copy_to_user(buf, kernel_buf, read_size)) {
        printk(KERN_ERR "copy_to_user failed\n");
        goto unmap;
    }

    ret = read_size;

unmap:
    iounmap(virt_addr);
free_buf:
    kfree(kernel_buf);
    return ret;
}

/* 文件操作结构体实现 */
static struct file_operations fops = {
    .owner = THIS_MODULE,
    .read = proc_mem_read,
};

/* 模块初始化 */
static int __init mem_reader_init(void) {
    /* 1. 注册字符设备 */
    major_number = register_chrdev(0, DEVICE_NAME, &fops);
    if (major_number < 0) {
        printk(KERN_ERR "register_chrdev failed\n");
        return major_number;
    }

    /* 2. 创建设备类 */
    mem_reader_class = class_create(THIS_MODULE, "mem_reader");
    if (IS_ERR(mem_reader_class)) {
        unregister_chrdev(major_number, DEVICE_NAME);
        return PTR_ERR(mem_reader_class);
    }

    /* 3. 创建设备节点 */
    mem_reader_device = device_create(mem_reader_class, NULL,
                                    MKDEV(major_number, 0), NULL, DEVICE_NAME);
    if (IS_ERR(mem_reader_device)) {
        class_destroy(mem_reader_class);
        unregister_chrdev(major_number, DEVICE_NAME);
        return PTR_ERR(mem_reader_device);
    }

    printk(KERN_INFO "Module loaded with major %d\n", major_number);
    return 0;
}

/* 模块卸载 */
static void __exit mem_reader_exit(void) {
    device_destroy(mem_reader_class, MKDEV(major_number, 0));
    class_unregister(mem_reader_class);
    class_destroy(mem_reader_class);
    unregister_chrdev(major_number, DEVICE_NAME);
    printk(KERN_INFO "Module unloaded\n");
}

module_init(mem_reader_init);
module_exit(mem_reader_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Process Memory Reader Driver for Android");
