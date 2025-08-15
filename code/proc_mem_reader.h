/* proc_mem_reader.h - 进程内存读取驱动头文件 */
#ifndef _PROC_MEM_READER_H
#define _PROC_MEM_READER_H

#include <linux/fs.h>       // 文件操作结构体file_operations
#include <linux/cdev.h>     // 字符设备结构体
#include <linux/device.h>   // 设备类相关
#include <linux/uaccess.h>  // 用户空间内存访问
#include <linux/io.h>       // I/O内存操作
#include <linux/mm.h>       // 内存管理
#include <linux/sched.h>    // 进程调度

#define DEVICE_NAME "proc_mem_reader"
#define MAX_READ_SIZE 4096

/* 内存读取请求结构体 */
struct mem_read_request {
    pid_t pid;           // 目标进程PID
    unsigned long vaddr; // 虚拟地址
    size_t size;        // 读取大小
};

/* 设备驱动函数声明 */
static phys_addr_t get_phys_addr(pid_t pid, unsigned long vaddr);
static ssize_t proc_mem_read(struct file *filp, char __user *buf, 
                           size_t count, loff_t *f_pos);
static int __init mem_reader_init(void);
static void __exit mem_reader_exit(void);

/* 文件操作结构体声明 */
extern struct file_operations fops;

/* 全局变量声明 */
extern int major_number;
extern struct class *mem_reader_class;
extern struct device *mem_reader_device;

#endif /* _PROC_MEM_READER_H */
