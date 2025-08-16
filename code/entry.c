#include <linux/module.h>
#include <linux/netlink.h>
#include <net/sock.h>

#include "memory.h"

#define NETLINK_USER 31

struct sock *nl_sk = NULL;

struct custom_msg {
    int pid;
    unsigned long virt_addr;
    void* buffer;
    size_t buffer_size;
    bool writein;
};

static void nl_receive_message(struct sk_buff *skb) {
    struct nlmsghdr *nlh;
    struct custom_msg user_msg;
    struct sk_buff *skb_out;
    int res;
    nlh = (struct nlmsghdr *)skb->data;
    memcpy(&user_msg, nlmsg_data(nlh), sizeof(struct custom_msg));
    
    int send_pid = nlh->nlmsg_pid;
        
    if (user_msg.writein) {
	  read_process_memory(user_msg.pid, user_msg.virt_addr, user_msg.buffer, user_msg.buffer_size);
    }else {
	  write_process_memory(user_msg.pid, user_msg.virt_addr, user_msg.buffer, user_msg.buffer_size);
    }
    
    skb_out = nlmsg_new(sizeof(struct custom_msg), 0);
    if (!skb_out) {
        printk(KERN_ERR "Failed to allocate new skb\n");
        return;
    }

    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, sizeof(struct custom_msg), 0);
    NETLINK_CB(skb_out).dst_group = 0;

    memcpy(nlmsg_data(nlh), &user_msg, sizeof(struct custom_msg));

    res = nlmsg_unicast(nl_sk, skb_out, send_pid);
    if (res < 0)
        printk(KERN_INFO "Error while sending back to user\n");
}

static int __init nl_init(void) {
    struct netlink_kernel_cfg cfg = {
        .input = nl_receive_message,
    };

    nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
    if (!nl_sk) {
        printk(KERN_ALERT "Error creating netlink socket\n");
        return -10;
    }

    return 0;
}

static void __exit nl_exit(void) {
    if (nl_sk != NULL) {
        netlink_kernel_release(nl_sk);
        nl_sk = NULL;
    }
}

module_init(nl_init);
module_exit(nl_exit);
MODULE_LICENSE("GPL");
//by 小雪生