#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <sys/socket.h>
#include "sockops.h"

SEC("sk_msg")  // sk_msg是一个特殊的section，用于指定类型为BPF_PROG_TYPE_SK_MSG的BPF程序的入口点
int bpf_redir(struct sk_msg_md *msg){
    struct sock_key key = {         // 为什么这里的源ip和源端口和sockops.bpf.c中的正好相反呢？因为这里的key是用于查找的，而sockops.bpf.c中的key是用于添加到map中的
            .src_ip = msg->remote_ip4,
            .dst_ip = msg->local_ip4,
            .dport = bpf_htonl(msg->local_port),
            .sport = msg->remote_port,
            .family = msg->family,
    };

    bpf_msg_redirect_hash(msg, &sock_map, &key, BPF_F_INGRESS);  // 将数据包重定向到sock_map中的对应套接字，BPF_F_INGRESS是什么意思呢？表示重定向到套接字的入口，即将数据包注入到套接字的入口
    
    return SK_PASS;  // SK_PASS表示将数据包传递给下一个BPF程序
}
char LICENSE[] SEC("license") = "Dual BSD/GPL";


