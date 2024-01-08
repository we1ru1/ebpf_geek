#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <sys/socket.h>
#include "sockops.h"

SEC("sockops")   // sockops是一个特殊的section，用于指定类型为BPF_PROG_TYPE_SOCK_OPS的BPF程序的入口点
int bpf_sockmap(struct bpf_sock_ops *skops) {   // skops是一个指向bpf_sock_ops结构体的指针，为什么叫ops呢，因为这个结构体中包含了一些操作函数
    // op字段表示当前的操作类型，BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB表示当前的操作是在被动连接建立之后，BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB表示当前的操作是在主动连接建立之后

    if (skops->family != AF_INET)  // 如果不是IPv4，直接返回BPF_OK，表示不做任何处理
        return BPF_OK;

    if (skops->op != BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB && skops->op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB)
        return BPF_OK;  // 如果不是这两种操作类型，直接返回BPF_OK，表示不做任何处理

    struct sock_key key = {
            .src_ip = skops->local_ip4,
            .dst_ip = skops->remote_ip4,
            .dport = skops->remote_port,
            // bpf_htonl()函数用于将主机字节序转换为网络字节序
            // bpf_htonl()即 host to network long
            .sport = bpf_htonl(skops->local_port),
            .family = skops->family,

    };

    // 到这里，说明套接字属于新建立的连接了
    bpf_sock_hash_update(skops, &sock_map, &key,
                         BPF_NOEXIST);  // 将新建立的连接加入到sock_map中，这里的key是remote_port，value是BPF_NOEXIST，表示键不存在才添加新元素

    return BPF_OK;

}
char LICENSE[] SEC("license") = "Dual BSD/GPL";
