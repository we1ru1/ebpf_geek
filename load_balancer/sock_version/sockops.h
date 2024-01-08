#include <linux/bpf.h>

struct sock_key{         // key代表了一个套接字，这里的key是用于查找的，而sockops.bpf.c中的key是用于添加到map中的
    __u32 src_ip;        // source IP address
    __u32 dst_ip;        // destination IP address
    __u32 sport;         // source port
    __u32 dport;         // destination port
    __u32 family;       // address family，  IPv4 or IPv6

};


struct {
	__uint(type, BPF_MAP_TYPE_SOCKHASH);     // BPF_MAP_TYPE_SOCKHASH表示这是一个socket hash map
	__uint(key_size, sizeof(struct sock_key));   // key的大小为struct sock_key的大小
	__uint(value_size, sizeof(int));         //  value的大小为int的大小
	__uint(max_entries, 65535);              // 最大元素个数为65535
	__uint(map_flags, 0);                   
} sock_map SEC(".maps");     // 这个映射的key是一个套接字，那请问value是什么呢？value是一个int，表示套接字的文件描述符，这个文件描述符是在用户空间创建的，然后通过bpf_map_update_elem()函数添加到sock_map中的