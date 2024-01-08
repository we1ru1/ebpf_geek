#!/usr/bin/python

from bcc import BPF

# 编写的eBPF程序
b = BPF(text="""
    int hello(void *ctx){
        bpf_trace_printk("Hello World!");
        return 0;
    }
""")
# 获取"execve"系统调用的名称
syscall = b.get_syscall_fnname("execve")
# 将eBPF函数`hello`附加到内核中一个叫做`syscall`的探测点(kprobe)上 
b.attach_kprobe(event=syscall, fn_name="hello")
b.trace_print()