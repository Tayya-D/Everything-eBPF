from bcc import BPF
import socket
import os
from time import sleep
from pyroute2 import IPRoute

# Define the eBPF program as a string
ebpf_hello_networking_world_code = """ 

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>

int tcpconnect(void *ctx) {
    bpf_trace_printk("[tcpconnect] TCP connection established\\n");
    return 0;

}

"""

interface = "eth0"  # Change this to your network interface

b = BPF(src_file="ebpf_hello_networking_world_code")

b.attach_kprobe(event="tcp_v4_connect", fn_name="tcp_connect")

print("Tracing TCP connections... Hit Ctrl-C to end.")

try:
    b.trace_print()
except KeyboardInterrupt:
    print("Exiting...")