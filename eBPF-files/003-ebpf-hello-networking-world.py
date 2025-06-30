from bcc import BPF
import socket
import os
from time import sleep
from pyroute2 import IPRoute

# Define the eBPF program (C code) as a string
ebpf_hello_networking_world_c_code = """ 

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>

/// This eBPF program traces TCP connections and prints a message when an entry is created.

int tcpconnect(void *ctx) {
    bpf_trace_printk("[tcpconnect] TCP connection established\\n");
    return 0;

}

/// The following function filters socket events based on the network interface.

int socket_filter(struct __sk_buff *skb) {
    unsigned char *cursor = 0;

    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));

    // Look for IP packets
    if (ethernet -> type != 0x0800) {
        return 0;  // Not an IP packet
    }
    
    struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
    
    // Look at the IP header to determine the type of packet
    
    if (ip -> nextp == 0x01) {  // Check if the next protocol is ICMP (otherwise known as ping)
        bpf_trace_printk("[socket_filter] ICMP packet detected for %x\\n", ip -> dst);
    } else if (ip -> nextp == 0x11) {  // Check if the next protocol is UDP
        bpf_trace_printk("[socket_filter] UDP packet detected for %x\\n", ip -> dst);
    }  else if (ip -> nextp == 0x06) {  // Check if the next protocol is TCP
        bpf_trace_printk("[socket_filter] TCP packet detected for %x\\n", ip -> dst);
        // Send a copy of this TCP packet to userspace 
        return -1;
    }
    return 0;  // Allow all other packets to pass through as normal - not sending any to userspace
}


"""

interface = "eth0"  # Change this to your network interface

b = BPF(src_file="ebpf_hello_networking_world_c_code")

b.attach_kprobe(event="tcp_v4_connect", fn_name="tcp_connect")

print("Tracing TCP connections... Hit Ctrl-C to end.")

try:
    b.trace_print()
except KeyboardInterrupt:
    print("Exiting...")