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

// The following function checks if the packet is an ICMP ping request (type 8) and passes that information to userspace.

int xdp(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    if (is_icmp_ping_request(data, data_end)) {
        struct iphdr *ip = data + sizeof(struct ethhdr);
        struct icmphdr *icmp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
        bpf_trace_printk("[xdp] ICMP ping request detected from %x to %x\\n", ip->saddr, ip->daddr, icmp->type);
    }
    
    return XDP_PASS;  // Pass the packet to the next stage in the networking stack
}

// The following function checks for ingress packets + whether they are ICMP ping requests, if true then drops the packet and does not pass it to the next stage in the networking stack.

int tc(struct __sk_buff *skb) {
    bpf_trace_printk("[tc] Ingress packet detected\\n");
    
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    if (is_icmp_ping_request(data, data_end)) {
        struct iphdr *ip = data + sizeof(struct ethhdr);
        struct icmphdr *icmp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
        bpf_trace_printk("[tc] ICMP ping request detected from %x to %x\\n", ip->saddr, ip->daddr, icmp->type);
        return TC_ACT_SHOT;  // Drop the packet
    }
    return TC_ACT_OK;  // Allow all other packets to pass through
}

// The following function will allow us to check if the packet is an ICMP ping request (type 8) and reply with a message to userspace.

int tc_reply(struct __sk_buff *skb) {
    bpf_trace_printk("[tc] ICMP ping request detected\\n");
    
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    if (is_icmp_ping_request(data, data_end)) {
        return TC_ACT_SHOT;  // Drop the packet
    }
    
    struct iphdr *ip = data + sizeof(struct ethhdr);
    struct icmphdr *icmp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    bpf_trace_printk("[tc] ICMP ping request detected from %x to %x\\n", ip->saddr, ip->daddr, icmp->type);
    
    // Send a reply to userspace
    // Swap the source and destination MAC addresses so that the reply can be sent back to the original sender
    swap_mac_addresses(skb);
    swap_ip_addresses(skb);
    
    // Change the ICMP type to 0 (echo reply) and set the code to 0
    update_icmp_type(skb, 8, 0);
    
    // Redirecting the cloned and modified skb on the same interface to be processed by the kernel
    bpf_clone_redirect(skb, skb->ifindex, 0);
    
    return TC_ACT_OK;  // We modified the packet and redirected a clone of it, so we drop this original packet

}

"""

interface = "eth0"  # Change this to your network interface

b = BPF(src_file="ebpf_hello_networking_world_c_code")

# b.attach_kprobe(event="tcp_v4_connect", fn_name="tcp_connect")

# Load the socket filter program
f = b.loadfunc("socket_filter", BPF.SOCKET_FILTER)
# Attach the socket filter to the specified network interface
# This will filter packets on the specified interface and send TCP packets to userspace.
BPF.attach_raw_socket(f, interface)
# create a raw socket to receive packets
# This will allow us to receive a copy of the packets that match the filter criteria.
fd = f.sock
sock = socket.fromfd(fd, socket.PF_PACKET, socket.SOCK_RAW, socket.IPPROTO_IP)
sock.setblocking(True)

# Load the XDP program
fx = b.load_func("xdp", BPF.XDP)
# Attach the XDP program to the specified network interface
BPF.attach_xdp(fx, interface, 0)


# Load the TC program
# Create the queuing discipline (qdisk) for the interface and the filter
# This will allow us to filter packets at the ingress stage and drop ICMP ping requests.
ipr = IPRoute()
#fi = b.load_func("tc", BPF.SCHED_CLS)
# Load the TC reply program
fi = b.load_func("tc_reply", BPF.SCHED_CLS)
links = ipr.link_lookup(ifname=interface)
idx = links[0]

try:
    ipr.tc("add", "ingress", idx, "ffff:")
except:
    print("qdisk ingress already exists, skipping...")
    
    ipr.tc("add-filter", "bpf", idx, ":1", fd=fi.fd, name=fi.name, parent="ffff:", action="drop", classid=1)


print("Tracing Ready... Hit Ctrl-C to end.")

try:
    b.trace_print()
    
    #while True:
    #   # Read packets from the raw socket
    #    packet = os.read(fd, 4096)  # Read a maximum of 4096 bytes
    #    print("Userspace received packet {}:".format(packet))
    #
    #    # Sleep for a short duration to avoid busy-waiting
    #    sleep(0.1)
    
except KeyboardInterrupt:
    print("\n unloading...")
    ipr.tc("del", "ingress", idx, "ffff:")

exit()