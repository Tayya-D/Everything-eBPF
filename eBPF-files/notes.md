# NOTES #

(notes on: A Beginner's Guide to eBPF Programming for Networking - Liz Rice, Isovalent)
(What is eBPF? Brightboard Lesson)

## eBPF Basics ##

Put simply - eBPF lets you run custom code in the kernal
These custom code or programs are triggered in response to events and are run when the kernal or application passes a certain 'hook point'. 
Example hook points would include pre-defined hooks such as system calls, function entry/exit, kernal tracepoints, network events and several others.

eBPF is not just limited to tracing syscalls - there are many more use cases as seen by the pred-defined hooks and Linux bcc/BPF Tracing Tools that can be used at different layers of the system (Application, Runtimes, System Libraries > System Call Interface >> VFS, File Systems, Volume Manager, Block Device >> Sockets, TCP/UDP, IP, Net Device >> Scheduler, Virtual Memory > Device Drivers)

Another way we you can view all the different events you can hook into is via 'sudo perf list'

## Network Events ##

### K Probes ###

There are lots of functions related to networking. Kprobes can be used and attached whenever an entry; kretprobe for exit from a kernal function occurs.
An example would be 'tcp_v4_connect()' kernal function

### Program Types ###

BPF_PROG_TYPE_SOCKET_FILTER program type allows us to attach to the raw socket interface and copy/filter what gets sent to userspace, for performant obversability. And example of this can be achieved via 'attch_raw_socket()'. 
As mentioned before, this is used for oberservability purposes only.

BPF_PROG_TYPE_XDP (XDP = Express Data Path) aka "What if we could run eBPF on the network interface card? ... therefore no resources used on the CPU itself" This only works of course if the NIC/driver supports XDP and can work on virtual network connections as well (only for inbound packets). These XDP programs can do the following to indound packets: pass, drop, manipulate, redirect packets. An example of achieving this is via the use of 'attach_xdp'

BPF_PROG_TYPE_SCHED_CLS is a program related to traffic control. This is a facility within the kernal where we can run actions on network packets. We can attach these filters to 'queuing disciplines' for both ingress and egress. You might use it for traffic prioritisation or filtering certain types of traffic. eBPF are a type of filter that you can attach to these disciplines.
We can attach these eBPF program to queueing disciplines, to act as a filter on Ingress/Egress (separately) to either pass, drop, mainpulate or redirect packets. We can do this via 'tc(add-filter)'
Rather than dropping the filtered packets - you can instead code a response at the kernal level - rather than making the failed ping response going through the entire network stack and then reply with a failed ping message; instead the intiator of the ping will get a negative to their ping reply at the kernal level (this saves time and resources on the network level)

### Perf Events ###

A way to check your filters are working as they should (rather than allowing the filtered packets to pass through the network stack), is to use 'sudo perf trace'

'sudo perf trace -e "net:*" ping -c1 <address>'

This command traces out the network related events that happen as those ping messages are sent out through the networking stack.
A helpful way of comparing pre and post filter program runtime, is to capture the output to two files -> one for before the filter program is run and one after the filter program is run.
So the resulting command will look something like the following:

'sudo perf trace -e "net:*" -o before-tc.txt ping -c1 <address> '
'sudo perf trace -e "net:*" -o after-tc.txt ping -c1 <address> '

Comparing the two files will result in the 'after-tc.txt' file have few entries as the tc program used in the example in '003-ebpf-hello-networking-world.py' drops the ICMP (ping) packets.

### eBPF is Kubernetes ###

eBPF is very useful for increasing efficiency on a network level and building high performance systems. eBPF can also be used on a virtual level - for example with Kubernetese pods on any given host. Just like physical hosts - virtual hosts/pods in this case will also have their own TC/IP network stack and veth entry points. With eBPF we can bypass a lot of the physical host network stack and route traffic we want directly to the veth without the traffic needing to pass through the entire hosts network stack and instead route the traffic to the appropriate pod's virtual eth interface. The result is significantly faster networking and makes a big difference in efficience and load on the hosts resources.

### eBPF-Enabled Networking Capabilities ###

Inspect packets -> Obersability
- Identity-aware data flows, message parsing, security forensics...

Drop or modify packets -> Security
- Network policies, encryption 

Redirect packets -> Network Functions
- Load balancing, routing, service mesh...

eBPF enables next-gen service mesh, high performance WITHOUT ANY APP OR CONFIG CHANGES!

NOTE TO SELF:
check out lizrice/ebpf-beginners, ebpf.io, cilium.io
=====

The 'bpf_trace_printk' function is ok to use for simple programs like the hello world program but not for production level programs.
This is because the 'bpf_trace_printk' function prints the output to a single pipe. This is the same for the '.trace_print()' function where it reads from a single pipe -> this won't really scale well when you start wanting to run multiple eBPF programs

-> Instead you can ustilise maps and key value pairs