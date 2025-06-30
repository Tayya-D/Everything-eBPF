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


=====
=====
The 'bpf_trace_printk' function is ok to use for simple programs like the hello world program but not for production level programs.
This is because the 'bpf_trace_printk' function prints the output to a single pipe. This is the same for the '.trace_print()' function where it reads from a single pipe -> this won't really scale well when you start wanting to run multiple eBPF programs

-> Instead you can ustilise maps and key value pairs