#!/usr/bin/python
# This script demonstrates a simple eBPF program that prints "Hello, World!" to the kernel log.
# It uses the BCC (BPF Compiler Collection) library to load and run the eBPF program.
# Make sure you have BCC installed on your system to run this script.
from bcc import BPF
from time import sleep

# Define the eBPF program as a string
program = """ 
int hello_world(void *ctx) {
    bpf_trace_printk("Hello, World!\\n");
    return 0;
}
"""

# Load the eBPF program
b = BPF(text=program)

# Get the syscall number for 'clone'
# 'clone' is a common syscall used for creating processes, and we will attach our eBPF program to it.
clone = b.get_syscall_fnname("clone")

# Attach the eBPF program to the 'clone' syscall
b.attach_kprobe(event=clone, fn_name="hello_world")

# Print the output
print("Tracing... Hit Ctrl-C to end.")
try:
    sleep(999999)
except KeyboardInterrupt:
    pass
# Print the trace output
print("Output:")
b.trace_print()