#!/usr/bin/python
# This script demonstrates a simple eBPF program that prints "Hello, World!" to the kernel log.
# It uses the BCC (BPF Compiler Collection) library to load and run the eBPF program.
# Make sure you have BCC installed on your system to run this script.
from bcc import BPF
from time import sleep

# Define the eBPF program as a string
program = """ 

BPF_HASH(clones ); // Define a hash map to store clone syscall data associated with UIDs

int hello_world(void *ctx) {
    u64 uid;
    u64 counter = 0;
    u64 *ptr;

    uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    ptr = clones.lookup(uid);
    // Check if pointer is non-null - without this check, the program will crash or simply not work due to the verifier not allowing it
    if (ptr) {
        counter = *ptr;
    }
    // Increment the counter for the current UID
    counter++;
    clones.update(uid, &counter);
    
    // Print the UID of the current process
    bpf_trace_printk("Hello, World! UID: %d\\n", uid);
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
# b.trace_print()

# Print the contents of the hash map
print("Clone syscall counts:")
while True:
    sleep(2)
    if len(b["clones"].items()):
        for k, v in b["clones"].items():
            print(f"UID: {k.value}, Count: {v.value}")
    else:
        print("No entries recorded yet.")
# Note: The above loop will continuously print the contents of the hash map every 2 seconds.
# You can stop the script with Ctrl-C, and it will print the final counts of clone syscalls per UID.
# This allows you to see how many times the clone syscall has been invoked by each UID since the script started.