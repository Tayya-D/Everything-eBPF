from bcc import BPF
import socket
import os
from time import sleep
from pyroute2 import IPRoute



interface = "eth0"  # Change this to your network interface

b = BPF(src_file="ebpf_hello_networking_world_code")

b.attach_kprobe(event="tcp_v4_connect", fn_name="tcp_connect")

print("Tracing TCP connections... Hit Ctrl-C to end.")

try:
    b.trace_print()
except KeyboardInterrupt:
    print("Exiting...")