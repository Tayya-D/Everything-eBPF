### NOTES ###

The 'bpf_trace_printk' function is ok to use for simple programs like the hello world program but not for production level programs.
This is because the 'bpf_trace_printk' function prints the output to a single pipe. This is the same for the '.trace_print()' function where it reads from a single pipe -> this won't really scale well when you start wanting to run multiple eBPF programs

-> Instead you can ustilise maps and key value pairs