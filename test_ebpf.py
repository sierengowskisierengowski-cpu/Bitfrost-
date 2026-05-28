#!/usr/bin/env python3
from bcc import BPF

print("Loading eBPF program...")

# Load BPF program
b = BPF(src_file="kernel/ebpf/hello.bpf.c")
b.attach_kprobe(event="__x64_sys_execve", fn_name="trace_execve")

print("✅ eBPF program loaded!")
print("🔍 Tracing execve syscalls... Ctrl-C to stop\n")

try:
    b.trace_print()
except KeyboardInterrupt:
    print("\n\n✅ eBPF test complete! You just traced kernel syscalls!")
    print("🚀 Ready to build the full Bifrost collector.")
