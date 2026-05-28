// kernel/ebpf/syscall_monitor.bpf.c
/*
 * Bifrost eBPF Syscall Monitor v0.1.0
 * 
 * Hooks critical syscalls (execve, connect, openat, unlinkat)
 * and sends events to userspace via ring buffer.
 */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/socket.h>
#include <linux/in.h>

// Ring buffer for sending events to userspace
BPF_RINGBUF_OUTPUT(events, 8);

// Event structure sent to Python
struct event_t {
    u32 pid;
    u32 uid;
    char comm[16];
    char type[16];
    char path[256];
    u32 ip;
    u16 port;
};

// Trace execve - process execution
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct event_t event = {};
    
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    __builtin_memcpy(event.type, "execve", 7);
    
    // Get the executable path from args
    const char *filename = (const char *)args->filename;
    bpf_probe_read_user_str(&event.path, sizeof(event.path), filename);
    
    events.ringbuf_output(&event, sizeof(event), 0);
    return 0;
}

// Trace connect - outbound network connections
TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    struct event_t event = {};
    
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    __builtin_memcpy(event.type, "connect", 8);
    
    // Extract IP and port from sockaddr
    struct sockaddr *addr = (struct sockaddr *)args->uservaddr;
    if (addr) {
        struct sockaddr_in addr_in;
        bpf_probe_read(&addr_in, sizeof(addr_in), addr);
        
        if (addr_in.sin_family == AF_INET) {
            event.ip = addr_in.sin_addr.s_addr;
            event.port = __builtin_bswap16(addr_in.sin_port);
        }
    }
    
    events.ringbuf_output(&event, sizeof(event), 0);
    return 0;
}

// Trace openat - file access
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct event_t event = {};
    
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    __builtin_memcpy(event.type, "openat", 7);
    
    const char *filename = (const char *)args->filename;
    bpf_probe_read_user_str(&event.path, sizeof(event.path), filename);
    
    events.ringbuf_output(&event, sizeof(event), 0);
    return 0;
}

// Trace unlinkat - file deletion
TRACEPOINT_PROBE(syscalls, sys_enter_unlinkat) {
    struct event_t event = {};
    
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    __builtin_memcpy(event.type, "unlinkat", 9);
    
    const char *filename = (const char *)args->pathname;
    bpf_probe_read_user_str(&event.path, sizeof(event.path), filename);
    
    events.ringbuf_output(&event, sizeof(event), 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
