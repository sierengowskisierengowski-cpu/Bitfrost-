// kernel/ebpf/syscall_firewall.bpf.c
/*
 * Bifrost eBPF Syscall Firewall v0.1.0
 * 
 * The circuit breaker. Blocks malicious paths and IPs
 * directly in the kernel before they reach userspace.
 * 
 * Heimdall writes threat patterns to BPF maps from userspace.
 * This program reads those maps and denies syscalls instantly.
 */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/socket.h>
#include <linux/in.h>

// Map: Blocked file paths
// Key: path string (e.g., "/tmp/malware")
// Value: 1=block, 0=allow
BPF_HASH(blocked_paths, char[256], u8, 10000);

// Map: Blocked IP addresses
// Key: IP address as u32
// Value: 1=block, 0=allow
BPF_HASH(blocked_ips, u32, u8, 10000);

// Map: Blocked PIDs (kill list)
// Key: PID
// Value: 1=block, 0=allow
BPF_HASH(blocked_pids, u32, u8, 1000);

// LSM hook: Block file opens
SEC("lsm/file_open")
int block_malicious_files(struct file *file) {
    char path[256];
    
    // Extract file path
    struct dentry *dentry = file->f_path.dentry;
    bpf_probe_read_kernel_str(&path, sizeof(path), dentry->d_name.name);
    
    // Check if path is in block list
    u8 *action = blocked_paths.lookup(&path);
    if (action && *action == 1) {
        bpf_trace_printk("BLOCKED: File open %s\n", path);
        return -EPERM;  // Deny immediately
    }
    
    return 0;  // Allow
}

// LSM hook: Block network connections
SEC("lsm/socket_connect")
int block_malicious_ips(struct socket *sock, struct sockaddr *address, int addrlen) {
    if (address->sa_family != AF_INET) {
        return 0;  // Only filter IPv4 for now
    }
    
    struct sockaddr_in *addr_in = (struct sockaddr_in *)address;
    u32 ip = addr_in->sin_addr.s_addr;
    
    // Check if IP is in block list
    u8 *action = blocked_ips.lookup(&ip);
    if (action && *action == 1) {
        bpf_trace_printk("BLOCKED: Connection to IP %x\n", ip);
        return -EPERM;  // Deny immediately
    }
    
    return 0;  // Allow
}

// Tracepoint: Block process execution
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    // Safety: Never block init or kernel threads
    if (pid <= 2) {
        return 0;
    }
    
    // Check if PID is in kill list
    u8 *action = blocked_pids.lookup(&pid);
    if (action && *action == 1) {
        bpf_trace_printk("BLOCKED: Execve from PID %d\n", pid);
        return -EPERM;  // Deny
    }
    
    return 0;  // Allow
}

char _license[] SEC("license") = "GPL";
