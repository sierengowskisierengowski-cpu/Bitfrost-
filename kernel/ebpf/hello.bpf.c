#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

BPF_HASH(counts, u32);

int trace_execve(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    u64 zero = 0, *val;
    val = counts.lookup_or_try_init(&pid, &zero);
    if (val) {
        (*val)++;
    }
    
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_trace_printk("PID %d executed: %s\n", pid, comm);
    
    return 0;
}
