 #include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "syscall_map.bpf.h"
// script for monitoring and analysiing syscalls to track processes and find something interseting to leverage
SEC("kprobe/do_execve")
int bpf_prog_execve(struct pt_regs *ctx) {
    // Get current process ID and thread ID
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    // argumenst to execve
    char *filename = (char *)PT_REGS_PARM1(ctx);
    char *argv = (char *)PT_REGS_PARM2(ctx);
    char *envp = (char *)PT_REGS_PARM3(ctx);

    // Log to kernel log
    bpf_trace_printk("Process %d executed %s\n", pid, filename);

    // Create data structure to store
    struct syscall_data data = {
        .filename = filename,
        .argv = argv,
        .envp = envp,
        .pid = pid
    };

    // Storing in the map 
    bpf_map_update_elem(&syscall_map, &data, &data, BPF_ANY);

    return 0;
}

SEC("kprobe/do_execveat")
int bpf_prog_execveat(struct pt_regs *ctx) {
    // Get current process ID and thread ID
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    // Get arguments to execveat
    char *filename = (char *)PT_REGS_PARM1(ctx);
    char *argv = (char *)PT_REGS_PARM2(ctx);
    char *envp = (char *)PT_REGS_PARM3(ctx);

    // Log to kernel log
    bpf_trace_printk("Process %d executed %s via execveat\n", pid, filename);

    // Create data structure to store
    struct syscall_data data = {
        .filename = filename,
        .argv = argv,
        .envp = envp,
        .pid = pid
    };

    // Store in map
    bpf_map_update_elem(&syscall_map, &data, &data, BPF_ANY);

    return 0;
}

SEC("kprobe/do_fork")
int bpf_prog_fork(struct pt_regs *ctx) {
    // Get process ID and thread ID
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    // Log to kernel log
    bpf_trace_printk("Process %d forked a new thread\n", pid);

    return 0;
}

SEC("kprobe/do_exit")
int bpf_prog_exit(struct pt_regs *ctx) {
    // Get process ID and thread ID
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    // Log to kernel log
    bpf_trace_printk("Process %d exited\n", pid);

    return 0;
}

char _license[] SEC("license") = "GPL";

