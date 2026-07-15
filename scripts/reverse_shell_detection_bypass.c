#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/unistd.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
// hooked into the sys_enter_excve syscla  which is triggered whnvr a process calls the execve 
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, int);
    __type(value, int);
} ignore_map SEC(".maps");//hash maps that maos int keys to int values 
// SEC("maps ") to place this map in the .maps section 
//used to track whether to ignore a specifc execve() event 

SEC("tracepoint/syscalls/sys_enter_execve")
int bpf_prog(struct pt_regs *ctx) {
    // Check if the execve is for /bin/sh or /bin/bash
    char *filename = (char *)PT_REGS_ARG(ctx, 0);// first argument which is used to get the filename in this case /bin/sh
    if (filename && (strcmp(filename, "/bin/sh") == 0 || strcmp(filename, "/bin/bash") == 0)) {
        //is the filename is /bin/sh or /bin/bash ignore the event 
        int key = 1;
        int *val = bpf_map_lookup_elem(&ignore_map, &key);
        if (val && *val == 1) {
            return 0; // Ignore this event
        }
    }
    return 1;
}

char _license[] SEC("license") = "GPL";
