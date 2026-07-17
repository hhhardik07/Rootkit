#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/fs.h>
#include <linux/ktime.h>
#define MAX 256
// file hider that hooks into the sys_enter_open tracepoint to intercept open file sys call
//checks the file name against a pattern map 
//patterns need to be insterted 
//if match is found file is" hidden" 
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, char[256]);
    __type(value, int);
} patterns SEC(".maps");

SEC("kprobe/__x64_sys_open")
 char *user_path = (char *)PT_REGS_PARM1(ctx);
    char buf[MAX];

    // Copy the path from user space into our buffer
    if (bpf_probe_read_str(buf, sizeof(buf), user_path) <= 0)
        return 1; 

    // Check if this path is in the pattern map to ignore 
    int *val = bpf_map_lookup_elem(&patterns, buf);
    if (val) {
        // Found – hide this file
        return 0;
    }

    //else trace 
    return 1;

char _license[] SEC("license") = "GPL";
