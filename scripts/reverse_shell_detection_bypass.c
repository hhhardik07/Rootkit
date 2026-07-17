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

SEC("kprobe/__x64_sys_execve")
int bpf_prog(struct pt_regs *ctx) {
//define the filename first 
char filename[16] = {0};

 //extract the first argument 
 struct pt_regs *real_regs = (struct pt_regs *)PT_REGS_PARM1_CORE(ctx);
  
const char *user_filename_ptr = (const char *)PT_REGS_PARM1_CORE(real_regs);
   const char *user_filename_ptr = (const char *)PT_REGS_PARM1_CORE(real_regs);
       
       if (!user_filename_ptr)
           return 0;

//pull the string from user space because user_filename_ptr conatians an dress from user space 
long res = bpf_probe_read_user_str(filename, sizeof(filename), user_filename_ptr);
    if (res < 0)
        return 0;
// if this is /bin/sh or /bin/bash

int is_sh   = (__builtin_memcmp(filename, "/bin/sh", 8) == 0);
    int is_bash = (__builtin_memcmp(filename, "/bin/bash", 10) == 0)


if (is_sh || is_bash) {
        int key = 1;
        int *val = bpf_map_lookup_elem(&ignore_map, &key);
        if (val && *val == 1) {
            return 0; 
        }
    }

           
    }
    return 1;
}

char _license[] SEC("license") = "GPL";
