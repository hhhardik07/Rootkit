#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "packet_map.bpf.h"

SEC("kprobe/sendmsg")//kprobe into sendmsg ,which is used to send data across a socket
int bpf_prog(struct pt_regs *ctx) {
    struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);//2nd argument which is the msg pointer  that is the he message header used to extract the msg struct
    // msg is a pointer to the msgdhr struct that has the message 
    char *buf = (char *)msg->msg_data;// access the raw buffer 
    size_t len = msg->msg_len;
// store in the map 
    struct packet_data data = {.buf = buf, .len = len};
    bpf_map_update_elem(&packet_map, &data, &data, BPF_ANY);

    return 0;
}

char _license[] SEC("license") = "GPL";
