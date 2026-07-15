#!/bin/bash

VMLINUX=/boot/vmlinuz-$(uname -r)
VMLINUX_OBJ=/sys/kernel/btf/vmlinux

# Step 1: Compile the eBPF program
clang -O2 -target bpf -c file_hiding.c -o file_hiding.o

# Step 2: Load the eBPF program into the kernel
bpftool prog load file_hiding.o /sys/fs/bpf/file_hiding

# Step 3: Attach the program to the tracepoint
bpftool tracepoint attach syscalls/sys_enter_open prog file_hiding

# Step 4: Print confirmation
echo "✅ File hiding program loaded and attached to sys_enter_open tracepoint."
