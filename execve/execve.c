// go:build ignore
//  This directive ensures that the C file is ignored by the Go compiler during regular builds.
//  It is used only for generating eBPF bindings with bpf2go.

#include "../headers/vmlinux.h"     // Includes kernel header definitions for vmlinux.
#include "../headers/bpf_helpers.h" // Provides helper macros and functions for writing eBPF programs.

SEC("tp/syscalls/sys_enter_execve")
// Defines an eBPF program that attaches to the tracepoint `sys_enter_execve`.
// This tracepoint is triggered whenever the `execve` system call is invoked.
void trace_execve()
{
    bpf_printk("Hello World! I am triggered by enter point of execve.");
}

char _license[] SEC("license") = "Dual MIT/GPL";
// Specifies the license of the eBPF program. The kernel enforces this field to ensure compliance.
