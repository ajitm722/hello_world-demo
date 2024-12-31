// go:build ignore
// This directive ensures that the C file is ignored by the Go compiler during regular builds.
// It is used only for generating eBPF bindings with bpf2go.

#include "../headers/vmlinux.h"     // Includes kernel header definitions for vmlinux.
#include "../headers/bpf_helpers.h" // Provides helper macros and functions for writing eBPF programs.

SEC("tp/syscalls/sys_enter_execve")
// Tracepoint for the sys_enter_execve syscall
void trace_execve(struct pt_regs *ctx)
{
    // Log that execve syscall was invoked
    bpf_printk("execve syscall invoked");
}

SEC("tp/syscalls/sys_enter_fork")
// Tracepoint for the sys_enter_fork syscall
void trace_fork(struct pt_regs *ctx)
{
    // Log that fork syscall was invoked
    bpf_printk("fork syscall invoked");
}

SEC("tp/syscalls/sys_enter_clone")
// Tracepoint for the sys_enter_clone syscall
void trace_clone(struct pt_regs *ctx)
{
    // Log that clone syscall was invoked
    bpf_printk("clone syscall invoked");
}

SEC("tp/syscalls/sys_enter_openat")
// Tracepoint for the sys_enter_openat syscall
void trace_openat(struct pt_regs *ctx)
{
    // Log that openat syscall was invoked
    bpf_printk("openat syscall invoked");
}

// will constantly be invoked on cat command on /sys/kernel/debug/tracing/trace_pipe
//  SEC("tp/syscalls/sys_enter_read")
//  // Tracepoint for the sys_enter_read syscall
//  void trace_read(struct pt_regs *ctx)
//  {
//      // Log that read syscall was invoked
//      bpf_printk("read syscall invoked");
//  }

char _license[] SEC("license") = "Dual MIT/GPL";
// Specifies the license of the eBPF program. The kernel enforces this field to ensure compliance.
