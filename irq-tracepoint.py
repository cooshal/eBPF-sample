#!/usr/bin/python
#
# urandomread-explicit  Example of instrumenting a kernel tracepoint.
#                       For Linux, uses BCC, BPF. Embedded C.
#
# This is an older example of instrumenting a tracepoint, which defines
# the argument struct and makes an explicit call to attach_tracepoint().
# See urandomread for a newer version that uses TRACEPOINT_PROBE().
#
# REQUIRES: Linux 4.7+ (BPF_PROG_TYPE_TRACEPOINT support).
#
# Test by running this, then in another shell, run:
#     dd if=/dev/urandom of=/dev/null bs=1k count=5
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from __future__ import print_function
from bcc import BPF

# define BPF program
bpf_text = """
#include <linux/netdevice.h>

struct irq_ctx {
	/* Tracepoint common fields */
	unsigned short common_type;	//	offset:0;  size:2; signed:0;
	unsigned char common_flags;	//	offset:2;  size:1; signed:0;
	unsigned char common_preempt_count;//	offset:3;  size:1; signed:0;
	int common_pid;			//	offset:4;  size:4; signed:1;

	/* Tracepoint specific fields */
	int irq;    // offset:8;    size:4; signed:1;
    char name[]; // offset:12;  size:4; signed:1; 
};

TRACEPOINT_PROBE(irq, irq_handler_entry) {
    u64 __pid_tgid = bpf_get_current_pid_tgid();
    u32 __pid      = __pid_tgid;        // lower 32 bits
    u32 __tgid     = __pid_tgid >> 32;  // upper 32 bits


    if (!(args->irq==19)) return 0;
    
    bpf_trace_printk("IRQ %d encountered \\n", args->irq);

    return 0;
}
"""

# load BPF program
b = BPF(text=bpf_text)
b.attach_tracepoint("irq:irq_handler_entry():int:args->irq:args->irq==19'", "sycon_irq_handler")

# header
print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "GOTBITS"))

# format output
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue
    print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))
