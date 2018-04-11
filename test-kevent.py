#!/usr/bin/env python
#
# This is a Hello World example that formats output as fields.

from bcc import BPF

# define BPF program
prog = """
#include <linux/cpu.h>
#include <linux/interrupt.h>
#include <linux/kernel_stat.h>
#include <linux/of.h>
#include <linux/seq_file.h>
#include <linux/smp.h>
#include <linux/ftrace.h>
#include <linux/delay.h>
#include <linux/export.h>

#include <asm/apic.h>
#include <asm/io_apic.h>
#include <asm/irq.h>
#include <asm/mce.h>
#include <asm/hw_irq.h>
#include <asm/desc.h>

unsigned int irq_handler(struct pt_regs *regs) {

    struct irq_desc *desc;

    int irq_num;

    unsigned int vector = ~regs->orig_ax;
    bpf_trace_printk("VECTOR: %d \\n ", vector);

    desc = __this_cpu_read(vector_irq[vector]);

    return 0;
}

"""

# load BPF program
b = BPF(text=prog)
# b.attach_kprobe(event="sys_clone", fn_name="hello")
b.attach_kprobe(event="do_IRQ", fn_name="irq_handler")

# header
# print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "MESSAGE"))

# format output
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue
    print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))