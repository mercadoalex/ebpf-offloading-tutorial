"""
This script reads spec.txt and generates an eBPF C program.
It automates the tedious parts of writing eBPF code.
"""

spec = {}
with open("../../spec.txt") as f:
    for line in f:
        if not line.strip() or line.strip().startswith("#"):
            continue
        key, value = line.strip().split(":")
        spec[key.strip()] = [v.strip() for v in value.split(",")] if key == "fields" else value.strip()

# Template for the eBPF program
fields_struct = ""
fields_assign = ""
for field in spec["fields"]:
    if field == "pid":
        fields_struct += "    u32 pid;\n"
        fields_assign += "    data.pid = bpf_get_current_pid_tgid() >> 32;\n"
    elif field == "comm":
        fields_struct += "    char comm[16];\n"
        fields_assign += "    bpf_get_current_comm(&data.comm, sizeof(data.comm));\n"
    elif field == "saddr":
        fields_struct += "    u32 saddr;\n"
        fields_assign += "    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);\n"
        fields_assign += "    bpf_probe_read_kernel(&data.saddr, sizeof(data.saddr), &sk->__sk_common.skc_rcv_saddr);\n"
    elif field == "daddr":
        fields_struct += "    u32 daddr;\n"
        fields_assign += "    bpf_probe_read_kernel(&data.daddr, sizeof(data.daddr), &sk->__sk_common.skc_daddr);\n"
    elif field == "sport":
        fields_struct += "    u16 sport;\n"
        fields_assign += "    data.sport = sk->__sk_common.skc_num;\n"
    elif field == "dport":
        fields_struct += "    u16 dport;\n"
        fields_assign += "    u16 dport_net;\n"
        fields_assign += "    bpf_probe_read_kernel(&dport_net, sizeof(dport_net), &sk->__sk_common.skc_dport);\n"
        fields_assign += "    data.dport = ntohs(dport_net);\n"

template = f"""
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>

struct event {{
{fields_struct}
}};

struct {{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
}} events SEC(".maps");

SEC("kprobe/{spec['trace']}")
int trace_func(struct pt_regs *ctx) {{
    struct event data = {{}};
{fields_assign}
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}}

char LICENSE[] SEC("license") = "GPL";
"""

with open("ebpf/tcp_trace.bpf.c", "w") as f:
    f.write(template)

print("eBPF program generated at ebpf/tcp_trace.bpf.c")