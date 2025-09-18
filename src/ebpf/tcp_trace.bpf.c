#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>

// This struct defines the fields collected for each event.
struct event {
    u32 pid;
    char comm[16];
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
};

// This map is used to send events to user space.
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

// This is the main eBPF program attached to the tcp_connect tracepoint.
SEC("kprobe/tcp_connect")
int trace_func(struct pt_regs *ctx) {
    struct event data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // Extract struct sock *sk from first argument
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);

    // Read source address from sk
    bpf_probe_read_kernel(&data.saddr, sizeof(data.saddr), &sk->__sk_common.skc_rcv_saddr);

    // Read destination address from sk
    bpf_probe_read_kernel(&data.daddr, sizeof(data.daddr), &sk->__sk_common.skc_daddr);

    // Read source port from sk (convert from network to host byte order)
    u16 sport = sk->__sk_common.skc_num;
    data.sport = sport;

    // Read destination port from sk (convert from network to host byte order)
    u16 dport_net;
    bpf_probe_read_kernel(&dport_net, sizeof(dport_net), &sk->__sk_common.skc_dport);
    data.dport = ntohs(dport_net);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}


char LICENSE[] SEC("license") = "GPL";