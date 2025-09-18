"""
This script loads the generated eBPF program and prints events.
Requires the 'bcc' Python package.
"""

from bcc import BPF

# Load the generated eBPF program
bpf = BPF(src_file="ebpf/tcp_trace.bpf.c")

# Define a callback to print each event
def print_event(cpu, data, size):
    event = bpf["events"].event(data)
    print(f"PID: {event.pid}, COMM: {event.comm}")

# Open the perf buffer to receive events
bpf["events"].open_perf_buffer(print_event)
print("Tracing TCP connects... Press Ctrl-C to exit.")

while True:
    try:
        bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        break