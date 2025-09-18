# eBPF Offloading Tutorial

This project demonstrates how to automate the generation of eBPF programs using a high-level specification.  
You write your tracing requirements in `spec.txt`, and the Python script generates the corresponding eBPF code.

## How it works

1. Edit `spec.txt` to specify what you want to trace.
2. Run `generate_ebpf.py` to create the eBPF program.
3. Use `main.py` to load and run the eBPF program, printing trace events.

## Files

- `spec.txt`: High-level tracing specification.
- `src/generate_ebpf.py`: Code generator script.
- `src/ebpf/tcp_trace.bpf.c`: Generated eBPF code.
- `src/main.py`: Loader and event printer.

## Author
Alejandro Mercado Peña

## A comprehensive explanation can be found in my blog
[Read on Medium](https://alexmarket.medium.com/offloading-the-tedious-task-of-writing-ebpf-programs-e8ebfce45c69)
