# agent_cmdb

A lightweight CMDB agent for collecting process/service information and network traffic data.

## Features

- **Service Collection**: Process discovery, CPU/memory/IO metrics, listening ports
- **Network Traffic**: eBPF or gopacket-based packet capture
- **Output Formats**: InfluxDB line protocol, JSON
- **Container Aware**: Detects Docker, Kubernetes, systemd services

## Quick Start

```bash
# Build
make build

# Run once, show top 10 services by CPU
./build/agent_cmdb --once --top 10 --sort cpu

# Output as JSON
./build/agent_cmdb --once --format json

# Continuous collection with network monitoring (requires root)
./build/agent_cmdb --network --verbose
```

## Build

### Local Build

```bash
# Full build (with gopacket support, requires libpcap-dev)
make build

# Static build (no CGO, smaller binary, eBPF still works)
make build-static

# Run tests
make test

# Full CI checks
make ci
```

### Build for CentOS 7

```bash
# Usage examples:
./compose/build-centos7.sh static   # Default: static binary, eBPF works
./compose/build-centos7.sh dynamic  # With gopacket support
./compose/build-centos7.sh image    # Docker image only
./compose/build-centos7.sh both     # Build both binaries
```

## Usage

```
Usage of agent_cmdb:
  -collector string
        Network collector: auto, ebpf, gopacket (default "auto")
  -format string
        Output format: line, json (default "line")
  -instance-id string
        Instance ID (default: hostname)
  -instance-ip string
        Instance IP (default: auto-detect)
  -interface string
        Network interface (default: auto-detect)
  -io-rate-duration duration
        IO rate sampling duration (default 3s)
  -network
        Collect network traffic
  -network-interval duration
        Network stats collection interval (default 30s)
  -once
        Run once and exit
  -output string
        Output file (default: stdout)
  -service-interval duration
        Service collection interval (default 1m0s)
  -services
        Collect service information (default true)
  -sort string
        Sort services by: name, cpu, memory, io_r, io_w (default "cpu")
  -top int
        Show only top N services (0 = all)
  -verbose
        Enable verbose logging
  -version
        Show version information
```

## Output Examples

### Line Protocol (InfluxDB)

```
services,instance_id=node-01,name=nginx,instance_ip=10.0.0.1,bin_path=/usr/sbin/nginx,start_mode=systemd,detail_cmd=abc123 pid=1234i,listen_ports="80,443",cpu_pct=2.5,mem_bytes=52428800i,io_read_kbps=10.5,io_write_kbps=5.2,root_pid=1234i,child_count=4i 1704067200000000000
```

### JSON

```json
[
  {
    "instance_id": "node-01",
    "name": "nginx",
    "pid": 1234,
    "listen_ports": [80, 443],
    "cpu_pct": 2.5,
    "mem_bytes": 52428800
  }
]
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     agent_cmdb                          │
├─────────────────────────────────────────────────────────┤
│  main.go          - CLI entry point                     │
│  probe/           - Collection modules                  │
│    ├── service.go   - Process/service collector         │
│    ├── network.go   - Network traffic collector         │
│    ├── kernel.go    - Kernel version detection          │
│    └── types.go     - Data structures                   │
└─────────────────────────────────────────────────────────┘
```

## Requirements

- **Linux**: Required for process and network monitoring
- **Root/CAP_NET_ADMIN**: Required for network collection
- **Kernel 4.15+**: For eBPF network collector
- **Kernel 3.x+**: For gopacket (AF_PACKET) fallback

## Troubleshooting

### eBPF Error: "BPF_STX uses reserved fields"

This error occurs when the eBPF bytecode was compiled with a newer clang/kernel than the target system.

```
BPF verifier error: BPF_STX uses reserved fields
```

**Solutions:**

1. **Use gopacket instead** (recommended):
   ```bash
   ./agent_cmdb --network --collector gopacket
   ```

2. **Rebuild on the target system**: The eBPF code must be compiled on a system with compatible clang/kernel versions. Use `./compose/build-centos7.sh` for CentOS 7.

3. **Check kernel version**:
   ```bash
   uname -r
   # eBPF requires kernel >= 4.15
   # For best compatibility, use kernel >= 5.7
   ```

### Network collector fails to start

- Ensure running as **root** or with `CAP_NET_ADMIN` capability
- For Docker: `docker run --cap-add=NET_ADMIN --cap-add=SYS_ADMIN ...`

## License

MIT
