# eBPF Network Monitor with Dynamic Filtering

An XDP-based network monitor that supports dynamic filter rules at runtime.

## Build

```bash
make build
```

## Usage

### Basic monitoring (no filtering)
```bash
sudo ./ebpfdemo -i eth0
```

### Enable filtering mode
```bash
sudo ./ebpfdemo -i eth0 -filter
```

### Add filter rules
Rule format: `src_ip,dst_ip,src_port,dst_port,proto,action`

- Use `*` or `0` for wildcard (match any)
- Proto: `tcp`, `udp`, `icmp`, `any`, or number
- Action: `count`, `drop`, `pass`

```bash
# Drop all traffic from 192.168.1.100
sudo ./ebpfdemo -i eth0 -filter -add "192.168.1.100,*,*,*,any,drop"

# Drop TCP traffic to port 22 (SSH)
sudo ./ebpfdemo -i eth0 -filter -add "*,*,*,22,tcp,drop"

# Count UDP traffic on port 53 (DNS)
sudo ./ebpfdemo -i eth0 -filter -add "*,*,*,53,udp,count"

# Drop all traffic from subnet (single IP example)
sudo ./ebpfdemo -i eth0 -filter -add "10.0.0.5,*,*,*,any,drop"
```

### Change stats interval
```bash
sudo ./ebpfdemo -i eth0 -interval 10s
```

## Filter Rule Examples

| Rule | Description |
|------|-------------|
| `192.168.1.100,*,*,*,any,drop` | Drop all from IP |
| `*,192.168.1.1,*,*,any,drop` | Drop all to IP |
| `*,*,*,80,tcp,count` | Count HTTP traffic |
| `*,*,*,443,tcp,count` | Count HTTPS traffic |
| `*,*,*,22,tcp,drop` | Block SSH |
| `*,*,53,*,udp,count` | Count DNS queries |
| `10.0.0.0,*,*,*,icmp,drop` | Drop ICMP from IP |

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Userspace (Go)                          │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐    │
│  │  Config  │  │  Filter  │  │    IP    │  │   Rule   │    │
│  │   Map    │  │  Rules   │  │  Stats   │  │  Stats   │    │
│  │ (on/off) │  │ (64 max) │  │ (bytes)  │  │(matches) │    │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘    │
│       │             │             │             │           │
├───────┼─────────────┼─────────────┼─────────────┼───────────┤
│       │             │             │             │           │
│       ▼             ▼             ▼             ▼           │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              XDP Program (count_packets)             │   │
│  │  1. Parse packet (ETH → IP → TCP/UDP)               │   │
│  │  2. Check filter rules if enabled                    │   │
│  │  3. Update IP stats                                  │   │
│  │  4. Return XDP_PASS or XDP_DROP                     │   │
│  └─────────────────────────────────────────────────────┘   │
│                     Kernel (eBPF/XDP)                       │
└─────────────────────────────────────────────────────────────┘
```

## Requirements

- Linux kernel 5.x+ with XDP support
- clang, llvm, libbpf-dev
- Root privileges (for XDP attachment)
