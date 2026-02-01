# Process Collector MVP

A lightweight process collector for CMDB that implements:
- Process discovery and filtering
- Start mode detection (docker, systemd, native)
- Listen port detection
- CPU, Memory, I/O metrics
- Process tree convergence (aggregates parent + children)

## Build

```bash
go build -o processdemo .
```

## Usage

```bash
# Run once with table output (human readable)
./processdemo -once -format table

# Run once with line protocol output (for TSDB)
./processdemo -once -format line

# Run continuously every 60 seconds
./processdemo -interval 60 -format line

# With custom instance ID
./processdemo -instance-id "prod-server-01" -format line
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-interval` | 60 | Collection interval in seconds |
| `-once` | false | Run once and exit |
| `-v` | false | Verbose output |
| `-format` | line | Output format: `line` (influx), `json`, `table` |
| `-instance-id` | hostname | Instance ID for tagging |

## Output Formats

### Line Protocol (for VictoriaMetrics/InfluxDB)

```
services,instance_id=myhost,name=nginx,instance_ip=10.0.0.1,bin_path=/usr/sbin/nginx,start_mode=systemd pid=1234i,listen_ports="80,443",cpu_pct=2.50,mem_bytes=52428800i,io_read_bytes=102400i,io_write_bytes=51200i,root_pid=1234i,child_count=3i 1700000000000000000
```

### Table (human readable)

```
--- Services [10:12:25] ---
NAME                 | PID      | START_MODE | CPU%     | MEM(MB)    | PORTS           | EXE
----------------------------------------------------------------------------------------------------
nginx                | 1234     | systemd    | 2.50     | 50.0       | 80,443          | nginx
mysql                | 5678     | docker     | 5.00     | 512.0      | 3306            | mysqld
```

### JSON

```json
[
  {"name":"nginx","pid":1234,"start_mode":"systemd","exe":"/usr/sbin/nginx","cpu_pct":2.50,"mem_bytes":52428800,"io_read_bytes":102400,"io_write_bytes":51200,"listen_ports":"80,443","child_count":3,"instance_ip":"10.0.0.1"}
]
```

## Features

### Start Mode Detection

| Mode | Detection Method |
|------|------------------|
| `docker` | cgroup contains `docker`, `kubepods`, or `containerd` |
| `systemd` | cgroup contains `.service` or `system.slice`, or PPID is 1 |
| `native` | Default for other processes |

### Process Tree Convergence

The collector aggregates parent and child processes into a single service:

1. **Threads are skipped** - They share memory/CPU with parent (already counted)
2. **Service root = direct child of systemd (PID 1)**
3. **Same exe = aggregate** - Sum CPU, Memory, I/O; merge ports
4. **Different exe = separate service**

### Excluded Processes

Kernel threads and system processes are automatically excluded:
- kworker, ksoftirqd, kthreadd
- migration, rcu_*, watchdog
- kswapd, kcompactd, khugepaged
- And more kernel threads...

## Architecture

```
┌─────────────────┐
│   /proc/[PID]   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│     Filter      │ ← Skip kernel threads, excluded names
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Collect Data   │ ← CPU%, Memory, I/O, Ports
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Convergence    │ ← Group by service root (PPID chain)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│    Output       │ ← Line protocol / JSON / Table
└─────────────────┘
```

## Requirements

- Linux (uses `/proc` filesystem)
- Go 1.21+
- May need `CAP_SYS_PTRACE` for reading other processes' info
