
## name

> gocmdb

## Requirements Analaysis

- a agent golang process can do cmdb collect
- cmdb:
  - process (exclude sshd kworker etc ..)
    - execute of process
    - name of process
    - start mode(docker, systemd, or just native start)
    - listen port of process
    - net_in_bytes base the listen port of process
    - cpu of process
    - memory of process
    - diskusage of process
    - iousage of process
- base the collect data, saved to TSDB
---
all the above ,the final target is establish the net between processs, even the processes is not is same machine


## Architecture Overview
> The agent will follow a Collector-Transformer-Exporter pattern. Since you want to link PIDs to network and disk usage, we need a "Context Mapper" to join these disparate data sources.

### High-Level Architecture

```mermaid
flowchart TB
    subgraph DataSources["📊 Data Sources"]
        PROC["/proc filesystem"]
        NETSTAT["Network Sockets"]
        EBPF["eBPF/XDP"]
        GOPSUTIL["gopsutil"]
    end

    subgraph Collector["🔍 Collector Layer"]
        PROBER["Prober"]
        LINKER["Linker<br/>(Context Mapper)"]
        FILTER["Filter Engine"]
    end

    subgraph Transformer["⚙️ Transformer Layer"]
        MAPPER["PID → Port → Path → Disk"]
        ENRICHER["Metric Enricher"]
        SCHEMA["Line Protocol Formatter"]
    end

    subgraph Exporter["📤 Exporter Layer"]
        ACCUM["Accumulator<br/>(Memory Buffer)"]
        PERSIST["Persistent Buffer<br/>(Disk)"]
        SHIPPER["Shipper<br/>(Retry + Backoff)"]
    end

    subgraph Backend["🗄️ Backend"]
        VM["VictoriaMetrics"]
        CMDB["CMDB Database"]
    end

    PROC --> PROBER
    NETSTAT --> PROBER
    EBPF --> PROBER
    GOPSUTIL --> PROBER

    PROBER --> FILTER
    FILTER --> LINKER
    LINKER --> MAPPER
    MAPPER --> ENRICHER
    ENRICHER --> SCHEMA

    SCHEMA --> ACCUM
    ACCUM -->|"batch every 1min"| SHIPPER
    ACCUM -->|"on failure"| PERSIST
    PERSIST -->|"retry"| SHIPPER
    SHIPPER --> VM
    SHIPPER --> CMDB
```

Key Components:
- The Prober: Uses gopsutil or /proc to gather raw data.
- The Linker: The "secret sauce" that maps a Listening Port -> PID -> Executable Path -> Disk Mount.
- The Filter: A regex-based engine to exclude sshd, kworker, etc.
- The Exporter: base https://github.com/VictoriaMetrics/VictoriaMetrics/tree/master/app/vmagent  to implement data local cache, retry, send to victoriametrics batch
  - The Accumulator (Memory): Collects metrics every minute and batches them to reduce HTTP overhead.
  - The Persistent Buffer (Disk): If the DB is down or the network is flaky, data is written to a fast, append-only file on disk.
  - The Shipper (Network + Retry): A background worker that pulls from the buffer and sends to the DB using Exponential Backoff.

## Technical Implementation Strategy

###  Process & Resource Mapping

> Don't reinvent the wheel—use gopsutil. It's the industry standard for Go.

```mermaid
flowchart LR
    subgraph Input["Input"]
        PLIST["Process List<br/>/proc/*/"]
    end

    subgraph Collect["Collect Metrics"]
        CPU["CPU %<br/>Process.Percent()"]
        MEM["Memory<br/>Process.MemoryInfo()"]
        FD["File Descriptors<br/>Process.OpenFiles()"]
    end

    subgraph Filter["Filter Stage"]
        EXCLUDE{"Match<br/>ExcludeList?"}
        SKIP["Skip Process"]
        KEEP["Keep Process"]
    end

    subgraph Output["Output"]
        METRICS["Process Metrics"]
    end

    PLIST --> EXCLUDE
    EXCLUDE -->|"sshd, kworker..."| SKIP
    EXCLUDE -->|"No"| CPU
    EXCLUDE -->|"No"| MEM
    EXCLUDE -->|"No"| FD
    CPU --> KEEP
    MEM --> KEEP
    FD --> KEEP
    KEEP --> METRICS
```

- CPU/Mem: Use Process.Percent() and Process.MemoryInfo().
- Filtering: Use a configuration file (or env var) to define an ExcludeList.
- Tip: Filter early in the loop to save CPU cycles.

### Process I/O Usage

> Track read/write bytes per process using `/proc/PID/io`

```mermaid
flowchart LR
    subgraph Source["📁 /proc/PID/io"]
        IO_FILE["io file"]
    end

    subgraph Parse["Parse Fields"]
        RCHAR["rchar: bytes read"]
        WCHAR["wchar: bytes written"]
        RBYTES["read_bytes: disk reads"]
        WBYTES["write_bytes: disk writes"]
    end

    subgraph Output["📊 I/O Metrics"]
        IO_READ["io_read_bytes"]
        IO_WRITE["io_write_bytes"]
        IO_RATE["io_rate (delta/time)"]
    end

    IO_FILE --> RCHAR
    IO_FILE --> WCHAR
    IO_FILE --> RBYTES
    IO_FILE --> WBYTES
    RBYTES --> IO_READ
    WBYTES --> IO_WRITE
    IO_READ --> IO_RATE
    IO_WRITE --> IO_RATE
```



### Process Start Mode Detection

> Detect how a process was started: k8s, docker, systemd, or native

```mermaid
flowchart TB
    PID["Process PID"]
    
    subgraph Detect["🔍 Start Mode Detection"]
        CGROUP["/proc/PID/cgroup"]
        PPID["Parent PID"]
        UNIT["/proc/PID/cgroup<br/>systemd slice"]
    end

    subgraph Check["Decision Tree"]
        IS_K8S{"Contains<br/>kubepods?"}
        IS_DOCKER{"Contains<br/>docker/containerd?"}
        IS_SYSTEMD{"Parent is<br/>systemd (PID 1)?<br/>or has .service unit?"}
        IS_NATIVE["Native Start"]
    end

    subgraph Result["Start Mode"]
        K8S["k8s"]
        DOCKER["docker"]
        SYSTEMD["systemd"]
        NATIVE["native"]
    end

    PID --> CGROUP
    PID --> PPID
    CGROUP --> IS_K8S
    IS_K8S -->|"Yes"| K8S
    IS_K8S -->|"No"| IS_DOCKER
    IS_DOCKER -->|"Yes"| DOCKER
    IS_DOCKER -->|"No"| IS_SYSTEMD
    PPID --> IS_SYSTEMD
    UNIT --> IS_SYSTEMD
    IS_SYSTEMD -->|"Yes"| SYSTEMD
    IS_SYSTEMD -->|"No"| NATIVE
```

### process aggreation

```mermaid
flowchart TB
    subgraph PstreeOutput["pstree -p 1 output"]
        S["systemd(1)"]
        
        subgraph Service1["Service: blackbox_export"]
            B1["blackbox_export(1344)"]
            BT1["{blackbox_export}(1392)<br/>THREAD - skip!"]
            BT2["{blackbox_export}(1393)<br/>THREAD - skip!"]
        end
        
        subgraph Service2["Service: java"]
            J1["java(3371)"]
            JT1["{java}(117403)<br/>THREAD - skip!"]
            JT2["{java}(117404)<br/>THREAD - skip!"]
        end
        
        subgraph Service3["Service: crond"]
            C1["crond(1519)"]
            C2["crond(42376)<br/>CHILD - aggregate"]
            C3["python(49003)<br/>DIFFERENT exe - separate?"]
        end
    end

    S --> B1
    S --> J1
    S --> C1
    B1 --> BT1
    B1 --> BT2
    J1 --> JT1
    J1 --> JT2
    C1 --> C2
    C2 --> C3
```

#### Key Rules from pstree Analysis

| Rule | Description | Action |
|------|-------------|--------|
| **Skip threads** | `{name}(tid)` in curly braces | Don't collect - already in parent metrics |
| **Find service root** | Direct child of PID 1 (systemd) | This is the service |
| **Aggregate children** | Same exe as parent | Sum metrics to parent |
| **Separate service** | Different exe (crond→python) | Treat as separate service |

#### Implementation: Simple pstree-like Logic  ref example/processdemo

#### 

```mermaid
flowchart TB
    START["Process PID"]
    
    CHECK_DOCKER{"In Docker<br/>container?"}
    CHECK_SYSTEMD{"Has systemd<br/>.service unit?"}
    CHECK_EXE{"Same exe as<br/>parent?"}
    
    DOCKER["Group by Container ID"]
    SYSTEMD["Group by Service Unit"]
    PPID["Group by PPID Chain"]
    EXE["Group by Exe Path"]

    START --> CHECK_DOCKER
    CHECK_DOCKER -->|"Yes"| DOCKER
    CHECK_DOCKER -->|"No"| CHECK_SYSTEMD
    CHECK_SYSTEMD -->|"Yes"| SYSTEMD
    CHECK_SYSTEMD -->|"No"| CHECK_EXE
    CHECK_EXE -->|"Yes"| PPID
    CHECK_EXE -->|"No"| EXE
```

### The Service-to-Disk Chain

- This is the trickiest part. You need to bridge the gap between a network socket and a physical disk.

```mermaid
flowchart TB
    subgraph Network["🌐 Network Layer"]
        SOCKET["TCP/UDP Socket<br/>/proc/net/tcp"]
        PORT["Listen Port<br/>:3306, :8080"]
    end

    subgraph Process["⚡ Process Layer"]
        PID["PID<br/>Process ID"]
        EXE["Executable Path<br/>/proc/PID/exe"]
    end

    subgraph Filesystem["💾 Filesystem Layer"]
        PATH["Binary Path<br/>/usr/bin/mysqld"]
        MOUNT["Mount Point<br/>/data"]
        DISK["Disk Usage<br/>unix.Statfs()"]
    end

    subgraph Output["📊 Output"]
        METRIC["Service Metric<br/>name + path + disk%"]
    end

    SOCKET -->|"inode lookup"| PID
    PORT --> SOCKET
    PID -->|"os.Readlink"| EXE
    EXE --> PATH
    PATH -->|"find mount"| MOUNT
    MOUNT -->|"statfs"| DISK
    
    PID --> METRIC
    PATH --> METRIC
    DISK --> METRIC
```

- Listen Ports: Find PIDs listening on TCP/UDP (via /proc/net/tcp or gopsutil/net).
- Deploy Path: Use os.Readlink("/proc/<pid>/exe") to find where the binary lives.
- Disk Usage: Once you have the path, identify the mount point and use unix.Statfs to get usage for that specific partition.

###  Network Traffic 

> traffic per service, check the linux kernel, when linux kernel > 4.4 use a library like cilium/ebpf,else use socket counters.

```mermaid
flowchart TB
    START["Start Network<br/>Traffic Collection"]
    
    CHECK{"Linux Kernel<br/>Version?"}
    
    subgraph Legacy["Legacy Mode (< 4.4)"]
        GOPACKET["gopacket<br/>AF_PACKET + MMAP"]
        PCAP["Packet Capture"]
        PARSE["Parse Headers"]
    end

    subgraph Modern["Modern Mode (≥ 4.4)"]
        EBPF["eBPF/XDP"]
        HOOK["Hook tcp_sendmsg<br/>tcp_cleanup_rbuf"]
        MAP["BPF Maps<br/>Per-PID Counters"]
    end

    subgraph Metrics["Traffic Metrics"]
        FLOW["Flow Key<br/>src:port → dst:port"]
        BYTES["Bytes TX/RX"]
        PKTS["Packet Count"]
    end

    OUTPUT["Export to<br/>VictoriaMetrics"]

    START --> CHECK
    CHECK -->|"< 4.4"| GOPACKET
    CHECK -->|"≥ 4.4"| EBPF
    
    GOPACKET --> PCAP
    PCAP --> PARSE
    PARSE --> FLOW
    
    EBPF --> HOOK
    HOOK --> MAP
    MAP --> FLOW
    
    FLOW --> BYTES
    FLOW --> PKTS
    BYTES --> OUTPUT
    PKTS --> OUTPUT
```

- AF_PACKET + MMAP： ref [gopacket](./example/gopacketdemo/README.md)

- eBPF: Use a library like cilium/ebpf. It allows you to trace tcp_sendmsg and tcp_cleanup_rbuf to get exact byte counts per PID with near-zero overhead. ref [ebpfdemo](./example/ebpfdemo/README.md)

### eBPF XDP Data Flow

```mermaid
flowchart LR
    subgraph Kernel["🔧 Kernel Space"]
        NIC["NIC Driver"]
        XDP["XDP Hook<br/>(Earliest Point)"]
        PARSE["Parse Packet<br/>ETH → IP → TCP/UDP"]
        FILTER{"Match<br/>Filter Rule?"}
        ACTION["Action:<br/>PASS/DROP/COUNT"]
        BPFMAP["BPF Map<br/>(flow_key → stats)"]
    end

    subgraph User["👤 User Space"]
        POLL["Poll Map<br/>Every N seconds"]
        PRINT["Print Stats"]
        EXPORT["Export Metrics"]
    end

    NIC --> XDP
    XDP --> PARSE
    PARSE --> FILTER
    FILTER -->|"Yes"| ACTION
    FILTER -->|"No"| NIC
    ACTION --> BPFMAP
    BPFMAP -.->|"read"| POLL
    POLL --> PRINT
    POLL --> EXPORT
```

## Exporter Data Flow

```mermaid
flowchart TB
    subgraph Collect["Collection Cycle (every 1 min)"]
        TICK["Timer Tick"]
        GATHER["Gather Metrics"]
        FORMAT["Format to<br/>Line Protocol"]
    end

    subgraph Buffer["Buffer Layer"]
        MEMBUF["Memory Buffer<br/>(Accumulator)"]
        DISKBUF["Disk Buffer<br/>(WAL File)"]
    end

    subgraph Ship["Shipping Layer"]
        BATCH["Batch Builder<br/>(max 1000 lines)"]
        HTTP["HTTP POST<br/>/api/v1/write"]
        RETRY{"Success?"}
        BACKOFF["Exponential<br/>Backoff"]
    end

    subgraph Backend["Backend"]
        VM["VictoriaMetrics"]
    end

    TICK --> GATHER
    GATHER --> FORMAT
    FORMAT --> MEMBUF
    
    MEMBUF -->|"batch full"| BATCH
    MEMBUF -->|"on error"| DISKBUF
    DISKBUF -->|"retry later"| BATCH
    
    BATCH --> HTTP
    HTTP --> RETRY
    RETRY -->|"200 OK"| VM
    RETRY -->|"5xx/timeout"| BACKOFF
    BACKOFF -->|"wait"| DISKBUF
```

## collect Data Schema 

> To make this CMDB-friendly, use https://docs.influxdata.com/influxdb3/core/reference/line-protocol/

### cmdb 
- example:

```
services,instance_id=node-10-104-111-16,name=clusterfileplugin,instance_ip=10.104.111.16,bin_path=/clusterfileplugin,start_mode=k8s,detail_cmd=75a207a4c0840c7a00d994cf7fa294ef7fed57e7f0ae107efcb4858b4ab797b8 pid=6621i,listen_ports="",cpu_pct=0.02,mem_bytes=24076288i,io_read_bytes=70148096i,io_write_bytes=8126464i,io_read_mb=66.90,io_write_mb=7.75,io_read_kbps=0.00,io_write_kbps=0.00,root_pid=6621i,child_count=1i 1769748861679319010
services,instance_id=node-10-104-111-16,name=bo-self_monitor,instance_ip=10.104.111.16,bin_path=/usr/local/bin/bo-self_monitor,start_mode=systemd,detail_cmd=daa4cd11f60276870f97c4d5da7bcf0a4da1021a0cf2e78b23e1a3d5f0460c2d pid=17748i,listen_ports="",cpu_pct=0.02,mem_bytes=11431936i,io_read_bytes=315392i,io_write_bytes=1015808i,io_read_mb=0.30,io_write_mb=0.97,io_read_kbps=0.00,io_write_kbps=0.00,root_pid=17748i,child_count=1i 1769748861679319010
```

### network trafic

- example:

```
network-traffic,dst_ip=,dst_port=,src_ip=,bytes_receive=40040
```

### Data Schema Diagram

```mermaid
erDiagram
    SERVICE {
        string instance_id PK
        string instance_ip
        string name
        string bin_path
        string start_mode "docker/systemd/native"
        string detail_cmd "hash of full cmd"
        int pid
        string listen_ports
        float cpu_pct
        int mem_bytes
        int net_rx_bytes
        int net_tx_bytes
        float disk_usage_pct
        int io_read_bytes "disk read bytes"
        int io_write_bytes "disk write bytes"
        timestamp time
    }

    NETWORK_TRAFFIC {
        string src_ip PK
        int src_port PK
        string dst_ip PK "related with instance_ip of SERVICE"
        int dst_port PK  "realatd with listentports of SERVICE"
        string protocol
        int packets
        int bytes
        timestamp time
    }

    SERVICE ||--o{ NETWORK_TRAFFIC : "generates"
```

## SRE "Best Practices" for the Agent

```mermaid
flowchart TB
    subgraph Practices["🛡️ Best Practices"]
        TIMEOUT["Self-Limiting<br/>context.WithTimeout(10s)"]
        CONCURRENT["Concurrency<br/>sync.WaitGroup"]
        ATOMIC["Atomic Writes<br/>.tmp → rename"]
        STATIC["Static Build<br/>CGO_ENABLED=0"]
    end

    subgraph Timeout["Timeout Flow"]
        T1["Start Collection"]
        T2{"< 10s?"}
        T3["Complete"]
        T4["Kill + Alert"]
    end

    subgraph Atomic["Atomic Write Flow"]
        A1["Write data.tmp"]
        A2["fsync()"]
        A3["rename → data.json"]
    end

    T1 --> T2
    T2 -->|"Yes"| T3
    T2 -->|"No"| T4

    A1 --> A2
    A2 --> A3
```

- Self-Limiting: Wrap the execution in a context.WithTimeout. If the collection takes longer than 10 seconds, kill it and alert. You don't want a "zombie collector" eating the resources it's supposed to monitor.
- Concurrency: Use a WaitGroup to fetch process list and network stats in parallel.
- Atomic Writes: If you are outputting to a file, write to a .tmp file and rename it to prevent the CMDB consumer from reading a half-written file.
- Static Compilation: Use CGO_ENABLED=0 go build to ensure the binary runs on any Linux distro regardless of GLIBC versions.

## Docker/Container Special Handling

> Containers introduce namespace isolation (PID, network, mount) that requires special handling to accurately collect metrics.

### Container Detection Flow

```mermaid
flowchart TB
    subgraph Detection["🔍 Container Detection"]
        PID["Process PID"]
        CGROUP["/proc/PID/cgroup"]
        CHECK{"Contains<br/>docker/kubepods?"}
    end

    subgraph Native["🖥️ Native Process"]
        NATIVE_FLOW["Standard Collection"]
    end

    subgraph Container["🐳 Container Process"]
        CID["Extract Container ID"]
        DOCKER["Docker API<br/>/var/run/docker.sock"]
        INSPECT["docker inspect"]
        META["Container Metadata"]
    end

    subgraph Enrich["📊 Enriched Data"]
        LABELS["Container Labels"]
        IMAGE["Image Name:Tag"]
        NETMODE["Network Mode"]
        MOUNTS["Volume Mounts"]
    end

    PID --> CGROUP
    CGROUP --> CHECK
    CHECK -->|"No"| NATIVE_FLOW
    CHECK -->|"Yes"| CID
    CID --> DOCKER
    DOCKER --> INSPECT
    INSPECT --> META
    META --> LABELS
    META --> IMAGE
    META --> NETMODE
    META --> MOUNTS
```

### Container Namespace Challenges

```mermaid
flowchart LR
    subgraph Namespaces["🔒 Linux Namespaces"]
        PIDNS["PID Namespace<br/>Different PID inside/outside"]
        NETNS["Network Namespace<br/>Isolated network stack"]
        MNTNS["Mount Namespace<br/>Different filesystem view"]
    end

    subgraph Problems["⚠️ Problems"]
        P1["Container PID 1 ≠ Host PID"]
        P2["Container ports via NAT"]
        P3["/proc/PID/exe points to overlay"]
    end

    subgraph Solutions["✅ Solutions"]
        S1["Use Host PID from /proc"]
        S2["Parse docker-proxy or iptables"]
        S3["Resolve through /proc/PID/root"]
    end

    PIDNS --> P1 --> S1
    NETNS --> P2 --> S2
    MNTNS --> P3 --> S3
```

### Container-Aware Collection

```mermaid
flowchart TB
    subgraph Input["Input"]
        PROC["/proc/PID"]
    end

    subgraph Detect["Container Detection"]
        CGROUP_READ["Read /proc/PID/cgroup"]
        PARSE_CID["Parse Container ID<br/>/docker/abc123..."]
    end

    subgraph Docker["Docker API"]
        SOCK["/var/run/docker.sock"]
        API["GET /containers/{id}/json"]
        JSON["Container JSON"]
    end

    subgraph Extract["Extract Metadata"]
        NAME["container_name"]
        IMG["image:tag"]
        LBL["labels{}"]
        NET["NetworkSettings"]
        PORT["PortBindings"]
    end

    subgraph Network["Network Resolution"]
        MODE{"Network<br/>Mode?"}
        HOST["host: Use host ports"]
        BRIDGE["bridge: Map via NAT"]
        OVERLAY["overlay: Use container IP"]
    end

    subgraph Output["Final Metric"]
        METRIC["services,container_id=abc,<br/>container_name=mysql,<br/>image=mysql:8.0"]
    end

    PROC --> CGROUP_READ
    CGROUP_READ --> PARSE_CID
    PARSE_CID --> SOCK
    SOCK --> API
    API --> JSON
    JSON --> NAME
    JSON --> IMG
    JSON --> LBL
    JSON --> NET
    NET --> PORT
    PORT --> MODE
    MODE -->|"host"| HOST
    MODE -->|"bridge"| BRIDGE
    MODE -->|"overlay"| OVERLAY
    HOST --> METRIC
    BRIDGE --> METRIC
    OVERLAY --> METRIC
    NAME --> METRIC
    IMG --> METRIC
    LBL --> METRIC
```

### Container Network Modes

```mermaid
flowchart TB
    subgraph Modes["🌐 Docker Network Modes"]
        HOST["--network=host"]
        BRIDGE["--network=bridge (default)"]
        OVERLAY["--network=overlay"]
        NONE["--network=none"]
    end

    subgraph HostMode["Host Mode"]
        H1["Container shares host network"]
        H2["Ports visible directly"]
        H3["eBPF sees all traffic"]
    end

    subgraph BridgeMode["Bridge Mode (NAT)"]
        B1["docker0 bridge"]
        B2["Port mapping: -p 8080:80"]
        B3["docker-proxy process"]
        B4["iptables DNAT rules"]
    end

    subgraph OverlayMode["Overlay Mode (Swarm/K8s)"]
        O1["VXLAN encapsulation"]
        O2["Container has own IP"]
        O3["May need CNI awareness"]
    end

    HOST --> H1 --> H2 --> H3
    BRIDGE --> B1 --> B2 --> B3 --> B4
    OVERLAY --> O1 --> O2 --> O3
```

### Implementation: Container ID Extraction

```go
// Example: Extract container ID from /proc/PID/cgroup
func getContainerID(pid int) (string, error) {
    data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
    if err != nil {
        return "", err
    }
    
    // Docker cgroup v1: /docker/<container_id>
    // Docker cgroup v2: /system.slice/docker-<container_id>.scope
    // Kubernetes: /kubepods/pod<pod_id>/<container_id>
    
    re := regexp.MustCompile(`docker[/-]([a-f0-9]{64})`)
    matches := re.FindStringSubmatch(string(data))
    if len(matches) > 1 {
        return matches[1][:12], nil // Short ID
    }
    return "", nil // Not a container
}
```

### Container-Enriched Data Schema

```mermaid
erDiagram
    SERVICE {
        string instance_id PK
        string name
        string bin_path
        int pid
        string listen_ports
        float cpu_pct
        int mem_bytes
        float disk_usage_pct
        timestamp time
    }

    CONTAINER {
        string container_id PK
        string container_name
        string image
        string image_tag
        string network_mode
        string labels
        string pod_name
        string namespace
    }

    SERVICE ||--o| CONTAINER : "runs_in"
```

### Updated Line Protocol with Container Tags

```
# Native process
services,instance_id=i-0abc,name=nginx,bin_path=/usr/sbin/nginx pid=1234i,cpu_pct=2.5 1700000000000000000

# Container process
services,instance_id=i-0abc,name=nginx,container_id=abc123def456,container_name=web-nginx,image=nginx,image_tag=1.25,network_mode=bridge pid=5678i,cpu_pct=1.2 1700000000000000000

# Kubernetes pod
services,instance_id=i-0abc,name=nginx,container_id=abc123def456,pod_name=web-nginx-7d4b8c,namespace=production,image=nginx,image_tag=1.25 pid=5678i,cpu_pct=1.2 1700000000000000000
```

### Container Detection Sequence

```mermaid
sequenceDiagram
    participant Prober
    participant Proc as /proc
    participant Docker as Docker API
    participant Enricher

    Prober->>Proc: Read /proc/PID/cgroup
    Proc-->>Prober: cgroup content
    
    alt Contains docker/kubepods
        Prober->>Prober: Extract Container ID
        Prober->>Docker: GET /containers/{id}/json
        Docker-->>Prober: Container metadata
        Prober->>Enricher: PID + Container info
        Enricher->>Enricher: Add container_id, image, labels
    else Native process
        Prober->>Enricher: PID only
    end
    
    Enricher-->>Prober: Enriched metric
```

### eBPF Considerations for Containers

```mermaid
flowchart TB
    subgraph Challenge["⚠️ eBPF + Containers"]
        C1["XDP attaches to<br/>physical NIC"]
        C2["Bridge traffic goes<br/>through veth pairs"]
        C3["Container IP vs Host IP"]
    end

    subgraph Solutions["✅ Solutions"]
        direction TB
        S1["Attach to docker0<br/>bridge interface"]
        S2["Use TC instead of XDP<br/>for container traffic"]
        S3["Hook at socket level<br/>(tcp_sendmsg) for PID"]
    end

    subgraph Recommendation["💡 Recommendation"]
        R1["For host network: XDP on eth0"]
        R2["For bridge network: TC on docker0"]
        R3["For per-PID stats: socket hooks"]
    end

    C1 --> S1
    C2 --> S2
    C3 --> S3
    S1 --> R1
    S2 --> R2
    S3 --> R3
```

### Container-Aware Agent Deployment

```mermaid
flowchart LR
    subgraph Deployment["📦 Deployment Options"]
        BINARY["Host Binary<br/>with docker.sock access"]
        DAEMONSET["K8s DaemonSet<br/>hostPID: true"]
        PRIVILEGED["Privileged Container<br/>access to /proc"]
    end

    subgraph Requirements["🔑 Requirements"]
        R1["Mount /var/run/docker.sock"]
        R2["Mount /proc (hostPath)"]
        R3["CAP_SYS_PTRACE"]
        R4["CAP_NET_ADMIN"]
    end

    BINARY --> R1
    BINARY --> R3
    DAEMONSET --> R2
    DAEMONSET --> R3
    DAEMONSET --> R4
    PRIVILEGED --> R2
    PRIVILEGED --> R1
```

### Kubernetes-Specific Enrichment

```mermaid
flowchart TB
    subgraph K8s["☸️ Kubernetes Environment"]
        POD["Pod"]
        CONTAINER["Container"]
        LABELS["Pod Labels<br/>app, version, team"]
        NS["Namespace"]
    end

    subgraph Sources["Data Sources"]
        CGROUP["/proc/PID/cgroup<br/>→ pod UID"]
        CRICTL["crictl inspect"]
        DOWNWARD["Downward API<br/>(if running in cluster)"]
    end

    subgraph Output["Enriched Tags"]
        T1["pod_name"]
        T2["namespace"]
        T3["app_label"]
        T4["deployment"]
    end

    POD --> CGROUP
    CONTAINER --> CRICTL
    LABELS --> DOWNWARD
    CGROUP --> T1
    CGROUP --> T2
    CRICTL --> T3
    DOWNWARD --> T4
```

## Potential Pitfalls

```mermaid
flowchart LR
    subgraph Pitfalls["⚠️ Pitfalls"]
        PERM["Permission Denied"]
        CHURN["High PID Churn"]
        DOCKER["Docker Socket Access"]
        NETNS["Network Namespace Isolation"]
    end

    subgraph Solutions["✅ Solutions"]
        CAP["Add Capabilities<br/>CAP_NET_RAW<br/>CAP_SYS_PTRACE"]
        FREQ["Increase Frequency<br/>or Accept Gaps"]
        SOCK["Mount docker.sock<br/>or use containerd"]
        NSENTER["nsenter or<br/>attach to container netns"]
    end

    PERM -->|"fix"| CAP
    CHURN -->|"fix"| FREQ
    DOCKER -->|"fix"| SOCK
    NETNS -->|"fix"| NSENTER
```

- Permission Denied: To see other processes' disk and network info, the util will likely need sudo or CAP_NET_RAW / CAP_SYS_PTRACE capabilities.
- High PID Churn: If the ECS instance has many short-lived processes, your "1-minute snapshot" might miss them. (Usually fine for CMDB, bad for billing).
- Docker Socket Access: Agent needs access to `/var/run/docker.sock` to query container metadata. For Kubernetes, may need `crictl` or kubelet API.
- Network Namespace Isolation: Containers in bridge mode have isolated network stacks. Use `nsenter -t PID -n` to enter container's network namespace if needed.

## Component Interaction Sequence

```mermaid
sequenceDiagram
    participant Timer
    participant Prober
    participant Linker
    participant Filter
    participant Exporter
    participant VM as VictoriaMetrics

    Timer->>Prober: Tick (every 1 min)
    
    par Parallel Collection
        Prober->>Prober: Get Process List
        Prober->>Prober: Get Network Stats
        Prober->>Prober: Get eBPF Maps
    end

    Prober->>Filter: Raw Metrics
    Filter->>Filter: Apply ExcludeList
    Filter->>Linker: Filtered Metrics
    
    Linker->>Linker: Map Port→PID→Path→Disk
    Linker->>Exporter: Enriched Metrics
    
    Exporter->>Exporter: Format Line Protocol
    Exporter->>Exporter: Batch (max 1000)
    
    alt Backend Available
        Exporter->>VM: HTTP POST /write
        VM-->>Exporter: 200 OK
    else Backend Down
        Exporter->>Exporter: Write to Disk Buffer
        Note over Exporter: Retry with backoff
    end
```
