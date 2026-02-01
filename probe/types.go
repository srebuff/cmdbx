// Package probe provides system probing capabilities for CMDB data collection.
// It supports process/service collection and network traffic monitoring.
package probe

import (
	"time"
)

// Service represents an aggregated service (may contain multiple processes)
// This matches the SERVICE schema in design.md
type Service struct {
	InstanceID   string   `json:"instance_id"`
	InstanceIP   string   `json:"instance_ip"`
	Name         string   `json:"name"`
	BinPath      string   `json:"bin_path"`
	StartMode    string   `json:"start_mode"`   // k8s, docker, systemd, native
	DetailCmd    string   `json:"detail_cmd"`   // hash of full cmd
	ContainerID  string   `json:"container_id"` // Docker container ID (short)
	PID          int32    `json:"pid"`
	RootPID      int32    `json:"root_pid"`
	ListenPorts  []uint32 `json:"listen_ports"`
	CPUPercent   float64  `json:"cpu_pct"`
	MemBytes     uint64   `json:"mem_bytes"`
	IOReadBytes  uint64   `json:"io_read_bytes"`
	IOWriteBytes uint64   `json:"io_write_bytes"`
	IOReadMB     float64  `json:"io_read_mb"`
	IOWriteMB    float64  `json:"io_write_mb"`
	IOReadKBps   float64  `json:"io_read_kbps"`
	IOWriteKBps  float64  `json:"io_write_kbps"`
	ChildCount   int      `json:"child_count"`
	Timestamp    int64    `json:"timestamp"`
}

// NetworkTraffic represents network traffic statistics
// This matches the NETWORK_TRAFFIC schema in design.md
type NetworkTraffic struct {
	SrcIP     string    `json:"src_ip"`
	SrcPort   uint16    `json:"src_port"`
	DstIP     string    `json:"dst_ip"`
	DstPort   uint16    `json:"dst_port"`
	Protocol  string    `json:"protocol"` // TCP, UDP, ICMP, etc.
	Packets   uint64    `json:"packets"`
	Bytes     uint64    `json:"bytes"`
	Timestamp time.Time `json:"time"`
}

// FlowKey uniquely identifies a network flow
type FlowKey struct {
	SrcIP    string
	SrcPort  uint16
	DstIP    string
	DstPort  uint16
	Protocol string
}

// ServiceCollector interface for collecting service/process information
type ServiceCollector interface {
	// Collect gathers all services and returns them
	Collect() ([]Service, error)
	// SetInstanceID sets the instance ID for tagging
	SetInstanceID(id string)
	// SetInstanceIP sets the instance IP for tagging
	SetInstanceIP(ip string)
}

// NetworkCollector interface for collecting network traffic
type NetworkCollector interface {
	// Start begins collecting network traffic
	Start() error
	// Stop stops the collection
	Stop() error
	// GetStats returns current traffic statistics
	GetStats() ([]NetworkTraffic, error)
	// ClearStats clears the statistics
	ClearStats()
}

// CollectorType indicates the type of network collector
type CollectorType string

const (
	// CollectorTypeEBPF uses eBPF/XDP for packet capture (kernel >= 4.15)
	CollectorTypeEBPF CollectorType = "ebpf"
	// CollectorTypeGoPacket uses AF_PACKET/gopacket for packet capture
	CollectorTypeGoPacket CollectorType = "gopacket"
	// CollectorTypeNone indicates no network collection available
	CollectorTypeNone CollectorType = "none"
)

// ExcludeList contains process names/patterns to skip
var ExcludeList = []string{
	"kworker",
	"ksoftirqd",
	"kthreadd",
	"migration",
	"rcu_",
	"watchdog",
	"kswapd",
	"kcompactd",
	"khugepaged",
	"kdevtmpfs",
	"kauditd",
	"khungtaskd",
	"oom_reaper",
	"writeback",
	"kblockd",
	"md",
	"edac-poller",
	"cpuhp",
	"netns",
	"rcu_tasks",
}

// ContainerInfraProcesses are container runtime/infrastructure processes
// These should NOT be considered as service roots - they are just "wrappers"
var ContainerInfraProcesses = []string{
	"containerd-shim",
	"containerd-shim-runc-v2",
	"tini",
	"dumb-init",
	"docker-init",
	"pause",
	"s6-svscan",
	"s6-supervise",
	"runc",
}
