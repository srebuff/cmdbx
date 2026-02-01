//go:build linux && !amd64
// +build linux,!amd64

package probe

import (
	"fmt"
	"net"
	"time"
)

// EBPFFlowKey matches the C struct flow_key for tracking connections
type EBPFFlowKey struct {
	SrcIP    uint32
	DstIP    uint32
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
	Pad      [3]uint8 // padding for alignment
}

// EBPFFlowStats matches the C struct flow_stats for tracking packets and bytes
type EBPFFlowStats struct {
	Packets uint64
	Bytes   uint64
}

// EBPFCollector stub for non-amd64 architectures
// eBPF packet counting is only supported on amd64
type EBPFCollector struct {
	iface  *net.Interface
	parent *NetworkTrafficCollector
}

// NewEBPFCollector returns an error on non-amd64 architectures
func NewEBPFCollector(parent *NetworkTrafficCollector, ifaceName string) (*EBPFCollector, error) {
	return nil, fmt.Errorf("eBPF collector is only supported on amd64 architecture")
}

// GetInterface returns the network interface (stub)
func (e *EBPFCollector) GetInterface() *net.Interface {
	return e.iface
}

// Start returns an error on non-amd64 architectures
func (e *EBPFCollector) Start(pollInterval time.Duration) error {
	return fmt.Errorf("eBPF collector is only supported on amd64 architecture")
}

// Stop is a no-op on non-amd64 architectures
func (e *EBPFCollector) Stop() error {
	return nil
}

// ReadStatsOnce returns an error on non-amd64 architectures
func (e *EBPFCollector) ReadStatsOnce() ([]NetworkTraffic, error) {
	return nil, fmt.Errorf("eBPF collector is only supported on amd64 architecture")
}
