//go:build !linux
// +build !linux

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
	Pad      [3]uint8
}

// EBPFFlowStats matches the C struct flow_stats for tracking packets and bytes
type EBPFFlowStats struct {
	Packets uint64
	Bytes   uint64
}

// EBPFCollector is a stub for non-Linux systems
type EBPFCollector struct {
	parent *NetworkTrafficCollector
}

// NewEBPFCollector returns an error on non-Linux systems
func NewEBPFCollector(parent *NetworkTrafficCollector, ifaceName string) (*EBPFCollector, error) {
	return nil, fmt.Errorf("eBPF is only supported on Linux")
}

// Start returns an error on non-Linux systems
func (e *EBPFCollector) Start(pollInterval time.Duration) error {
	return fmt.Errorf("eBPF is only supported on Linux")
}

// Stop is a no-op on non-Linux systems
func (e *EBPFCollector) Stop() error {
	return nil
}

// GetInterface returns nil on non-Linux systems
func (e *EBPFCollector) GetInterface() *net.Interface {
	return nil
}

// ReadStatsOnce returns an error on non-Linux systems
func (e *EBPFCollector) ReadStatsOnce() ([]NetworkTraffic, error) {
	return nil, fmt.Errorf("eBPF is only supported on Linux")
}
