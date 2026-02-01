//go:build !linux || !cgo
// +build !linux !cgo

package probe

import (
	"fmt"
	"net"
)

// GoPacketCollector is a stub for non-Linux systems
type GoPacketCollector struct {
	parent *NetworkTrafficCollector
}

// GoPacketCollectorOption is a functional option for GoPacketCollector
type GoPacketCollectorOption func(*GoPacketCollector)

// WithFrameSize is a no-op on non-Linux systems
func WithFrameSize(size int) GoPacketCollectorOption {
	return func(c *GoPacketCollector) {}
}

// WithBlockSize is a no-op on non-Linux systems
func WithBlockSize(size int) GoPacketCollectorOption {
	return func(c *GoPacketCollector) {}
}

// WithNumBlocks is a no-op on non-Linux systems
func WithNumBlocks(n int) GoPacketCollectorOption {
	return func(c *GoPacketCollector) {}
}

// NewGoPacketCollector returns an error on non-Linux systems
func NewGoPacketCollector(parent *NetworkTrafficCollector, ifaceName string, opts ...GoPacketCollectorOption) (*GoPacketCollector, error) {
	return nil, fmt.Errorf("gopacket/AF_PACKET is only supported on Linux")
}

// Start returns an error on non-Linux systems
func (c *GoPacketCollector) Start() error {
	return fmt.Errorf("gopacket/AF_PACKET is only supported on Linux")
}

// Stop is a no-op on non-Linux systems
func (c *GoPacketCollector) Stop() error {
	return nil
}

// GetInterface returns nil on non-Linux systems
func (c *GoPacketCollector) GetInterface() *net.Interface {
	return nil
}

// GetPacketCount returns 0 on non-Linux systems
func (c *GoPacketCollector) GetPacketCount() uint64 {
	return 0
}

// IsRunning returns false on non-Linux systems
func (c *GoPacketCollector) IsRunning() bool {
	return false
}
