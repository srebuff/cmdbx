//go:build linux && cgo
// +build linux,cgo

package probe

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
)

// GoPacketCollector implements AF_PACKET-based network traffic collection
// using gopacket library. This works on older kernels where eBPF is not available.
type GoPacketCollector struct {
	mu          sync.RWMutex
	handle      *afpacket.TPacket
	iface       *net.Interface
	stopCh      chan struct{}
	stoppedCh   chan struct{}
	parent      *NetworkTrafficCollector
	packetCount uint64
	running     bool

	// Configuration
	frameSize   int
	blockSize   int
	numBlocks   int
	pollTimeout time.Duration
	pollInterval time.Duration

	stats map[FlowKey]*NetworkTraffic
}

// GoPacketCollectorOption is a functional option for GoPacketCollector
type GoPacketCollectorOption func(*GoPacketCollector)

// WithFrameSize sets the frame size for AF_PACKET
func WithFrameSize(size int) GoPacketCollectorOption {
	return func(c *GoPacketCollector) {
		c.frameSize = size
	}
}

// WithBlockSize sets the block size for AF_PACKET
func WithBlockSize(size int) GoPacketCollectorOption {
	return func(c *GoPacketCollector) {
		c.blockSize = size
	}
}

// WithNumBlocks sets the number of blocks for AF_PACKET ring buffer
func WithNumBlocks(n int) GoPacketCollectorOption {
	return func(c *GoPacketCollector) {
		c.numBlocks = n
	}
}

// WithPollTimeout sets the poll timeout for AF_PACKET reads.
func WithPollTimeout(d time.Duration) GoPacketCollectorOption {
	return func(c *GoPacketCollector) {
		c.pollTimeout = d
	}
}

// NewGoPacketCollector creates a new gopacket-based network collector
func NewGoPacketCollector(parent *NetworkTrafficCollector, ifaceName string, opts ...GoPacketCollectorOption) (*GoPacketCollector, error) {
	// Get interface
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("interface %q not found: %w", ifaceName, err)
	}

	c := &GoPacketCollector{
		iface:     iface,
		stopCh:    make(chan struct{}),
		stoppedCh: make(chan struct{}),
		parent:    parent,
		// Default values matching gopacketdemo
		frameSize:   4096,
		blockSize:   4096 * 128, // 512KB blocks
		numBlocks:   128,        // Total ~64MB ring buffer
		pollTimeout: 100 * time.Millisecond,
		stats:       make(map[FlowKey]*NetworkTraffic),
	}
	if parent != nil && parent.pollInterval > 0 {
		c.pollInterval = parent.pollInterval
	} else {
		c.pollInterval = 5 * time.Second
	}

	// Apply options
	for _, opt := range opts {
		opt(c)
	}

	return c, nil
}

// Start begins capturing packets using AF_PACKET
func (c *GoPacketCollector) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.running {
		return fmt.Errorf("collector already running")
	}

	// Create a new TPacket (AF_PACKET) source
	handle, err := afpacket.NewTPacket(
		afpacket.OptInterface(c.iface.Name),
		afpacket.OptFrameSize(c.frameSize),
		afpacket.OptBlockSize(c.blockSize),
		afpacket.OptNumBlocks(c.numBlocks),
		afpacket.OptPollTimeout(c.pollTimeout),
	)
	if err != nil {
		return fmt.Errorf("failed to create AF_PACKET handle: %w", err)
	}

	c.handle = handle
	c.stopCh = make(chan struct{})
	c.stoppedCh = make(chan struct{})
	c.running = true

	// Start packet capture goroutine
	go c.captureLoop()
	go c.flushLoop()

	return nil
}

// captureLoop reads packets from AF_PACKET and records statistics
func (c *GoPacketCollector) captureLoop() {
	defer close(c.stoppedCh)
	defer func() {
		if c.handle != nil {
			c.handle.Close()
		}
	}()
	defer func() {
		// Recover from any panics in packet processing
		if r := recover(); r != nil {
			// Recovered from panic, continue gracefully
			_ = r // Silence staticcheck SA9003
		}
	}()

	// Wrap handle in gopacket for easy decoding
	packetSource := gopacket.NewPacketSource(c.handle, layers.LinkTypeEthernet)
	packetSource.NoCopy = true // Don't copy packet data for performance
	packetSource.DecodeOptions.Lazy = true
	packetSource.DecodeOptions.NoCopy = true

	// Use a loop with explicit error checking instead of channel
	for {
		// Check if we should stop
		select {
		case <-c.stopCh:
			return
		default:
		}

		// Read packet with timeout
		packet, _, err := c.handle.ZeroCopyReadPacketData()
		if err != nil {
			// Handle specific errors
			select {
			case <-c.stopCh:
				return
			default:
				// Brief sleep on error to prevent tight loop
				time.Sleep(10 * time.Millisecond)
				continue
			}
		}

		// Decode and process packet
		decoded := gopacket.NewPacket(packet, layers.LayerTypeEthernet, gopacket.NoCopy)
		c.processPacket(decoded)
	}
}

// flushLoop periodically flushes interval stats to the parent collector.
func (c *GoPacketCollector) flushLoop() {
	ticker := time.NewTicker(c.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.flushStats()
		}
	}
}

// flushStats snapshots current interval stats and writes them to the parent.
func (c *GoPacketCollector) flushStats() {
	c.mu.Lock()
	snapshot := c.stats
	c.stats = make(map[FlowKey]*NetworkTraffic, len(snapshot))
	c.mu.Unlock()

	c.parent.ClearStats()
	for _, traffic := range snapshot {
		c.parent.RecordTraffic(
			traffic.SrcIP,
			traffic.SrcPort,
			traffic.DstIP,
			traffic.DstPort,
			traffic.Protocol,
			traffic.Packets,
			traffic.Bytes,
		)
	}
}

// processPacket extracts flow information and records traffic
func (c *GoPacketCollector) processPacket(packet gopacket.Packet) {
	// Get network layer (IP)
	netLayer := packet.NetworkLayer()
	if netLayer == nil {
		return
	}

	var srcIP, dstIP string
	var protocol string

	// Handle IPv4
	if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		ipv4, ok := ipv4Layer.(*layers.IPv4)
		if !ok || ipv4 == nil {
			return
		}
		srcIP = ipv4.SrcIP.String()
		dstIP = ipv4.DstIP.String()
		protocol = ProtocolNumberToName(uint8(ipv4.Protocol))
	} else if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
		// Handle IPv6
		ipv6, ok := ipv6Layer.(*layers.IPv6)
		if !ok || ipv6 == nil {
			return
		}
		srcIP = ipv6.SrcIP.String()
		dstIP = ipv6.DstIP.String()
		protocol = ProtocolNumberToName(uint8(ipv6.NextHeader))
	} else {
		return
	}

	var srcPort, dstPort uint16

	// Get transport layer ports
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, ok := tcpLayer.(*layers.TCP)
		if ok && tcp != nil {
			srcPort = uint16(tcp.SrcPort)
			dstPort = uint16(tcp.DstPort)
		}
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, ok := udpLayer.(*layers.UDP)
		if ok && udp != nil {
			srcPort = uint16(udp.SrcPort)
			dstPort = uint16(udp.DstPort)
		}
	}

	// Record traffic
	packetLen := uint64(len(packet.Data()))

	key := FlowKey{
		SrcIP:    srcIP,
		SrcPort:  srcPort,
		DstIP:    dstIP,
		DstPort:  dstPort,
		Protocol: protocol,
	}

	c.mu.Lock()
	c.packetCount++
	if existing, ok := c.stats[key]; ok {
		existing.Packets++
		existing.Bytes += packetLen
	} else {
		c.stats[key] = &NetworkTraffic{
			SrcIP:    srcIP,
			SrcPort:  srcPort,
			DstIP:    dstIP,
			DstPort:  dstPort,
			Protocol: protocol,
			Packets:  1,
			Bytes:    packetLen,
		}
	}
	c.mu.Unlock()
}

// Stop stops the packet capture
func (c *GoPacketCollector) Stop() error {
	c.mu.Lock()
	if !c.running {
		c.mu.Unlock()
		return nil
	}
	c.running = false
	c.mu.Unlock()

	// Signal stop
	close(c.stopCh)

	// Wait for capture loop to finish (with timeout)
	select {
	case <-c.stoppedCh:
		c.flushStats()
	case <-time.After(5 * time.Second):
		return fmt.Errorf("timeout waiting for capture loop to stop")
	}

	return nil
}

// GetInterface returns the interface being monitored
func (c *GoPacketCollector) GetInterface() *net.Interface {
	return c.iface
}

// GetPacketCount returns the number of packets captured
func (c *GoPacketCollector) GetPacketCount() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.packetCount
}

// IsRunning returns whether the collector is running
func (c *GoPacketCollector) IsRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}
