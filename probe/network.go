package probe

import (
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// NetworkTrafficCollector collects network traffic statistics
// It automatically detects the best collection method based on kernel version
type NetworkTrafficCollector struct {
	mu            sync.RWMutex
	stats         map[FlowKey]*NetworkTraffic
	collectorType CollectorType
	interfaceName string
	running       bool
	stopCh        chan struct{}

	// Kernel version info
	kernelVersion KernelVersion

	// eBPF collector (only used when collectorType == CollectorTypeEBPF)
	ebpfCollector *EBPFCollector

	// gopacket collector (only used when collectorType == CollectorTypeGoPacket)
	gopacketCollector *GoPacketCollector

	// Poll interval for reading stats from BPF maps
	pollInterval time.Duration
}

// NetworkCollectorOption is a functional option for NetworkTrafficCollector
type NetworkCollectorOption func(*NetworkTrafficCollector)

// WithInterface sets the network interface to monitor
func WithInterface(name string) NetworkCollectorOption {
	return func(c *NetworkTrafficCollector) {
		c.interfaceName = name
	}
}

// WithCollectorType forces a specific collector type
func WithCollectorType(ct CollectorType) NetworkCollectorOption {
	return func(c *NetworkTrafficCollector) {
		c.collectorType = ct
	}
}

// WithPollInterval sets the interval for polling stats from BPF maps
func WithPollInterval(d time.Duration) NetworkCollectorOption {
	return func(c *NetworkTrafficCollector) {
		c.pollInterval = d
	}
}

// NewNetworkTrafficCollector creates a new network traffic collector
func NewNetworkTrafficCollector(opts ...NetworkCollectorOption) (*NetworkTrafficCollector, error) {
	c := &NetworkTrafficCollector{
		stats:        make(map[FlowKey]*NetworkTraffic),
		stopCh:       make(chan struct{}),
		pollInterval: 5 * time.Second, // default poll interval
	}

	// Get kernel version
	var err error
	c.kernelVersion, err = GetKernelVersion()
	if err != nil {
		// Default to gopacket if we can't determine kernel version
		c.kernelVersion = KernelVersion{Major: 3, Minor: 10, Patch: 0}
	}

	// Apply options
	for _, opt := range opts {
		opt(c)
	}

	// Auto-detect collector type if not specified
	if c.collectorType == "" {
		c.collectorType = DetectBestCollectorType()
	}

	// Auto-detect interface if not specified
	if c.interfaceName == "" {
		iface, err := getDefaultInterface()
		if err != nil {
			return nil, fmt.Errorf("failed to find network interface: %w", err)
		}
		c.interfaceName = iface.Name
	}

	return c, nil
}

// GetCollectorType returns the type of collector being used
func (c *NetworkTrafficCollector) GetCollectorType() CollectorType {
	return c.collectorType
}

// GetKernelVersion returns the detected kernel version
func (c *NetworkTrafficCollector) GetKernelVersion() KernelVersion {
	return c.kernelVersion
}

// GetInterfaceName returns the interface being monitored
func (c *NetworkTrafficCollector) GetInterfaceName() string {
	return c.interfaceName
}

// Start begins collecting network traffic
// Note: For eBPF, this requires root privileges and kernel >= 4.15
// For gopacket, this requires CAP_NET_RAW capability
func (c *NetworkTrafficCollector) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.running {
		return fmt.Errorf("collector already running")
	}

	c.stopCh = make(chan struct{})

	// Start the appropriate collector based on type
	switch c.collectorType {
	case CollectorTypeEBPF:
		return c.startEBPF()
	case CollectorTypeGoPacket:
		return c.startGoPacket()
	default:
		return fmt.Errorf("unknown collector type: %s", c.collectorType)
	}
}

// startEBPF starts the eBPF-based network traffic collection
func (c *NetworkTrafficCollector) startEBPF() error {
	// Create eBPF collector
	ebpf, err := NewEBPFCollector(c, c.interfaceName)
	if err != nil {
		return fmt.Errorf("failed to create eBPF collector: %w", err)
	}

	// Start the collector
	if err := ebpf.Start(c.pollInterval); err != nil {
		return fmt.Errorf("failed to start eBPF collector: %w", err)
	}

	c.ebpfCollector = ebpf
	c.running = true
	return nil
}

// startGoPacket starts the gopacket/AF_PACKET-based network traffic collection
func (c *NetworkTrafficCollector) startGoPacket() error {
	// Create gopacket collector
	gp, err := NewGoPacketCollector(c, c.interfaceName)
	if err != nil {
		return fmt.Errorf("failed to create gopacket collector: %w", err)
	}

	// Start the collector
	if err := gp.Start(); err != nil {
		return fmt.Errorf("failed to start gopacket collector: %w", err)
	}

	c.gopacketCollector = gp
	c.running = true
	return nil
}

// Stop stops the collection
func (c *NetworkTrafficCollector) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return nil
	}

	// Stop eBPF collector if running
	if c.ebpfCollector != nil {
		if err := c.ebpfCollector.Stop(); err != nil {
			return fmt.Errorf("failed to stop eBPF collector: %w", err)
		}
		c.ebpfCollector = nil
	}

	// Stop gopacket collector if running
	if c.gopacketCollector != nil {
		if err := c.gopacketCollector.Stop(); err != nil {
			return fmt.Errorf("failed to stop gopacket collector: %w", err)
		}
		c.gopacketCollector = nil
	}

	if c.stopCh != nil {
		close(c.stopCh)
	}
	c.running = false
	return nil
}

// IsRunning returns whether the collector is currently running
func (c *NetworkTrafficCollector) IsRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}

// GetStats returns current traffic statistics
func (c *NetworkTrafficCollector) GetStats() ([]NetworkTraffic, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make([]NetworkTraffic, 0, len(c.stats))
	for _, traffic := range c.stats {
		result = append(result, *traffic)
	}

	// Sort by bytes descending
	sort.Slice(result, func(i, j int) bool {
		return result[i].Bytes > result[j].Bytes
	})

	return result, nil
}

// ClearStats clears the statistics
func (c *NetworkTrafficCollector) ClearStats() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stats = make(map[FlowKey]*NetworkTraffic)
}

// RecordTraffic records a network traffic flow (used by collectors)
func (c *NetworkTrafficCollector) RecordTraffic(srcIP string, srcPort uint16, dstIP string, dstPort uint16, protocol string, packets, bytes uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := FlowKey{
		SrcIP:    srcIP,
		SrcPort:  srcPort,
		DstIP:    dstIP,
		DstPort:  dstPort,
		Protocol: protocol,
	}

	if existing, ok := c.stats[key]; ok {
		existing.Packets += packets
		existing.Bytes += bytes
		existing.Timestamp = time.Now()
	} else {
		c.stats[key] = &NetworkTraffic{
			SrcIP:     srcIP,
			SrcPort:   srcPort,
			DstIP:     dstIP,
			DstPort:   dstPort,
			Protocol:  protocol,
			Packets:   packets,
			Bytes:     bytes,
			Timestamp: time.Now(),
		}
	}
}

// FormatNetworkTrafficLineProtocol formats network traffic as InfluxDB line protocol
func FormatNetworkTrafficLineProtocol(t NetworkTraffic) string {
	return fmt.Sprintf(
		"network_traffic,src_ip=%s,src_port=%d,dst_ip=%s,dst_port=%d,protocol=%s packets=%di,bytes=%di %d",
		t.SrcIP,
		t.SrcPort,
		t.DstIP,
		t.DstPort,
		t.Protocol,
		t.Packets,
		t.Bytes,
		t.Timestamp.UnixNano(),
	)
}

// getDefaultInterface finds the first non-loopback, up interface
func getDefaultInterface() (*net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range ifaces {
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		return &iface, nil
	}

	return nil, fmt.Errorf("no suitable network interface found")
}

// GetAvailableInterfaces returns a list of available network interfaces
func GetAvailableInterfaces() ([]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var names []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp != 0 {
			names = append(names, iface.Name)
		}
	}
	return names, nil
}

// ProtocolNumberToName converts IP protocol number to name
func ProtocolNumberToName(proto uint8) string {
	switch proto {
	case 1:
		return "ICMP"
	case 2:
		return "IGMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 47:
		return "GRE"
	case 50:
		return "ESP"
	case 51:
		return "AH"
	case 89:
		return "OSPF"
	case 112:
		return "VRRP"
	case 132:
		return "SCTP"
	default:
		return fmt.Sprintf("%d", proto)
	}
}

// ProtocolNameToNumber converts protocol name to IP protocol number
func ProtocolNameToNumber(name string) uint8 {
	switch strings.ToUpper(name) {
	case "ICMP":
		return 1
	case "IGMP":
		return 2
	case "TCP":
		return 6
	case "UDP":
		return 17
	case "GRE":
		return 47
	case "ESP":
		return 50
	case "AH":
		return 51
	case "OSPF":
		return 89
	case "VRRP":
		return 112
	case "SCTP":
		return 132
	default:
		return 0
	}
}

// IPToUint32 converts an IP to uint32 (little-endian, for eBPF compatibility)
func IPToUint32(ip net.IP) uint32 {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	return binary.LittleEndian.Uint32(ip4)
}

// Uint32ToIP converts uint32 to IP (little-endian, for eBPF compatibility)
func Uint32ToIP(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, n)
	return ip
}

// ParseIPPort parses an IP:port string
func ParseIPPort(s string) (string, uint16, error) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, err
	}

	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		return "", 0, err
	}

	return host, uint16(port), nil
}

// NetworkStatsInfo provides information about network statistics collection
type NetworkStatsInfo struct {
	CollectorType   CollectorType
	KernelVersion   string
	SupportsEBPF    bool
	SupportsBPFLink bool
	InterfaceName   string
	IsRunning       bool
	FlowCount       int
}

// GetInfo returns information about the network collector
func (c *NetworkTrafficCollector) GetInfo() NetworkStatsInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return NetworkStatsInfo{
		CollectorType:   c.collectorType,
		KernelVersion:   c.kernelVersion.String(),
		SupportsEBPF:    c.kernelVersion.SupportsEBPF(),
		SupportsBPFLink: c.kernelVersion.SupportsBPFLink(),
		InterfaceName:   c.interfaceName,
		IsRunning:       c.running,
		FlowCount:       len(c.stats),
	}
}

// PrintInfo prints collector information
func (c *NetworkTrafficCollector) PrintInfo() string {
	info := c.GetInfo()
	return fmt.Sprintf(`Network Traffic Collector Info:
  Collector Type: %s (%s)
  Kernel Version: %s
  eBPF Support:   %v
  BPF Link:       %v
  Interface:      %s
  Running:        %v
  Flow Count:     %d`,
		info.CollectorType,
		GetCollectorTypeString(info.CollectorType),
		info.KernelVersion,
		info.SupportsEBPF,
		info.SupportsBPFLink,
		info.InterfaceName,
		info.IsRunning,
		info.FlowCount,
	)
}
