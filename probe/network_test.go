package probe

import (
	"net"
	"strings"
	"testing"
	"time"
)

func TestNewNetworkTrafficCollector(t *testing.T) {
	t.Run("default options", func(t *testing.T) {
		c, err := NewNetworkTrafficCollector()
		if err != nil {
			t.Fatalf("NewNetworkTrafficCollector() error = %v", err)
		}

		if c.collectorType == "" {
			t.Error("collectorType should be auto-detected")
		}
		if c.interfaceName == "" {
			t.Error("interfaceName should be auto-detected")
		}
	})

	t.Run("with interface option", func(t *testing.T) {
		// Get an existing interface
		ifaces, _ := GetAvailableInterfaces()
		if len(ifaces) == 0 {
			t.Skip("No network interfaces available")
		}

		c, err := NewNetworkTrafficCollector(
			WithInterface(ifaces[0]),
		)
		if err != nil {
			t.Fatalf("NewNetworkTrafficCollector() error = %v", err)
		}

		if c.interfaceName != ifaces[0] {
			t.Errorf("interfaceName = %s, want %s", c.interfaceName, ifaces[0])
		}
	})

	t.Run("with collector type option", func(t *testing.T) {
		c, err := NewNetworkTrafficCollector(
			WithCollectorType(CollectorTypeGoPacket),
		)
		if err != nil {
			t.Fatalf("NewNetworkTrafficCollector() error = %v", err)
		}

		if c.collectorType != CollectorTypeGoPacket {
			t.Errorf("collectorType = %s, want %s", c.collectorType, CollectorTypeGoPacket)
		}
	})
}

func TestNetworkTrafficCollectorGetters(t *testing.T) {
	c, err := NewNetworkTrafficCollector(
		WithCollectorType(CollectorTypeGoPacket),
	)
	if err != nil {
		t.Fatalf("NewNetworkTrafficCollector() error = %v", err)
	}

	if c.GetCollectorType() != CollectorTypeGoPacket {
		t.Errorf("GetCollectorType() = %s, want %s", c.GetCollectorType(), CollectorTypeGoPacket)
	}

	kv := c.GetKernelVersion()
	if kv.Major == 0 && kv.Minor == 0 && kv.Patch == 0 {
		t.Error("GetKernelVersion() returned zero version")
	}

	if c.GetInterfaceName() == "" {
		t.Error("GetInterfaceName() returned empty string")
	}
}

func TestNetworkTrafficCollectorRecordTraffic(t *testing.T) {
	c, err := NewNetworkTrafficCollector()
	if err != nil {
		t.Fatalf("NewNetworkTrafficCollector() error = %v", err)
	}

	// Record some traffic
	c.RecordTraffic("192.168.1.1", 12345, "10.0.0.1", 80, "TCP", 10, 1500)
	c.RecordTraffic("192.168.1.1", 12345, "10.0.0.1", 80, "TCP", 5, 750)
	c.RecordTraffic("192.168.1.2", 54321, "10.0.0.1", 443, "TCP", 3, 500)

	stats, err := c.GetStats()
	if err != nil {
		t.Fatalf("GetStats() error = %v", err)
	}

	if len(stats) != 2 {
		t.Errorf("len(stats) = %d, want 2", len(stats))
	}

	// Find the aggregated flow
	var found bool
	for _, s := range stats {
		if s.SrcIP == "192.168.1.1" && s.DstPort == 80 {
			found = true
			if s.Packets != 15 {
				t.Errorf("Packets = %d, want 15 (10+5)", s.Packets)
			}
			if s.Bytes != 2250 {
				t.Errorf("Bytes = %d, want 2250 (1500+750)", s.Bytes)
			}
		}
	}
	if !found {
		t.Error("Expected flow not found in stats")
	}
}

func TestNetworkTrafficCollectorClearStats(t *testing.T) {
	c, err := NewNetworkTrafficCollector()
	if err != nil {
		t.Fatalf("NewNetworkTrafficCollector() error = %v", err)
	}

	// Record some traffic
	c.RecordTraffic("192.168.1.1", 12345, "10.0.0.1", 80, "TCP", 10, 1500)

	stats, _ := c.GetStats()
	if len(stats) == 0 {
		t.Fatal("Stats should not be empty after recording")
	}

	// Clear
	c.ClearStats()

	stats, _ = c.GetStats()
	if len(stats) != 0 {
		t.Errorf("len(stats) = %d after clear, want 0", len(stats))
	}
}

func TestNetworkTrafficCollectorIsRunning(t *testing.T) {
	c, err := NewNetworkTrafficCollector()
	if err != nil {
		t.Fatalf("NewNetworkTrafficCollector() error = %v", err)
	}

	if c.IsRunning() {
		t.Error("IsRunning() should be false initially")
	}

	// Stop should be safe when not running
	err = c.Stop()
	if err != nil {
		t.Errorf("Stop() error = %v", err)
	}
}

func TestNetworkTrafficCollectorStopDoesNotDeadlockOnGoPacket(t *testing.T) {
	parent, err := NewNetworkTrafficCollector(
		WithCollectorType(CollectorTypeGoPacket),
	)
	if err != nil {
		t.Fatalf("NewNetworkTrafficCollector() error = %v", err)
	}

	gp := &GoPacketCollector{
		parent:    parent,
		stopCh:    make(chan struct{}),
		stoppedCh: make(chan struct{}),
		running:   true,
		stats:     make(map[FlowKey]*NetworkTraffic),
	}
	close(gp.stoppedCh)

	parent.gopacketCollector = gp
	parent.running = true

	done := make(chan struct{})
	go func() {
		_ = parent.Stop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Stop() appears to be deadlocked")
	}
}

func TestNetworkTrafficStruct(t *testing.T) {
	traffic := NetworkTraffic{
		SrcIP:     "192.168.1.100",
		SrcPort:   54321,
		DstIP:     "10.0.0.1",
		DstPort:   443,
		Protocol:  "TCP",
		Packets:   100,
		Bytes:     15000,
		Timestamp: time.Now(),
	}

	if traffic.SrcIP != "192.168.1.100" {
		t.Errorf("SrcIP = %s, want 192.168.1.100", traffic.SrcIP)
	}
	if traffic.Protocol != "TCP" {
		t.Errorf("Protocol = %s, want TCP", traffic.Protocol)
	}
	if traffic.Packets != 100 {
		t.Errorf("Packets = %d, want 100", traffic.Packets)
	}
}

func TestFormatNetworkTrafficLineProtocol(t *testing.T) {
	traffic := NetworkTraffic{
		SrcIP:     "192.168.1.100",
		SrcPort:   54321,
		DstIP:     "10.0.0.1",
		DstPort:   443,
		Protocol:  "TCP",
		Packets:   100,
		Bytes:     15000,
		Timestamp: time.Unix(0, 1234567890),
	}

	line := FormatNetworkTrafficLineProtocol(traffic)

	if !strings.HasPrefix(line, "network_traffic,") {
		t.Error("Line should start with 'network_traffic,'")
	}
	if !strings.Contains(line, "src_ip=192.168.1.100") {
		t.Error("Line should contain src_ip")
	}
	if !strings.Contains(line, "src_port=54321") {
		t.Error("Line should contain src_port")
	}
	if !strings.Contains(line, "dst_ip=10.0.0.1") {
		t.Error("Line should contain dst_ip")
	}
	if !strings.Contains(line, "dst_port=443") {
		t.Error("Line should contain dst_port")
	}
	if !strings.Contains(line, "protocol=TCP") {
		t.Error("Line should contain protocol")
	}
	if !strings.Contains(line, "packets=100i") {
		t.Error("Line should contain packets")
	}
	if !strings.Contains(line, "bytes=15000i") {
		t.Error("Line should contain bytes")
	}
}

func TestProtocolNumberToName(t *testing.T) {
	tests := []struct {
		proto uint8
		want  string
	}{
		{1, "ICMP"},
		{2, "IGMP"},
		{6, "TCP"},
		{17, "UDP"},
		{47, "GRE"},
		{50, "ESP"},
		{51, "AH"},
		{89, "OSPF"},
		{112, "VRRP"},
		{132, "SCTP"},
		{99, "99"}, // Unknown protocol
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := ProtocolNumberToName(tt.proto)
			if got != tt.want {
				t.Errorf("ProtocolNumberToName(%d) = %s, want %s", tt.proto, got, tt.want)
			}
		})
	}
}

func TestProtocolNameToNumber(t *testing.T) {
	tests := []struct {
		name string
		want uint8
	}{
		{"ICMP", 1},
		{"icmp", 1},
		{"TCP", 6},
		{"tcp", 6},
		{"UDP", 17},
		{"udp", 17},
		{"SCTP", 132},
		{"unknown", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ProtocolNameToNumber(tt.name)
			if got != tt.want {
				t.Errorf("ProtocolNameToNumber(%s) = %d, want %d", tt.name, got, tt.want)
			}
		})
	}
}

func TestIPToUint32AndBack(t *testing.T) {
	tests := []string{
		"192.168.1.1",
		"10.0.0.1",
		"127.0.0.1",
		"255.255.255.255",
		"0.0.0.0",
	}

	for _, ipStr := range tests {
		t.Run(ipStr, func(t *testing.T) {
			ip := net.ParseIP(ipStr)
			n := IPToUint32(ip)
			back := Uint32ToIP(n)

			if back.String() != ipStr {
				t.Errorf("IPToUint32 -> Uint32ToIP: %s -> %d -> %s", ipStr, n, back.String())
			}
		})
	}
}

func TestIPToUint32Nil(t *testing.T) {
	result := IPToUint32(nil)
	if result != 0 {
		t.Errorf("IPToUint32(nil) = %d, want 0", result)
	}
}

func TestParseIPPort(t *testing.T) {
	tests := []struct {
		input    string
		wantIP   string
		wantPort uint16
		wantErr  bool
	}{
		{"192.168.1.1:80", "192.168.1.1", 80, false},
		{"10.0.0.1:443", "10.0.0.1", 443, false},
		{"127.0.0.1:8080", "127.0.0.1", 8080, false},
		{"invalid", "", 0, true},
		{"192.168.1.1", "", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			ip, port, err := ParseIPPort(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseIPPort(%s) expected error", tt.input)
				}
				return
			}
			if err != nil {
				t.Errorf("ParseIPPort(%s) error = %v", tt.input, err)
				return
			}
			if ip != tt.wantIP {
				t.Errorf("IP = %s, want %s", ip, tt.wantIP)
			}
			if port != tt.wantPort {
				t.Errorf("Port = %d, want %d", port, tt.wantPort)
			}
		})
	}
}

func TestGetAvailableInterfaces(t *testing.T) {
	ifaces, err := GetAvailableInterfaces()
	if err != nil {
		t.Fatalf("GetAvailableInterfaces() error = %v", err)
	}

	// Should have at least loopback (lo)
	if len(ifaces) == 0 {
		t.Log("Warning: No network interfaces found")
	}
}

func TestFlowKey(t *testing.T) {
	key1 := FlowKey{
		SrcIP:    "192.168.1.1",
		SrcPort:  12345,
		DstIP:    "10.0.0.1",
		DstPort:  80,
		Protocol: "TCP",
	}

	key2 := FlowKey{
		SrcIP:    "192.168.1.1",
		SrcPort:  12345,
		DstIP:    "10.0.0.1",
		DstPort:  80,
		Protocol: "TCP",
	}

	key3 := FlowKey{
		SrcIP:    "192.168.1.2", // Different src IP
		SrcPort:  12345,
		DstIP:    "10.0.0.1",
		DstPort:  80,
		Protocol: "TCP",
	}

	if key1 != key2 {
		t.Error("Identical FlowKeys should be equal")
	}
	if key1 == key3 {
		t.Error("Different FlowKeys should not be equal")
	}
}

func TestNetworkStatsInfo(t *testing.T) {
	c, err := NewNetworkTrafficCollector(
		WithCollectorType(CollectorTypeGoPacket),
	)
	if err != nil {
		t.Fatalf("NewNetworkTrafficCollector() error = %v", err)
	}

	// Record some traffic
	c.RecordTraffic("192.168.1.1", 12345, "10.0.0.1", 80, "TCP", 10, 1500)

	info := c.GetInfo()

	if info.CollectorType != CollectorTypeGoPacket {
		t.Errorf("CollectorType = %s, want %s", info.CollectorType, CollectorTypeGoPacket)
	}
	if info.KernelVersion == "" {
		t.Error("KernelVersion should not be empty")
	}
	if info.InterfaceName == "" {
		t.Error("InterfaceName should not be empty")
	}
	if info.FlowCount != 1 {
		t.Errorf("FlowCount = %d, want 1", info.FlowCount)
	}
}

func TestNetworkCollectorPrintInfo(t *testing.T) {
	c, err := NewNetworkTrafficCollector()
	if err != nil {
		t.Fatalf("NewNetworkTrafficCollector() error = %v", err)
	}

	output := c.PrintInfo()

	if !strings.Contains(output, "Network Traffic Collector Info") {
		t.Error("PrintInfo should contain header")
	}
	if !strings.Contains(output, "Collector Type") {
		t.Error("PrintInfo should contain Collector Type")
	}
	if !strings.Contains(output, "Kernel Version") {
		t.Error("PrintInfo should contain Kernel Version")
	}
	if !strings.Contains(output, "Interface") {
		t.Error("PrintInfo should contain Interface")
	}
}

func TestCollectorTypeConstants(t *testing.T) {
	if CollectorTypeEBPF != "ebpf" {
		t.Errorf("CollectorTypeEBPF = %s, want ebpf", CollectorTypeEBPF)
	}
	if CollectorTypeGoPacket != "gopacket" {
		t.Errorf("CollectorTypeGoPacket = %s, want gopacket", CollectorTypeGoPacket)
	}
	if CollectorTypeNone != "none" {
		t.Errorf("CollectorTypeNone = %s, want none", CollectorTypeNone)
	}
}
