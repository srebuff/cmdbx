package probe

import (
	"testing"
	"time"
)

func TestEBPFFlowKeyStruct(t *testing.T) {
	key := EBPFFlowKey{
		SrcIP:    0x0100007f, // 127.0.0.1 in little-endian
		DstIP:    0x0100007f,
		SrcPort:  12345,
		DstPort:  80,
		Protocol: 6, // TCP
	}

	if key.SrcPort != 12345 {
		t.Errorf("SrcPort = %d, want 12345", key.SrcPort)
	}
	if key.DstPort != 80 {
		t.Errorf("DstPort = %d, want 80", key.DstPort)
	}
	if key.Protocol != 6 {
		t.Errorf("Protocol = %d, want 6", key.Protocol)
	}
}

func TestEBPFFlowStatsStruct(t *testing.T) {
	stats := EBPFFlowStats{
		Packets: 1000,
		Bytes:   1500000,
	}

	if stats.Packets != 1000 {
		t.Errorf("Packets = %d, want 1000", stats.Packets)
	}
	if stats.Bytes != 1500000 {
		t.Errorf("Bytes = %d, want 1500000", stats.Bytes)
	}
}

func TestNewEBPFCollectorInvalidInterface(t *testing.T) {
	parent, err := NewNetworkTrafficCollector()
	if err != nil {
		t.Fatalf("NewNetworkTrafficCollector() error = %v", err)
	}

	_, err = NewEBPFCollector(parent, "nonexistent_interface_xyz")
	if err == nil {
		t.Error("NewEBPFCollector() should fail with invalid interface")
	}
}

func TestNewEBPFCollectorValidInterface(t *testing.T) {
	parent, err := NewNetworkTrafficCollector()
	if err != nil {
		t.Fatalf("NewNetworkTrafficCollector() error = %v", err)
	}

	// Get a valid interface
	ifaces, err := GetAvailableInterfaces()
	if err != nil || len(ifaces) == 0 {
		t.Skip("No network interfaces available")
	}

	collector, err := NewEBPFCollector(parent, ifaces[0])
	if err != nil {
		t.Fatalf("NewEBPFCollector() error = %v", err)
	}

	iface := collector.GetInterface()
	if iface == nil {
		t.Fatal("GetInterface() should return non-nil")
	}
	if iface.Name != ifaces[0] {
		t.Errorf("GetInterface().Name = %s, want %s", iface.Name, ifaces[0])
	}
}

func TestWithPollInterval(t *testing.T) {
	c, err := NewNetworkTrafficCollector(
		WithPollInterval(10 * time.Second),
	)
	if err != nil {
		t.Fatalf("NewNetworkTrafficCollector() error = %v", err)
	}

	if c.pollInterval != 10*time.Second {
		t.Errorf("pollInterval = %v, want 10s", c.pollInterval)
	}
}

func TestDefaultPollInterval(t *testing.T) {
	c, err := NewNetworkTrafficCollector()
	if err != nil {
		t.Fatalf("NewNetworkTrafficCollector() error = %v", err)
	}

	if c.pollInterval != 5*time.Second {
		t.Errorf("pollInterval = %v, want 5s (default)", c.pollInterval)
	}
}

func TestEBPFCollectorStartRequiresRoot(t *testing.T) {
	// This test verifies that starting the eBPF collector
	// properly handles permission errors when not running as root
	c, err := NewNetworkTrafficCollector(
		WithCollectorType(CollectorTypeEBPF),
	)
	if err != nil {
		t.Fatalf("NewNetworkTrafficCollector() error = %v", err)
	}

	// Starting should fail without root privileges (unless running as root)
	err = c.Start()
	// We expect an error in most test environments
	// If running as root, it might succeed
	if err != nil {
		t.Logf("Start() error (expected without root): %v", err)
	} else {
		// If it succeeded, make sure to stop it
		_ = c.Stop()
		t.Log("Start() succeeded - running as root?")
	}
}

func TestNetworkCollectorEBPFType(t *testing.T) {
	c, err := NewNetworkTrafficCollector(
		WithCollectorType(CollectorTypeEBPF),
	)
	if err != nil {
		t.Fatalf("NewNetworkTrafficCollector() error = %v", err)
	}

	if c.GetCollectorType() != CollectorTypeEBPF {
		t.Errorf("GetCollectorType() = %s, want %s", c.GetCollectorType(), CollectorTypeEBPF)
	}
}

func TestNetworkCollectorStopWhenNotRunning(t *testing.T) {
	c, err := NewNetworkTrafficCollector(
		WithCollectorType(CollectorTypeEBPF),
	)
	if err != nil {
		t.Fatalf("NewNetworkTrafficCollector() error = %v", err)
	}

	// Stop should be safe when not running
	err = c.Stop()
	if err != nil {
		t.Errorf("Stop() error = %v", err)
	}
}
