package probe

import (
	"testing"
)

func TestNewGoPacketCollectorInvalidInterface(t *testing.T) {
	parent, err := NewNetworkTrafficCollector()
	if err != nil {
		t.Fatalf("NewNetworkTrafficCollector() error = %v", err)
	}

	_, err = NewGoPacketCollector(parent, "nonexistent_interface_xyz")
	if err == nil {
		t.Error("NewGoPacketCollector() should fail with invalid interface")
	}
}

func TestNewGoPacketCollectorValidInterface(t *testing.T) {
	parent, err := NewNetworkTrafficCollector()
	if err != nil {
		t.Fatalf("NewNetworkTrafficCollector() error = %v", err)
	}

	// Get a valid interface
	ifaces, err := GetAvailableInterfaces()
	if err != nil || len(ifaces) == 0 {
		t.Skip("No network interfaces available")
	}

	collector, err := NewGoPacketCollector(parent, ifaces[0])
	if err != nil {
		t.Fatalf("NewGoPacketCollector() error = %v", err)
	}

	iface := collector.GetInterface()
	if iface == nil {
		t.Fatal("GetInterface() should return non-nil")
	}
	if iface.Name != ifaces[0] {
		t.Errorf("GetInterface().Name = %s, want %s", iface.Name, ifaces[0])
	}
}

func TestNewGoPacketCollectorWithOptions(t *testing.T) {
	parent, err := NewNetworkTrafficCollector()
	if err != nil {
		t.Fatalf("NewNetworkTrafficCollector() error = %v", err)
	}

	// Get a valid interface
	ifaces, err := GetAvailableInterfaces()
	if err != nil || len(ifaces) == 0 {
		t.Skip("No network interfaces available")
	}

	collector, err := NewGoPacketCollector(
		parent,
		ifaces[0],
		WithFrameSize(8192),
		WithBlockSize(8192*64),
		WithNumBlocks(64),
	)
	if err != nil {
		t.Fatalf("NewGoPacketCollector() error = %v", err)
	}

	if collector.frameSize != 8192 {
		t.Errorf("frameSize = %d, want 8192", collector.frameSize)
	}
	if collector.blockSize != 8192*64 {
		t.Errorf("blockSize = %d, want %d", collector.blockSize, 8192*64)
	}
	if collector.numBlocks != 64 {
		t.Errorf("numBlocks = %d, want 64", collector.numBlocks)
	}
}

func TestGoPacketCollectorDefaultValues(t *testing.T) {
	parent, err := NewNetworkTrafficCollector()
	if err != nil {
		t.Fatalf("NewNetworkTrafficCollector() error = %v", err)
	}

	// Get a valid interface
	ifaces, err := GetAvailableInterfaces()
	if err != nil || len(ifaces) == 0 {
		t.Skip("No network interfaces available")
	}

	collector, err := NewGoPacketCollector(parent, ifaces[0])
	if err != nil {
		t.Fatalf("NewGoPacketCollector() error = %v", err)
	}

	// Check default values
	if collector.frameSize != 4096 {
		t.Errorf("default frameSize = %d, want 4096", collector.frameSize)
	}
	if collector.blockSize != 4096*128 {
		t.Errorf("default blockSize = %d, want %d", collector.blockSize, 4096*128)
	}
	if collector.numBlocks != 128 {
		t.Errorf("default numBlocks = %d, want 128", collector.numBlocks)
	}
}

func TestGoPacketCollectorIsRunningInitially(t *testing.T) {
	parent, err := NewNetworkTrafficCollector()
	if err != nil {
		t.Fatalf("NewNetworkTrafficCollector() error = %v", err)
	}

	// Get a valid interface
	ifaces, err := GetAvailableInterfaces()
	if err != nil || len(ifaces) == 0 {
		t.Skip("No network interfaces available")
	}

	collector, err := NewGoPacketCollector(parent, ifaces[0])
	if err != nil {
		t.Fatalf("NewGoPacketCollector() error = %v", err)
	}

	if collector.IsRunning() {
		t.Error("IsRunning() should be false initially")
	}
}

func TestGoPacketCollectorGetPacketCountInitially(t *testing.T) {
	parent, err := NewNetworkTrafficCollector()
	if err != nil {
		t.Fatalf("NewNetworkTrafficCollector() error = %v", err)
	}

	// Get a valid interface
	ifaces, err := GetAvailableInterfaces()
	if err != nil || len(ifaces) == 0 {
		t.Skip("No network interfaces available")
	}

	collector, err := NewGoPacketCollector(parent, ifaces[0])
	if err != nil {
		t.Fatalf("NewGoPacketCollector() error = %v", err)
	}

	if collector.GetPacketCount() != 0 {
		t.Errorf("GetPacketCount() = %d, want 0", collector.GetPacketCount())
	}
}

func TestGoPacketCollectorStartRequiresRoot(t *testing.T) {
	// Skip this test as it requires root and can cause issues with mmap'd memory
	// in test environments
	t.Skip("Skipping: requires root privileges and stable network interface")
}

func TestNetworkCollectorGoPacketType(t *testing.T) {
	c, err := NewNetworkTrafficCollector(
		WithCollectorType(CollectorTypeGoPacket),
	)
	if err != nil {
		t.Fatalf("NewNetworkTrafficCollector() error = %v", err)
	}

	if c.GetCollectorType() != CollectorTypeGoPacket {
		t.Errorf("GetCollectorType() = %s, want %s", c.GetCollectorType(), CollectorTypeGoPacket)
	}
}

func TestGoPacketCollectorStopWhenNotRunning(t *testing.T) {
	parent, err := NewNetworkTrafficCollector()
	if err != nil {
		t.Fatalf("NewNetworkTrafficCollector() error = %v", err)
	}

	// Get a valid interface
	ifaces, err := GetAvailableInterfaces()
	if err != nil || len(ifaces) == 0 {
		t.Skip("No network interfaces available")
	}

	collector, err := NewGoPacketCollector(parent, ifaces[0])
	if err != nil {
		t.Fatalf("NewGoPacketCollector() error = %v", err)
	}

	// Stop should be safe when not running
	err = collector.Stop()
	if err != nil {
		t.Errorf("Stop() error = %v", err)
	}
}

func TestGoPacketCollectorStartAlreadyRunning(t *testing.T) {
	// Skip this test as it requires root and can cause issues with mmap'd memory
	// in test environments
	t.Skip("Skipping: requires root privileges and stable network interface")
}
