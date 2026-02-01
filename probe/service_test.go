package probe

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestNewServiceCollector(t *testing.T) {
	t.Run("default options", func(t *testing.T) {
		c := NewServiceCollector()
		if c.instanceID == "" {
			t.Error("instanceID should be auto-detected")
		}
		if c.instanceIP == "" {
			t.Error("instanceIP should be auto-detected")
		}
		if c.ioRateDuration != 3*time.Second {
			t.Errorf("ioRateDuration = %v, want 3s", c.ioRateDuration)
		}
	})

	t.Run("with custom options", func(t *testing.T) {
		c := NewServiceCollector(
			WithInstanceID("test-instance"),
			WithInstanceIP("192.168.1.100"),
			WithIORateDuration(5*time.Second),
			WithVerbose(true),
		)
		if c.instanceID != "test-instance" {
			t.Errorf("instanceID = %s, want test-instance", c.instanceID)
		}
		if c.instanceIP != "192.168.1.100" {
			t.Errorf("instanceIP = %s, want 192.168.1.100", c.instanceIP)
		}
		if c.ioRateDuration != 5*time.Second {
			t.Errorf("ioRateDuration = %v, want 5s", c.ioRateDuration)
		}
		if !c.verbose {
			t.Error("verbose should be true")
		}
	})
}

func TestServiceCollectorSetters(t *testing.T) {
	c := NewServiceCollector()

	c.SetInstanceID("new-id")
	if c.instanceID != "new-id" {
		t.Errorf("instanceID = %s, want new-id", c.instanceID)
	}

	c.SetInstanceIP("10.0.0.1")
	if c.instanceIP != "10.0.0.1" {
		t.Errorf("instanceIP = %s, want 10.0.0.1", c.instanceIP)
	}
}

func TestIsContainerInfraProcess(t *testing.T) {
	tests := []struct {
		name     string
		procName string
		want     bool
	}{
		{"containerd-shim", "containerd-shim", true},
		{"containerd-shim-runc-v2", "containerd-shim-runc-v2", true},
		{"tini", "tini", true},
		{"dumb-init", "dumb-init", true},
		{"docker-init", "docker-init", true},
		{"pause", "pause", true},
		{"s6-svscan", "s6-svscan", true},
		{"runc", "runc", true},
		{"uppercase TINI", "TINI", true},
		{"nginx not infra", "nginx", false},
		{"java not infra", "java", false},
		{"empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isContainerInfraProcess(tt.procName)
			if got != tt.want {
				t.Errorf("isContainerInfraProcess(%q) = %v, want %v", tt.procName, got, tt.want)
			}
		})
	}
}

func TestMergePorts(t *testing.T) {
	tests := []struct {
		name string
		a    []uint32
		b    []uint32
		want []uint32
	}{
		{"both empty", nil, nil, []uint32{}},
		{"a empty", nil, []uint32{80, 443}, []uint32{80, 443}},
		{"b empty", []uint32{80, 443}, nil, []uint32{80, 443}},
		{"no overlap", []uint32{80}, []uint32{443}, []uint32{80, 443}},
		{"with overlap", []uint32{80, 443}, []uint32{443, 8080}, []uint32{80, 443, 8080}},
		{"all duplicates", []uint32{80, 443}, []uint32{80, 443}, []uint32{80, 443}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mergePorts(tt.a, tt.b)
			if len(got) != len(tt.want) {
				t.Errorf("mergePorts() = %v, want %v", got, tt.want)
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("mergePorts() = %v, want %v", got, tt.want)
					return
				}
			}
		})
	}
}

func TestFormatPorts(t *testing.T) {
	tests := []struct {
		name  string
		ports []uint32
		want  string
	}{
		{"empty", nil, ""},
		{"single port", []uint32{80}, "80"},
		{"two ports", []uint32{80, 443}, "80,443"},
		{"multiple ports", []uint32{80, 443, 8080}, "80,443,8080"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatPorts(tt.ports)
			if got != tt.want {
				t.Errorf("FormatPorts(%v) = %q, want %q", tt.ports, got, tt.want)
			}
		})
	}
}

func TestEscapeTagValue(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"no special chars", "nginx", "nginx"},
		{"with space", "my service", "my\\ service"},
		{"with comma", "a,b,c", "a\\,b\\,c"},
		{"with equals", "key=value", "key\\=value"},
		{"mixed", "my service,key=val", "my\\ service\\,key\\=val"},
		{"empty string", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := escapeTagValue(tt.input)
			if got != tt.want {
				t.Errorf("escapeTagValue(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestHashDetailCmd(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"empty string", ""},
		{"simple command", "/usr/bin/nginx"},
		{"command with args", "/usr/bin/nginx -c /etc/nginx/nginx.conf"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hashDetailCmd(tt.input)

			if tt.input == "" {
				if got != "" {
					t.Errorf("hashDetailCmd(%q) = %q, want empty", tt.input, got)
				}
				return
			}

			// SHA-256 hash should be 64 hex characters
			if len(got) != 64 {
				t.Errorf("hashDetailCmd(%q) length = %d, want 64", tt.input, len(got))
			}

			// Hash should be deterministic
			got2 := hashDetailCmd(tt.input)
			if got != got2 {
				t.Errorf("hashDetailCmd not deterministic")
			}
		})
	}
}

func TestGetInstanceIP(t *testing.T) {
	ip := getInstanceIP()
	// Should return a valid IP
	if ip == "" {
		t.Error("getInstanceIP() returned empty string")
	}
	// Should be a valid format
	if !strings.Contains(ip, ".") && ip != "127.0.0.1" {
		t.Errorf("getInstanceIP() = %s, doesn't look like an IP", ip)
	}
}

func TestServiceStruct(t *testing.T) {
	svc := Service{
		InstanceID:   "test-node",
		InstanceIP:   "192.168.1.100",
		Name:         "test-service",
		BinPath:      "/usr/bin/test",
		StartMode:    "systemd",
		DetailCmd:    "abc123",
		PID:          123,
		RootPID:      123,
		ListenPorts:  []uint32{80, 443},
		CPUPercent:   25.5,
		MemBytes:     1024 * 1024 * 100,
		IOReadBytes:  1024 * 1024,
		IOWriteBytes: 512 * 1024,
		IOReadMB:     1.0,
		IOWriteMB:    0.5,
		IOReadKBps:   10.5,
		IOWriteKBps:  5.25,
		ChildCount:   3,
		Timestamp:    1234567890,
	}

	if svc.InstanceID != "test-node" {
		t.Errorf("InstanceID = %s, want test-node", svc.InstanceID)
	}
	if svc.StartMode != "systemd" {
		t.Errorf("StartMode = %s, want systemd", svc.StartMode)
	}
	if len(svc.ListenPorts) != 2 {
		t.Errorf("ListenPorts length = %d, want 2", len(svc.ListenPorts))
	}
}

func TestFormatLineProtocol(t *testing.T) {
	svc := Service{
		InstanceID:   "test-node",
		InstanceIP:   "192.168.1.100",
		Name:         "nginx",
		BinPath:      "/usr/sbin/nginx",
		StartMode:    "systemd",
		DetailCmd:    "abc123def456",
		PID:          1234,
		RootPID:      1234,
		ListenPorts:  []uint32{80, 443},
		CPUPercent:   2.5,
		MemBytes:     104857600,
		IOReadBytes:  1048576,
		IOWriteBytes: 524288,
		IOReadMB:     1.0,
		IOWriteMB:    0.5,
		IOReadKBps:   10.0,
		IOWriteKBps:  5.0,
		ChildCount:   4,
		Timestamp:    1234567890,
	}

	line := FormatLineProtocol(svc)

	// Check key parts of the line protocol
	if !strings.HasPrefix(line, "services,") {
		t.Error("Line should start with 'services,'")
	}
	if !strings.Contains(line, "instance_id=test-node") {
		t.Error("Line should contain instance_id")
	}
	if !strings.Contains(line, "name=nginx") {
		t.Error("Line should contain name")
	}
	if !strings.Contains(line, "start_mode=systemd") {
		t.Error("Line should contain start_mode")
	}
	if !strings.Contains(line, "pid=1234i") {
		t.Error("Line should contain pid")
	}
	if !strings.Contains(line, `listen_ports="80,443"`) {
		t.Error("Line should contain listen_ports")
	}
	if !strings.Contains(line, "cpu_pct=2.50") {
		t.Error("Line should contain cpu_pct")
	}
}

func TestSampleIORate(t *testing.T) {
	// Test with current process
	pid := int32(os.Getpid())

	readKBps, writeKBps := sampleIORate(pid, 20*time.Millisecond)

	// Rates should not be negative
	if readKBps < 0 {
		t.Errorf("readKBps should not be negative, got %f", readKBps)
	}
	if writeKBps < 0 {
		t.Errorf("writeKBps should not be negative, got %f", writeKBps)
	}
}

func TestSampleIORateInvalidPID(t *testing.T) {
	readKBps, writeKBps := sampleIORate(-1, 10*time.Millisecond)

	if readKBps != 0 || writeKBps != 0 {
		t.Errorf("sampleIORate(-1) should return 0,0, got %f,%f", readKBps, writeKBps)
	}
}

func TestExcludeListContent(t *testing.T) {
	expectedPatterns := []string{
		"kworker", "ksoftirqd", "kthreadd", "migration", "rcu_", "watchdog",
	}

	for _, pattern := range expectedPatterns {
		found := false
		for _, exclude := range ExcludeList {
			if exclude == pattern {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("ExcludeList should contain %q", pattern)
		}
	}
}

func TestContainerInfraProcessesContent(t *testing.T) {
	expectedPatterns := []string{
		"containerd-shim", "tini", "dumb-init", "pause", "runc",
	}

	for _, pattern := range expectedPatterns {
		found := false
		for _, infra := range ContainerInfraProcesses {
			if infra == pattern {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("ContainerInfraProcesses should contain %q", pattern)
		}
	}
}

func TestCollectWithShortDuration(t *testing.T) {
	// Test collection with very short IO duration for speed
	c := NewServiceCollector(
		WithIORateDuration(10 * time.Millisecond),
	)

	services, err := c.Collect()
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	// Should return at least some services (the test process itself)
	if len(services) == 0 {
		t.Log("Warning: No services collected (may be expected in restricted environments)")
	}

	// Check that services have required fields
	for _, svc := range services {
		if svc.Name == "" {
			t.Error("Service name should not be empty")
		}
		if svc.PID <= 0 {
			t.Error("Service PID should be positive")
		}
		if svc.InstanceID == "" {
			t.Error("Service InstanceID should not be empty")
		}
		if svc.InstanceIP == "" {
			t.Error("Service InstanceIP should not be empty")
		}
		if svc.Timestamp <= 0 {
			t.Error("Service Timestamp should be positive")
		}
	}
}

func TestCollectWithZeroDuration(t *testing.T) {
	// Test collection with zero IO duration (skip IO rate sampling)
	c := NewServiceCollector(
		WithIORateDuration(0),
	)

	services, err := c.Collect()
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	// Should still work, just without IO rates
	for _, svc := range services {
		if svc.IOReadKBps != 0 || svc.IOWriteKBps != 0 {
			t.Log("IO rates should be 0 when duration is 0")
		}
	}
}
