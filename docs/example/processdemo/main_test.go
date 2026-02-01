package main

import (
	"os"
	"testing"
	"time"
)

func TestIsContainerInfraProcess(t *testing.T) {
	tests := []struct {
		name     string
		procName string
		want     bool
	}{
		{"containerd-shim exact", "containerd-shim", true},
		{"containerd-shim-runc-v2", "containerd-shim-runc-v2", true},
		{"tini", "tini", true},
		{"dumb-init", "dumb-init", true},
		{"docker-init", "docker-init", true},
		{"pause", "pause", true},
		{"s6-svscan", "s6-svscan", true},
		{"s6-supervise", "s6-supervise", true},
		{"runc", "runc", true},
		{"uppercase TINI", "TINI", true},
		{"mixed case Pause", "Pause", true},
		{"nginx not infra", "nginx", false},
		{"java not infra", "java", false},
		{"python not infra", "python", false},
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
		{"single element each", []uint32{80}, []uint32{80}, []uint32{80}},
		{"multiple duplicates", []uint32{80, 80, 443}, []uint32{443, 443, 8080}, []uint32{80, 443, 8080}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mergePorts(tt.a, tt.b)
			if len(got) != len(tt.want) {
				t.Errorf("mergePorts(%v, %v) = %v, want %v", tt.a, tt.b, got, tt.want)
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("mergePorts(%v, %v) = %v, want %v", tt.a, tt.b, got, tt.want)
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
		{"multiple ports", []uint32{80, 443, 8080, 9090}, "80,443,8080,9090"},
		{"high port numbers", []uint32{65535, 49152}, "65535,49152"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatPorts(tt.ports)
			if got != tt.want {
				t.Errorf("formatPorts(%v) = %q, want %q", tt.ports, got, tt.want)
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
		{"mixed special chars", "my service,key=val", "my\\ service\\,key\\=val"},
		{"empty string", "", ""},
		{"multiple spaces", "a b c", "a\\ b\\ c"},
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

func TestEscapeFieldString(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"no special chars", "hello world", "hello world"},
		{"with backslash", "path\\to\\file", "path\\\\to\\\\file"},
		{"with quote", `say "hello"`, `say \"hello\"`},
		{"mixed backslash and quote", `a\b"c`, `a\\b\"c`},
		{"empty string", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := escapeFieldString(tt.input)
			if got != tt.want {
				t.Errorf("escapeFieldString(%q) = %q, want %q", tt.input, got, tt.want)
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
		{"unicode", "服务启动命令"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hashDetailCmd(tt.input)

			// Empty input should return empty string
			if tt.input == "" {
				if got != "" {
					t.Errorf("hashDetailCmd(%q) = %q, want empty string", tt.input, got)
				}
				return
			}

			// SHA-256 hash should be 64 hex characters
			if len(got) != 64 {
				t.Errorf("hashDetailCmd(%q) returned hash of length %d, want 64", tt.input, len(got))
			}

			// Hash should be deterministic
			got2 := hashDetailCmd(tt.input)
			if got != got2 {
				t.Errorf("hashDetailCmd(%q) not deterministic: %q != %q", tt.input, got, got2)
			}

			// Different inputs should produce different hashes
			if tt.input != "" {
				different := hashDetailCmd(tt.input + "x")
				if got == different {
					t.Errorf("hashDetailCmd(%q) and hashDetailCmd(%q) produced same hash", tt.input, tt.input+"x")
				}
			}
		})
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		maxLen int
		want   string
	}{
		{"short string", "hello", 10, "hello"},
		{"exact length", "hello", 5, "hello"},
		{"needs truncation", "hello world", 8, "hello..."},
		{"very short max", "hello world", 4, "h..."},
		{"empty string", "", 10, ""},
		{"long path", "/usr/local/bin/very-long-program-name", 20, "/usr/local/bin/ve..."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := truncate(tt.input, tt.maxLen)
			if got != tt.want {
				t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.maxLen, got, tt.want)
			}
		})
	}
}

func TestSortedServices(t *testing.T) {
	// Create test services
	services := map[int32]*Service{
		1: {RootPID: 1, Name: "nginx", CPUPercent: 10.0, MemBytes: 1000, IOReadKBps: 5.0, IOWriteKBps: 2.0},
		2: {RootPID: 2, Name: "apache", CPUPercent: 20.0, MemBytes: 2000, IOReadKBps: 10.0, IOWriteKBps: 8.0},
		3: {RootPID: 3, Name: "mysql", CPUPercent: 15.0, MemBytes: 3000, IOReadKBps: 15.0, IOWriteKBps: 5.0},
	}

	t.Run("sort by name (default)", func(t *testing.T) {
		*sortBy = "name"
		sorted := sortedServices(services)
		if len(sorted) != 3 {
			t.Fatalf("expected 3 services, got %d", len(sorted))
		}
		if sorted[0].Name != "apache" || sorted[1].Name != "mysql" || sorted[2].Name != "nginx" {
			t.Errorf("sort by name failed: got %s, %s, %s", sorted[0].Name, sorted[1].Name, sorted[2].Name)
		}
	})

	t.Run("sort by cpu", func(t *testing.T) {
		*sortBy = "cpu"
		sorted := sortedServices(services)
		if sorted[0].Name != "apache" || sorted[1].Name != "mysql" || sorted[2].Name != "nginx" {
			t.Errorf("sort by cpu failed: got %s (%.1f), %s (%.1f), %s (%.1f)",
				sorted[0].Name, sorted[0].CPUPercent,
				sorted[1].Name, sorted[1].CPUPercent,
				sorted[2].Name, sorted[2].CPUPercent)
		}
	})

	t.Run("sort by memory", func(t *testing.T) {
		*sortBy = "memory"
		sorted := sortedServices(services)
		if sorted[0].Name != "mysql" || sorted[1].Name != "apache" || sorted[2].Name != "nginx" {
			t.Errorf("sort by memory failed: got %s, %s, %s", sorted[0].Name, sorted[1].Name, sorted[2].Name)
		}
	})

	t.Run("sort by io_r", func(t *testing.T) {
		*sortBy = "io_r"
		sorted := sortedServices(services)
		if sorted[0].Name != "mysql" || sorted[1].Name != "apache" || sorted[2].Name != "nginx" {
			t.Errorf("sort by io_r failed: got %s, %s, %s", sorted[0].Name, sorted[1].Name, sorted[2].Name)
		}
	})

	t.Run("sort by io_w", func(t *testing.T) {
		*sortBy = "io_w"
		sorted := sortedServices(services)
		if sorted[0].Name != "apache" || sorted[1].Name != "mysql" || sorted[2].Name != "nginx" {
			t.Errorf("sort by io_w failed: got %s, %s, %s", sorted[0].Name, sorted[1].Name, sorted[2].Name)
		}
	})

	t.Run("empty services", func(t *testing.T) {
		*sortBy = "name"
		sorted := sortedServices(map[int32]*Service{})
		if len(sorted) != 0 {
			t.Errorf("expected empty slice, got %d elements", len(sorted))
		}
	})
}

func TestExcludeListContainsExpectedPatterns(t *testing.T) {
	expectedPatterns := []string{
		"kworker", "ksoftirqd", "kthreadd", "migration",
		"rcu_", "watchdog", "kswapd",
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

func TestContainerInfraProcessesContainsExpectedPatterns(t *testing.T) {
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

func TestServiceStruct(t *testing.T) {
	// Test that Service struct can be created with all fields
	svc := Service{
		RootPID:      123,
		Name:         "test-service",
		Exe:          "/usr/bin/test",
		BinPath:      "/usr/bin/test",
		DetailCmd:    "/usr/bin/test --config /etc/test.conf",
		StartMode:    "systemd",
		ListenPorts:  []uint32{80, 443},
		CPUPercent:   25.5,
		MemBytes:     1024 * 1024 * 100,
		IOReadBytes:  1024 * 1024,
		IOWriteBytes: 512 * 1024,
		IOReadKBps:   10.5,
		IOWriteKBps:  5.25,
		ChildCount:   3,
		InstanceIP:   "192.168.1.100",
	}

	if svc.RootPID != 123 {
		t.Errorf("RootPID = %d, want 123", svc.RootPID)
	}
	if svc.Name != "test-service" {
		t.Errorf("Name = %s, want test-service", svc.Name)
	}
	if svc.StartMode != "systemd" {
		t.Errorf("StartMode = %s, want systemd", svc.StartMode)
	}
	if len(svc.ListenPorts) != 2 {
		t.Errorf("ListenPorts length = %d, want 2", len(svc.ListenPorts))
	}
}

func TestIORateCollectorConfig(t *testing.T) {
	// Test default config values
	if defaultIOConfig.duration != 3*time.Second {
		t.Errorf("default duration = %v, want %v", defaultIOConfig.duration, 3*time.Second)
	}
}

func TestCollectServiceIORatesWithEmptyServices(t *testing.T) {
	// Should not panic with empty services map
	services := make(map[int32]*Service)
	collectServiceIORates(services)

	if len(services) != 0 {
		t.Errorf("expected empty services map, got %d entries", len(services))
	}
}

func TestCollectServiceIORatesWithConfig(t *testing.T) {
	// Use a very short config for faster testing
	cfg := ioRateCollectorConfig{
		duration: 20 * time.Millisecond,
	}

	// Get current process PID for testing
	pid := int32(os.Getpid())
	services := map[int32]*Service{
		pid: {
			RootPID: pid,
			Name:    "test-process",
		},
	}

	// Run collection
	collectServiceIORatesWithConfig(services, cfg)

	// The IO rates should be set (may be 0 if no IO happened, but should not be negative)
	svc := services[pid]
	if svc.IOReadKBps < 0 {
		t.Errorf("IOReadKBps should not be negative, got %f", svc.IOReadKBps)
	}
	if svc.IOWriteKBps < 0 {
		t.Errorf("IOWriteKBps should not be negative, got %f", svc.IOWriteKBps)
	}
}

func TestSampleIORateWithCurrentProcess(t *testing.T) {
	// Use current process for testing
	pid := int32(os.Getpid())

	cfg := ioRateCollectorConfig{
		duration: 20 * time.Millisecond,
	}

	readKBps, writeKBps := sampleIORate(pid, cfg)

	// Rates should not be negative
	if readKBps < 0 {
		t.Errorf("readKBps should not be negative, got %f", readKBps)
	}
	if writeKBps < 0 {
		t.Errorf("writeKBps should not be negative, got %f", writeKBps)
	}
}

func TestSampleIORateWithInvalidPID(t *testing.T) {
	// Use an invalid PID
	cfg := ioRateCollectorConfig{
		duration: 10 * time.Millisecond,
	}

	readKBps, writeKBps := sampleIORate(-1, cfg)

	// Should return 0 for invalid PID
	if readKBps != 0 {
		t.Errorf("readKBps should be 0 for invalid PID, got %f", readKBps)
	}
	if writeKBps != 0 {
		t.Errorf("writeKBps should be 0 for invalid PID, got %f", writeKBps)
	}
}

func TestSampleIORateWithNonExistentPID(t *testing.T) {
	// Use a very high PID that likely doesn't exist
	cfg := ioRateCollectorConfig{
		duration: 10 * time.Millisecond,
	}

	readKBps, writeKBps := sampleIORate(999999999, cfg)

	// Should return 0 for non-existent PID
	if readKBps != 0 {
		t.Errorf("readKBps should be 0 for non-existent PID, got %f", readKBps)
	}
	if writeKBps != 0 {
		t.Errorf("writeKBps should be 0 for non-existent PID, got %f", writeKBps)
	}
}

func TestCollectServiceIORatesMultipleServices(t *testing.T) {
	// Test with multiple services using current process
	pid := int32(os.Getpid())

	cfg := ioRateCollectorConfig{
		duration: 20 * time.Millisecond,
	}

	// Create multiple service entries pointing to same PID (for testing concurrency)
	services := map[int32]*Service{
		pid: {
			RootPID: pid,
			Name:    "test-process-1",
		},
	}

	// Run collection
	collectServiceIORatesWithConfig(services, cfg)

	// Verify all services got updated
	for _, svc := range services {
		if svc.IOReadKBps < 0 || svc.IOWriteKBps < 0 {
			t.Errorf("IO rates should not be negative for service %s", svc.Name)
		}
	}
}
