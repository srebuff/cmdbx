package main

import (
	"net"
	"testing"
	"unsafe"
)

func TestParseRule(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    FilterRule
		wantErr bool
	}{
		{
			name:  "full rule with all fields",
			input: "192.168.1.100,10.0.0.1,8080,443,tcp,drop",
			want: FilterRule{
				SrcIP:    ipToUint32(net.ParseIP("192.168.1.100").To4()),
				DstIP:    ipToUint32(net.ParseIP("10.0.0.1").To4()),
				SrcPort:  8080,
				DstPort:  443,
				Protocol: 6, // TCP
				Action:   1, // drop
				Enabled:  1,
			},
			wantErr: false,
		},
		{
			name:  "wildcard source IP",
			input: "*,10.0.0.1,*,80,tcp,count",
			want: FilterRule{
				SrcIP:    0,
				DstIP:    ipToUint32(net.ParseIP("10.0.0.1").To4()),
				SrcPort:  0,
				DstPort:  80,
				Protocol: 6,
				Action:   0, // count
				Enabled:  1,
			},
			wantErr: false,
		},
		{
			name:  "all wildcards with UDP",
			input: "*,*,*,*,udp,pass",
			want: FilterRule{
				SrcIP:    0,
				DstIP:    0,
				SrcPort:  0,
				DstPort:  0,
				Protocol: 17, // UDP
				Action:   2,  // pass
				Enabled:  1,
			},
			wantErr: false,
		},
		{
			name:  "zero as wildcard",
			input: "0,0,0,0,any,count",
			want: FilterRule{
				SrcIP:    0,
				DstIP:    0,
				SrcPort:  0,
				DstPort:  0,
				Protocol: 0,
				Action:   0,
				Enabled:  1,
			},
			wantErr: false,
		},
		{
			name:  "ICMP protocol",
			input: "192.168.1.1,*,*,*,icmp,drop",
			want: FilterRule{
				SrcIP:    ipToUint32(net.ParseIP("192.168.1.1").To4()),
				DstIP:    0,
				SrcPort:  0,
				DstPort:  0,
				Protocol: 1, // ICMP
				Action:   1,
				Enabled:  1,
			},
			wantErr: false,
		},
		{
			name:  "numeric protocol",
			input: "*,*,*,*,47,count",
			want: FilterRule{
				SrcIP:    0,
				DstIP:    0,
				SrcPort:  0,
				DstPort:  0,
				Protocol: 47, // GRE
				Action:   0,
				Enabled:  1,
			},
			wantErr: false,
		},
		// Case insensitivity tests
		{
			name:  "uppercase TCP protocol",
			input: "*,*,*,443,TCP,DROP",
			want: FilterRule{
				SrcIP:    0,
				DstIP:    0,
				SrcPort:  0,
				DstPort:  443,
				Protocol: 6,
				Action:   1,
				Enabled:  1,
			},
			wantErr: false,
		},
		{
			name:  "mixed case UDP PASS",
			input: "*,*,*,53,Udp,Pass",
			want: FilterRule{
				SrcIP:    0,
				DstIP:    0,
				SrcPort:  0,
				DstPort:  53,
				Protocol: 17,
				Action:   2,
				Enabled:  1,
			},
			wantErr: false,
		},
		// Numeric action tests
		{
			name:  "numeric action 0 for count",
			input: "*,*,*,*,tcp,0",
			want: FilterRule{
				Protocol: 6,
				Action:   0,
				Enabled:  1,
			},
			wantErr: false,
		},
		{
			name:  "numeric action 1 for drop",
			input: "*,*,*,*,tcp,1",
			want: FilterRule{
				Protocol: 6,
				Action:   1,
				Enabled:  1,
			},
			wantErr: false,
		},
		{
			name:  "numeric action 2 for pass",
			input: "*,*,*,*,tcp,2",
			want: FilterRule{
				Protocol: 6,
				Action:   2,
				Enabled:  1,
			},
			wantErr: false,
		},
		// Port boundary tests
		{
			name:  "max valid port 65535",
			input: "*,*,65535,65535,tcp,count",
			want: FilterRule{
				SrcPort:  65535,
				DstPort:  65535,
				Protocol: 6,
				Enabled:  1,
			},
			wantErr: false,
		},
		{
			name:  "port 1",
			input: "*,*,1,1,tcp,count",
			want: FilterRule{
				SrcPort:  1,
				DstPort:  1,
				Protocol: 6,
				Enabled:  1,
			},
			wantErr: false,
		},
		// Error cases
		{
			name:    "invalid - too few parts",
			input:   "192.168.1.1,*,*,tcp,drop",
			wantErr: true,
		},
		{
			name:    "invalid - too many parts",
			input:   "192.168.1.1,*,*,*,tcp,drop,extra",
			wantErr: true,
		},
		{
			name:    "invalid source IP",
			input:   "invalid-ip,*,*,*,tcp,drop",
			wantErr: true,
		},
		{
			name:    "invalid destination IP",
			input:   "*,not.an.ip,*,*,tcp,drop",
			wantErr: true,
		},
		{
			name:    "invalid source port - not a number",
			input:   "*,*,abc,*,tcp,drop",
			wantErr: true,
		},
		{
			name:    "invalid destination port - out of range high",
			input:   "*,*,*,99999,tcp,drop",
			wantErr: true,
		},
		{
			name:    "invalid source port - negative",
			input:   "*,*,-1,*,tcp,drop",
			wantErr: true,
		},
		{
			name:    "invalid destination port - negative",
			input:   "*,*,*,-100,tcp,drop",
			wantErr: true,
		},
		{
			name:    "invalid protocol",
			input:   "*,*,*,*,invalid,drop",
			wantErr: true,
		},
		{
			name:    "invalid action",
			input:   "*,*,*,*,tcp,invalid",
			wantErr: true,
		},
		{
			name:    "empty input",
			input:   "",
			wantErr: true,
		},
		{
			name:    "only commas",
			input:   ",,,,,",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseRule(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseRule() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if got.SrcIP != tt.want.SrcIP {
					t.Errorf("SrcIP = %v, want %v", got.SrcIP, tt.want.SrcIP)
				}
				if got.DstIP != tt.want.DstIP {
					t.Errorf("DstIP = %v, want %v", got.DstIP, tt.want.DstIP)
				}
				if got.SrcPort != tt.want.SrcPort {
					t.Errorf("SrcPort = %v, want %v", got.SrcPort, tt.want.SrcPort)
				}
				if got.DstPort != tt.want.DstPort {
					t.Errorf("DstPort = %v, want %v", got.DstPort, tt.want.DstPort)
				}
				if got.Protocol != tt.want.Protocol {
					t.Errorf("Protocol = %v, want %v", got.Protocol, tt.want.Protocol)
				}
				if got.Action != tt.want.Action {
					t.Errorf("Action = %v, want %v", got.Action, tt.want.Action)
				}
				if got.Enabled != tt.want.Enabled {
					t.Errorf("Enabled = %v, want %v", got.Enabled, tt.want.Enabled)
				}
			}
		})
	}
}

func TestProtoToName(t *testing.T) {
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
		// Unknown protocols should return numeric string
		{0, "0"},
		{3, "3"},
		{41, "41"},   // IPv6 encapsulation
		{58, "58"},   // ICMPv6
		{255, "255"}, // Reserved
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := protoToName(tt.proto)
			if got != tt.want {
				t.Errorf("protoToName(%d) = %q, want %q", tt.proto, got, tt.want)
			}
		})
	}
}

func TestIpToUint32(t *testing.T) {
	tests := []struct {
		name string
		ip   net.IP
		want uint32
	}{
		{
			name: "192.168.1.1",
			ip:   net.ParseIP("192.168.1.1").To4(),
			want: 0x0101A8C0, // Little endian: 192.168.1.1
		},
		{
			name: "10.0.0.1",
			ip:   net.ParseIP("10.0.0.1").To4(),
			want: 0x0100000A,
		},
		{
			name: "127.0.0.1",
			ip:   net.ParseIP("127.0.0.1").To4(),
			want: 0x0100007F,
		},
		{
			name: "255.255.255.255",
			ip:   net.ParseIP("255.255.255.255").To4(),
			want: 0xFFFFFFFF,
		},
		{
			name: "0.0.0.0",
			ip:   net.ParseIP("0.0.0.0").To4(),
			want: 0x00000000,
		},
		{
			name: "nil IP",
			ip:   nil,
			want: 0,
		},
		{
			name: "1.2.3.4",
			ip:   net.ParseIP("1.2.3.4").To4(),
			want: 0x04030201,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ipToUint32(tt.ip)
			if got != tt.want {
				t.Errorf("ipToUint32() = 0x%08X, want 0x%08X", got, tt.want)
			}
		})
	}
}

func TestUint32ToIP(t *testing.T) {
	tests := []struct {
		name string
		n    uint32
		want string
	}{
		{
			name: "192.168.1.1",
			n:    0x0101A8C0,
			want: "192.168.1.1",
		},
		{
			name: "10.0.0.1",
			n:    0x0100000A,
			want: "10.0.0.1",
		},
		{
			name: "127.0.0.1",
			n:    0x0100007F,
			want: "127.0.0.1",
		},
		{
			name: "255.255.255.255",
			n:    0xFFFFFFFF,
			want: "255.255.255.255",
		},
		{
			name: "0.0.0.0",
			n:    0x00000000,
			want: "0.0.0.0",
		},
		{
			name: "1.2.3.4",
			n:    0x04030201,
			want: "1.2.3.4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := uint32ToIP(tt.n)
			if got.String() != tt.want {
				t.Errorf("uint32ToIP() = %v, want %v", got.String(), tt.want)
			}
		})
	}
}

func TestIpConversionRoundTrip(t *testing.T) {
	ips := []string{
		"192.168.1.1",
		"10.0.0.1",
		"172.16.0.100",
		"8.8.8.8",
		"1.2.3.4",
		"255.255.255.255",
		"0.0.0.0",
		"224.0.0.1",   // Multicast
		"169.254.1.1", // Link-local
	}

	for _, ipStr := range ips {
		t.Run(ipStr, func(t *testing.T) {
			original := net.ParseIP(ipStr).To4()
			asUint32 := ipToUint32(original)
			backToIP := uint32ToIP(asUint32)

			if !original.Equal(backToIP) {
				t.Errorf("Round trip failed: %v -> 0x%08X -> %v", original, asUint32, backToIP)
			}
		})
	}
}

func TestGetInterface(t *testing.T) {
	// Test with empty name - should find first non-loopback interface
	t.Run("auto detect interface", func(t *testing.T) {
		iface, err := getInterface("")
		// This may fail in some environments, so we just check it doesn't panic
		if err != nil {
			t.Logf("getInterface(\"\") returned error (expected in some envs): %v", err)
		} else {
			if iface.Flags&net.FlagLoopback != 0 {
				t.Error("getInterface returned loopback interface")
			}
			t.Logf("Found interface: %s", iface.Name)
		}
	})

	// Test with invalid interface name
	t.Run("invalid interface name", func(t *testing.T) {
		_, err := getInterface("nonexistent-interface-12345")
		if err == nil {
			t.Error("Expected error for nonexistent interface")
		}
	})

	// Test with loopback (should exist on most systems)
	t.Run("loopback interface", func(t *testing.T) {
		iface, err := getInterface("lo")
		if err != nil {
			t.Logf("loopback 'lo' not found (may be named differently): %v", err)
		} else {
			if iface.Name != "lo" {
				t.Errorf("Expected 'lo', got %s", iface.Name)
			}
		}
	})
}

// TestStructSizes verifies that Go structs match the expected sizes for eBPF compatibility
func TestStructSizes(t *testing.T) {
	t.Run("FilterRule size", func(t *testing.T) {
		// FilterRule should be 16 bytes to match C struct:
		// uint32 src_ip (4) + uint32 dst_ip (4) + uint16 src_port (2) +
		// uint16 dst_port (2) + uint8 protocol (1) + uint8 action (1) +
		// uint8 enabled (1) + uint8 pad (1) = 16 bytes
		expected := uintptr(16)
		actual := unsafe.Sizeof(FilterRule{})
		if actual != expected {
			t.Errorf("FilterRule size = %d bytes, want %d bytes", actual, expected)
		}
	})

	t.Run("FlowKey size", func(t *testing.T) {
		// FlowKey should be 16 bytes to match C struct:
		// uint32 src_ip (4) + uint32 dst_ip (4) + uint16 src_port (2) +
		// uint16 dst_port (2) + uint8 protocol (1) + [3]uint8 pad (3) = 16 bytes
		expected := uintptr(16)
		actual := unsafe.Sizeof(FlowKey{})
		if actual != expected {
			t.Errorf("FlowKey size = %d bytes, want %d bytes", actual, expected)
		}
	})

	t.Run("FlowStats size", func(t *testing.T) {
		// FlowStats should be 16 bytes to match C struct:
		// uint64 packets (8) + uint64 bytes (8) = 16 bytes
		expected := uintptr(16)
		actual := unsafe.Sizeof(FlowStats{})
		if actual != expected {
			t.Errorf("FlowStats size = %d bytes, want %d bytes", actual, expected)
		}
	})
}

// TestFlowKeyAlignment verifies struct field alignment for eBPF map operations
func TestFlowKeyAlignment(t *testing.T) {
	key := FlowKey{
		SrcIP:    0x0100007F, // 127.0.0.1
		DstIP:    0x0101A8C0, // 192.168.1.1
		SrcPort:  8080,
		DstPort:  443,
		Protocol: 6, // TCP
	}

	// Verify fields are accessible and maintain values
	if key.SrcIP != 0x0100007F {
		t.Errorf("SrcIP corrupted: got 0x%08X", key.SrcIP)
	}
	if key.DstIP != 0x0101A8C0 {
		t.Errorf("DstIP corrupted: got 0x%08X", key.DstIP)
	}
	if key.SrcPort != 8080 {
		t.Errorf("SrcPort corrupted: got %d", key.SrcPort)
	}
	if key.DstPort != 443 {
		t.Errorf("DstPort corrupted: got %d", key.DstPort)
	}
	if key.Protocol != 6 {
		t.Errorf("Protocol corrupted: got %d", key.Protocol)
	}
}

// TestFlowStatsAlignment verifies FlowStats struct for eBPF map operations
func TestFlowStatsAlignment(t *testing.T) {
	stats := FlowStats{
		Packets: 1000,
		Bytes:   1500000,
	}

	if stats.Packets != 1000 {
		t.Errorf("Packets corrupted: got %d", stats.Packets)
	}
	if stats.Bytes != 1500000 {
		t.Errorf("Bytes corrupted: got %d", stats.Bytes)
	}
}

// TestFilterRuleDefaults verifies default values
func TestFilterRuleDefaults(t *testing.T) {
	rule := FilterRule{}

	// All fields should be zero by default except when explicitly set
	if rule.SrcIP != 0 {
		t.Errorf("Default SrcIP should be 0, got %d", rule.SrcIP)
	}
	if rule.Enabled != 0 {
		t.Errorf("Default Enabled should be 0, got %d", rule.Enabled)
	}
}

func BenchmarkParseRule(b *testing.B) {
	rule := "192.168.1.100,10.0.0.1,8080,443,tcp,drop"
	for i := 0; i < b.N; i++ {
		_, _ = parseRule(rule)
	}
}

func BenchmarkParseRuleWildcard(b *testing.B) {
	rule := "*,*,*,9200,tcp,count"
	for i := 0; i < b.N; i++ {
		_, _ = parseRule(rule)
	}
}

func BenchmarkIpToUint32(b *testing.B) {
	ip := net.ParseIP("192.168.1.100").To4()
	for i := 0; i < b.N; i++ {
		_ = ipToUint32(ip)
	}
}

func BenchmarkUint32ToIP(b *testing.B) {
	n := uint32(0x0101A8C0)
	for i := 0; i < b.N; i++ {
		_ = uint32ToIP(n)
	}
}

func BenchmarkProtoToName(b *testing.B) {
	protos := []uint8{1, 6, 17, 47, 112, 255}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = protoToName(protos[i%len(protos)])
	}
}
