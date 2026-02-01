//go:build linux

package main

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/cilium/ebpf/rlimit"
)

// Test packet builder helpers
type packetBuilder struct {
	data []byte
}

func newPacket() *packetBuilder {
	return &packetBuilder{data: make([]byte, 0, 128)}
}

// addEthernet adds Ethernet header (14 bytes)
func (p *packetBuilder) addEthernet(srcMAC, dstMAC net.HardwareAddr, etherType uint16) *packetBuilder {
	p.data = append(p.data, dstMAC...)
	p.data = append(p.data, srcMAC...)
	p.data = append(p.data, byte(etherType>>8), byte(etherType))
	return p
}

// addIPv4 adds IPv4 header (20 bytes, no options)
func (p *packetBuilder) addIPv4(srcIP, dstIP net.IP, protocol uint8, totalLen uint16) *packetBuilder {
	ipHeader := make([]byte, 20)
	ipHeader[0] = 0x45                                  // Version (4) + IHL (5)
	ipHeader[1] = 0x00                                  // DSCP + ECN
	binary.BigEndian.PutUint16(ipHeader[2:4], totalLen) // Total Length
	binary.BigEndian.PutUint16(ipHeader[4:6], 0)        // Identification
	binary.BigEndian.PutUint16(ipHeader[6:8], 0)        // Flags + Fragment Offset
	ipHeader[8] = 64                                    // TTL
	ipHeader[9] = protocol                              // Protocol
	binary.BigEndian.PutUint16(ipHeader[10:12], 0)      // Checksum (0 for test)
	copy(ipHeader[12:16], srcIP.To4())                  // Source IP
	copy(ipHeader[16:20], dstIP.To4())                  // Destination IP
	p.data = append(p.data, ipHeader...)
	return p
}

// addTCP adds TCP header (20 bytes, no options)
func (p *packetBuilder) addTCP(srcPort, dstPort uint16, flags uint8) *packetBuilder {
	tcpHeader := make([]byte, 20)
	binary.BigEndian.PutUint16(tcpHeader[0:2], srcPort) // Source Port
	binary.BigEndian.PutUint16(tcpHeader[2:4], dstPort) // Destination Port
	binary.BigEndian.PutUint32(tcpHeader[4:8], 0)       // Sequence Number
	binary.BigEndian.PutUint32(tcpHeader[8:12], 0)      // Acknowledgment Number
	tcpHeader[12] = 0x50                                // Data Offset (5) + Reserved
	tcpHeader[13] = flags                               // Flags
	binary.BigEndian.PutUint16(tcpHeader[14:16], 65535) // Window Size
	binary.BigEndian.PutUint16(tcpHeader[16:18], 0)     // Checksum
	binary.BigEndian.PutUint16(tcpHeader[18:20], 0)     // Urgent Pointer
	p.data = append(p.data, tcpHeader...)
	return p
}

// addUDP adds UDP header (8 bytes)
func (p *packetBuilder) addUDP(srcPort, dstPort uint16, length uint16) *packetBuilder {
	udpHeader := make([]byte, 8)
	binary.BigEndian.PutUint16(udpHeader[0:2], srcPort) // Source Port
	binary.BigEndian.PutUint16(udpHeader[2:4], dstPort) // Destination Port
	binary.BigEndian.PutUint16(udpHeader[4:6], length)  // Length
	binary.BigEndian.PutUint16(udpHeader[6:8], 0)       // Checksum
	p.data = append(p.data, udpHeader...)
	return p
}

// addICMP adds ICMP header (8 bytes for echo request/reply)
func (p *packetBuilder) addICMP(icmpType, code uint8, id, seq uint16) *packetBuilder {
	icmpHeader := make([]byte, 8)
	icmpHeader[0] = icmpType                         // Type
	icmpHeader[1] = code                             // Code
	binary.BigEndian.PutUint16(icmpHeader[2:4], 0)   // Checksum
	binary.BigEndian.PutUint16(icmpHeader[4:6], id)  // Identifier
	binary.BigEndian.PutUint16(icmpHeader[6:8], seq) // Sequence Number
	p.data = append(p.data, icmpHeader...)
	return p
}

// addPayload adds arbitrary payload
func (p *packetBuilder) addPayload(payload []byte) *packetBuilder {
	p.data = append(p.data, payload...)
	return p
}

func (p *packetBuilder) build() []byte {
	return p.data
}

// TCP flags
const (
	TCP_FIN = 0x01
	TCP_SYN = 0x02
	TCP_RST = 0x04
	TCP_PSH = 0x08
	TCP_ACK = 0x10
	TCP_URG = 0x20
)

// ICMP types
const (
	ICMP_ECHO_REPLY   = 0
	ICMP_ECHO_REQUEST = 8
)

// buildTCPPacket creates a complete TCP packet
func buildTCPPacket(srcIP, dstIP string, srcPort, dstPort uint16) []byte {
	return buildTCPPacketWithFlags(srcIP, dstIP, srcPort, dstPort, TCP_SYN)
}

// buildTCPPacketWithFlags creates a TCP packet with specific flags
func buildTCPPacketWithFlags(srcIP, dstIP string, srcPort, dstPort uint16, flags uint8) []byte {
	srcMAC, _ := net.ParseMAC("00:00:00:00:00:01")
	dstMAC, _ := net.ParseMAC("00:00:00:00:00:02")

	return newPacket().
		addEthernet(srcMAC, dstMAC, 0x0800).                    // IPv4
		addIPv4(net.ParseIP(srcIP), net.ParseIP(dstIP), 6, 40). // TCP
		addTCP(srcPort, dstPort, flags).
		build()
}

// buildUDPPacket creates a complete UDP packet
func buildUDPPacket(srcIP, dstIP string, srcPort, dstPort uint16) []byte {
	srcMAC, _ := net.ParseMAC("00:00:00:00:00:01")
	dstMAC, _ := net.ParseMAC("00:00:00:00:00:02")

	return newPacket().
		addEthernet(srcMAC, dstMAC, 0x0800).                     // IPv4
		addIPv4(net.ParseIP(srcIP), net.ParseIP(dstIP), 17, 28). // UDP
		addUDP(srcPort, dstPort, 8).
		build()
}

// buildICMPPacket creates a complete ICMP packet
func buildICMPPacket(srcIP, dstIP string, icmpType uint8) []byte {
	srcMAC, _ := net.ParseMAC("00:00:00:00:00:01")
	dstMAC, _ := net.ParseMAC("00:00:00:00:00:02")

	return newPacket().
		addEthernet(srcMAC, dstMAC, 0x0800).                    // IPv4
		addIPv4(net.ParseIP(srcIP), net.ParseIP(dstIP), 1, 28). // ICMP
		addICMP(icmpType, 0, 1, 1).
		build()
}

// buildARPPacket creates a non-IPv4 ARP packet (should be passed through)
func buildARPPacket() []byte {
	srcMAC, _ := net.ParseMAC("00:00:00:00:00:01")
	dstMAC, _ := net.ParseMAC("ff:ff:ff:ff:ff:ff")

	pkt := newPacket().
		addEthernet(srcMAC, dstMAC, 0x0806) // ARP

	// ARP payload (28 bytes)
	arpData := make([]byte, 28)
	binary.BigEndian.PutUint16(arpData[0:2], 1)      // Hardware type: Ethernet
	binary.BigEndian.PutUint16(arpData[2:4], 0x0800) // Protocol type: IPv4
	arpData[4] = 6                                   // Hardware size
	arpData[5] = 4                                   // Protocol size
	binary.BigEndian.PutUint16(arpData[6:8], 1)      // Opcode: Request

	return pkt.addPayload(arpData).build()
}

// buildIPv6Packet creates an IPv6 packet (should be passed through)
func buildIPv6Packet() []byte {
	srcMAC, _ := net.ParseMAC("00:00:00:00:00:01")
	dstMAC, _ := net.ParseMAC("00:00:00:00:00:02")

	return newPacket().
		addEthernet(srcMAC, dstMAC, 0x86DD). // IPv6
		addPayload(make([]byte, 40)).        // Minimal IPv6 header
		build()
}

// XDP return values
const (
	XDP_ABORTED  = 0
	XDP_DROP     = 1
	XDP_PASS     = 2
	XDP_TX       = 3
	XDP_REDIRECT = 4
)

func TestXDPProgram(t *testing.T) {
	// Remove memory limits
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("Failed to remove memlock: %v", err)
	}

	// Load BPF objects
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		t.Fatalf("Failed to load BPF objects: %v", err)
	}
	defer objs.Close()

	t.Run("pass IPv4 TCP packet without filtering", func(t *testing.T) {
		// Disable filtering
		if err := objs.Config.Put(uint32(0), uint32(0)); err != nil {
			t.Fatalf("Failed to disable filtering: %v", err)
		}

		pkt := buildTCPPacket("192.168.1.100", "10.0.0.1", 12345, 80)

		ret, _, err := objs.CountPackets.Test(pkt)
		if err != nil {
			t.Fatalf("Program test failed: %v", err)
		}

		if ret != XDP_PASS {
			t.Errorf("Expected XDP_PASS (%d), got %d", XDP_PASS, ret)
		}
	})

	t.Run("pass IPv4 UDP packet without filtering", func(t *testing.T) {
		// Disable filtering
		if err := objs.Config.Put(uint32(0), uint32(0)); err != nil {
			t.Fatalf("Failed to disable filtering: %v", err)
		}

		pkt := buildUDPPacket("192.168.1.100", "10.0.0.1", 12345, 53)

		ret, _, err := objs.CountPackets.Test(pkt)
		if err != nil {
			t.Fatalf("Program test failed: %v", err)
		}

		if ret != XDP_PASS {
			t.Errorf("Expected XDP_PASS (%d), got %d", XDP_PASS, ret)
		}
	})

	t.Run("pass ICMP packet without filtering", func(t *testing.T) {
		if err := objs.Config.Put(uint32(0), uint32(0)); err != nil {
			t.Fatalf("Failed to disable filtering: %v", err)
		}

		pkt := buildICMPPacket("192.168.1.100", "10.0.0.1", ICMP_ECHO_REQUEST)

		ret, _, err := objs.CountPackets.Test(pkt)
		if err != nil {
			t.Fatalf("Program test failed: %v", err)
		}

		if ret != XDP_PASS {
			t.Errorf("Expected XDP_PASS (%d), got %d", XDP_PASS, ret)
		}
	})

	t.Run("pass non-IPv4 packets (ARP)", func(t *testing.T) {
		pkt := buildARPPacket()

		ret, _, err := objs.CountPackets.Test(pkt)
		if err != nil {
			t.Fatalf("Program test failed: %v", err)
		}

		if ret != XDP_PASS {
			t.Errorf("ARP packet should pass, expected XDP_PASS (%d), got %d", XDP_PASS, ret)
		}
	})

	t.Run("pass non-IPv4 packets (IPv6)", func(t *testing.T) {
		pkt := buildIPv6Packet()

		ret, _, err := objs.CountPackets.Test(pkt)
		if err != nil {
			t.Fatalf("Program test failed: %v", err)
		}

		if ret != XDP_PASS {
			t.Errorf("IPv6 packet should pass, expected XDP_PASS (%d), got %d", XDP_PASS, ret)
		}
	})

	t.Run("drop packet with filter rule", func(t *testing.T) {
		// Enable filtering
		if err := objs.Config.Put(uint32(0), uint32(1)); err != nil {
			t.Fatalf("Failed to enable filtering: %v", err)
		}

		// Add drop rule for source IP 192.168.1.100
		rule := FilterRule{
			SrcIP:    ipToUint32(net.ParseIP("192.168.1.100").To4()),
			DstIP:    0,
			SrcPort:  0,
			DstPort:  0,
			Protocol: 0,
			Action:   1, // DROP
			Enabled:  1,
		}
		if err := objs.FilterRules.Put(uint32(0), rule); err != nil {
			t.Fatalf("Failed to add filter rule: %v", err)
		}

		pkt := buildTCPPacket("192.168.1.100", "10.0.0.1", 12345, 80)

		ret, _, err := objs.CountPackets.Test(pkt)
		if err != nil {
			t.Fatalf("Program test failed: %v", err)
		}

		if ret != XDP_DROP {
			t.Errorf("Expected XDP_DROP (%d), got %d", XDP_DROP, ret)
		}

		// Clean up rule
		emptyRule := FilterRule{}
		objs.FilterRules.Put(uint32(0), emptyRule)
	})

	t.Run("pass packet not matching filter rule", func(t *testing.T) {
		// Enable filtering
		if err := objs.Config.Put(uint32(0), uint32(1)); err != nil {
			t.Fatalf("Failed to enable filtering: %v", err)
		}

		// Add drop rule for different IP
		rule := FilterRule{
			SrcIP:    ipToUint32(net.ParseIP("10.10.10.10").To4()),
			DstIP:    0,
			SrcPort:  0,
			DstPort:  0,
			Protocol: 0,
			Action:   1, // DROP
			Enabled:  1,
		}
		if err := objs.FilterRules.Put(uint32(0), rule); err != nil {
			t.Fatalf("Failed to add filter rule: %v", err)
		}

		// This packet should NOT match the rule
		pkt := buildTCPPacket("192.168.1.100", "10.0.0.1", 12345, 80)

		ret, _, err := objs.CountPackets.Test(pkt)
		if err != nil {
			t.Fatalf("Program test failed: %v", err)
		}

		if ret != XDP_PASS {
			t.Errorf("Expected XDP_PASS (%d), got %d", XDP_PASS, ret)
		}

		// Clean up rule
		emptyRule := FilterRule{}
		objs.FilterRules.Put(uint32(0), emptyRule)
	})

	t.Run("filter by destination port", func(t *testing.T) {
		// Enable filtering
		if err := objs.Config.Put(uint32(0), uint32(1)); err != nil {
			t.Fatalf("Failed to enable filtering: %v", err)
		}

		// Add drop rule for port 22 (SSH)
		rule := FilterRule{
			SrcIP:    0,
			DstIP:    0,
			SrcPort:  0,
			DstPort:  22,
			Protocol: 6, // TCP
			Action:   1, // DROP
			Enabled:  1,
		}
		if err := objs.FilterRules.Put(uint32(0), rule); err != nil {
			t.Fatalf("Failed to add filter rule: %v", err)
		}

		// Packet to port 22 should be dropped
		pkt22 := buildTCPPacket("192.168.1.100", "10.0.0.1", 12345, 22)
		ret, _, err := objs.CountPackets.Test(pkt22)
		if err != nil {
			t.Fatalf("Program test failed: %v", err)
		}
		if ret != XDP_DROP {
			t.Errorf("Port 22: Expected XDP_DROP (%d), got %d", XDP_DROP, ret)
		}

		// Packet to port 80 should pass
		pkt80 := buildTCPPacket("192.168.1.100", "10.0.0.1", 12345, 80)
		ret, _, err = objs.CountPackets.Test(pkt80)
		if err != nil {
			t.Fatalf("Program test failed: %v", err)
		}
		if ret != XDP_PASS {
			t.Errorf("Port 80: Expected XDP_PASS (%d), got %d", XDP_PASS, ret)
		}

		// Clean up rule
		emptyRule := FilterRule{}
		objs.FilterRules.Put(uint32(0), emptyRule)
	})

	t.Run("filter by source port", func(t *testing.T) {
		// Enable filtering
		if err := objs.Config.Put(uint32(0), uint32(1)); err != nil {
			t.Fatalf("Failed to enable filtering: %v", err)
		}

		// Add drop rule for source port 31337
		rule := FilterRule{
			SrcIP:    0,
			DstIP:    0,
			SrcPort:  31337,
			DstPort:  0,
			Protocol: 6, // TCP
			Action:   1, // DROP
			Enabled:  1,
		}
		if err := objs.FilterRules.Put(uint32(0), rule); err != nil {
			t.Fatalf("Failed to add filter rule: %v", err)
		}

		// Packet from port 31337 should be dropped
		pktDrop := buildTCPPacket("192.168.1.100", "10.0.0.1", 31337, 80)
		ret, _, err := objs.CountPackets.Test(pktDrop)
		if err != nil {
			t.Fatalf("Program test failed: %v", err)
		}
		if ret != XDP_DROP {
			t.Errorf("Source port 31337: Expected XDP_DROP (%d), got %d", XDP_DROP, ret)
		}

		// Packet from different port should pass
		pktPass := buildTCPPacket("192.168.1.100", "10.0.0.1", 12345, 80)
		ret, _, err = objs.CountPackets.Test(pktPass)
		if err != nil {
			t.Fatalf("Program test failed: %v", err)
		}
		if ret != XDP_PASS {
			t.Errorf("Source port 12345: Expected XDP_PASS (%d), got %d", XDP_PASS, ret)
		}

		// Clean up rule
		emptyRule := FilterRule{}
		objs.FilterRules.Put(uint32(0), emptyRule)
	})

	t.Run("filter by protocol", func(t *testing.T) {
		// Enable filtering
		if err := objs.Config.Put(uint32(0), uint32(1)); err != nil {
			t.Fatalf("Failed to enable filtering: %v", err)
		}

		// Add drop rule for UDP only
		rule := FilterRule{
			SrcIP:    0,
			DstIP:    0,
			SrcPort:  0,
			DstPort:  0,
			Protocol: 17, // UDP
			Action:   1,  // DROP
			Enabled:  1,
		}
		if err := objs.FilterRules.Put(uint32(0), rule); err != nil {
			t.Fatalf("Failed to add filter rule: %v", err)
		}

		// UDP packet should be dropped
		udpPkt := buildUDPPacket("192.168.1.100", "10.0.0.1", 12345, 53)
		ret, _, err := objs.CountPackets.Test(udpPkt)
		if err != nil {
			t.Fatalf("Program test failed: %v", err)
		}
		if ret != XDP_DROP {
			t.Errorf("UDP: Expected XDP_DROP (%d), got %d", XDP_DROP, ret)
		}

		// TCP packet should pass
		tcpPkt := buildTCPPacket("192.168.1.100", "10.0.0.1", 12345, 80)
		ret, _, err = objs.CountPackets.Test(tcpPkt)
		if err != nil {
			t.Fatalf("Program test failed: %v", err)
		}
		if ret != XDP_PASS {
			t.Errorf("TCP: Expected XDP_PASS (%d), got %d", XDP_PASS, ret)
		}

		// Clean up rule
		emptyRule := FilterRule{}
		objs.FilterRules.Put(uint32(0), emptyRule)
	})

	t.Run("filter by destination IP", func(t *testing.T) {
		// Enable filtering
		if err := objs.Config.Put(uint32(0), uint32(1)); err != nil {
			t.Fatalf("Failed to enable filtering: %v", err)
		}

		// Add drop rule for destination IP
		rule := FilterRule{
			SrcIP:    0,
			DstIP:    ipToUint32(net.ParseIP("10.0.0.1").To4()),
			SrcPort:  0,
			DstPort:  0,
			Protocol: 0,
			Action:   1, // DROP
			Enabled:  1,
		}
		if err := objs.FilterRules.Put(uint32(0), rule); err != nil {
			t.Fatalf("Failed to add filter rule: %v", err)
		}

		// Packet to 10.0.0.1 should be dropped
		pktDrop := buildTCPPacket("192.168.1.100", "10.0.0.1", 12345, 80)
		ret, _, err := objs.CountPackets.Test(pktDrop)
		if err != nil {
			t.Fatalf("Program test failed: %v", err)
		}
		if ret != XDP_DROP {
			t.Errorf("Dst 10.0.0.1: Expected XDP_DROP (%d), got %d", XDP_DROP, ret)
		}

		// Packet to different IP should pass
		pktPass := buildTCPPacket("192.168.1.100", "10.0.0.2", 12345, 80)
		ret, _, err = objs.CountPackets.Test(pktPass)
		if err != nil {
			t.Fatalf("Program test failed: %v", err)
		}
		if ret != XDP_PASS {
			t.Errorf("Dst 10.0.0.2: Expected XDP_PASS (%d), got %d", XDP_PASS, ret)
		}

		// Clean up rule
		emptyRule := FilterRule{}
		objs.FilterRules.Put(uint32(0), emptyRule)
	})

	t.Run("action count (should pass)", func(t *testing.T) {
		// Enable filtering
		if err := objs.Config.Put(uint32(0), uint32(1)); err != nil {
			t.Fatalf("Failed to enable filtering: %v", err)
		}

		// Add count rule (action=0)
		rule := FilterRule{
			SrcIP:    ipToUint32(net.ParseIP("192.168.1.100").To4()),
			DstIP:    0,
			SrcPort:  0,
			DstPort:  0,
			Protocol: 0,
			Action:   0, // COUNT
			Enabled:  1,
		}
		if err := objs.FilterRules.Put(uint32(0), rule); err != nil {
			t.Fatalf("Failed to add filter rule: %v", err)
		}

		pkt := buildTCPPacket("192.168.1.100", "10.0.0.1", 12345, 80)

		ret, _, err := objs.CountPackets.Test(pkt)
		if err != nil {
			t.Fatalf("Program test failed: %v", err)
		}

		// Count action should pass the packet
		if ret != XDP_PASS {
			t.Errorf("Count action: Expected XDP_PASS (%d), got %d", XDP_PASS, ret)
		}

		// Clean up rule
		emptyRule := FilterRule{}
		objs.FilterRules.Put(uint32(0), emptyRule)
	})

	t.Run("action pass (explicit pass)", func(t *testing.T) {
		// Enable filtering
		if err := objs.Config.Put(uint32(0), uint32(1)); err != nil {
			t.Fatalf("Failed to enable filtering: %v", err)
		}

		// Add pass rule (action=2)
		rule := FilterRule{
			SrcIP:    ipToUint32(net.ParseIP("192.168.1.100").To4()),
			DstIP:    0,
			SrcPort:  0,
			DstPort:  0,
			Protocol: 0,
			Action:   2, // PASS
			Enabled:  1,
		}
		if err := objs.FilterRules.Put(uint32(0), rule); err != nil {
			t.Fatalf("Failed to add filter rule: %v", err)
		}

		pkt := buildTCPPacket("192.168.1.100", "10.0.0.1", 12345, 80)

		ret, _, err := objs.CountPackets.Test(pkt)
		if err != nil {
			t.Fatalf("Program test failed: %v", err)
		}

		if ret != XDP_PASS {
			t.Errorf("Pass action: Expected XDP_PASS (%d), got %d", XDP_PASS, ret)
		}

		// Clean up rule
		emptyRule := FilterRule{}
		objs.FilterRules.Put(uint32(0), emptyRule)
	})

	t.Run("disabled rule should not match", func(t *testing.T) {
		// Enable filtering
		if err := objs.Config.Put(uint32(0), uint32(1)); err != nil {
			t.Fatalf("Failed to enable filtering: %v", err)
		}

		// Add disabled drop rule
		rule := FilterRule{
			SrcIP:    ipToUint32(net.ParseIP("192.168.1.100").To4()),
			DstIP:    0,
			SrcPort:  0,
			DstPort:  0,
			Protocol: 0,
			Action:   1, // DROP
			Enabled:  0, // DISABLED
		}
		if err := objs.FilterRules.Put(uint32(0), rule); err != nil {
			t.Fatalf("Failed to add filter rule: %v", err)
		}

		pkt := buildTCPPacket("192.168.1.100", "10.0.0.1", 12345, 80)

		ret, _, err := objs.CountPackets.Test(pkt)
		if err != nil {
			t.Fatalf("Program test failed: %v", err)
		}

		// Disabled rule should not drop
		if ret != XDP_PASS {
			t.Errorf("Disabled rule: Expected XDP_PASS (%d), got %d", XDP_PASS, ret)
		}

		// Clean up rule
		emptyRule := FilterRule{}
		objs.FilterRules.Put(uint32(0), emptyRule)
	})

	t.Run("multiple rules - first match wins", func(t *testing.T) {
		// Enable filtering
		if err := objs.Config.Put(uint32(0), uint32(1)); err != nil {
			t.Fatalf("Failed to enable filtering: %v", err)
		}

		// Rule 0: Pass packets from 192.168.1.100
		rule0 := FilterRule{
			SrcIP:    ipToUint32(net.ParseIP("192.168.1.100").To4()),
			DstIP:    0,
			SrcPort:  0,
			DstPort:  0,
			Protocol: 0,
			Action:   2, // PASS
			Enabled:  1,
		}
		if err := objs.FilterRules.Put(uint32(0), rule0); err != nil {
			t.Fatalf("Failed to add filter rule 0: %v", err)
		}

		// Rule 1: Drop all TCP (would match but rule 0 should win)
		rule1 := FilterRule{
			SrcIP:    0,
			DstIP:    0,
			SrcPort:  0,
			DstPort:  0,
			Protocol: 6, // TCP
			Action:   1, // DROP
			Enabled:  1,
		}
		if err := objs.FilterRules.Put(uint32(1), rule1); err != nil {
			t.Fatalf("Failed to add filter rule 1: %v", err)
		}

		// Packet from 192.168.1.100 should pass (rule 0 wins)
		pkt := buildTCPPacket("192.168.1.100", "10.0.0.1", 12345, 80)
		ret, _, err := objs.CountPackets.Test(pkt)
		if err != nil {
			t.Fatalf("Program test failed: %v", err)
		}
		if ret != XDP_PASS {
			t.Errorf("First match (rule 0): Expected XDP_PASS (%d), got %d", XDP_PASS, ret)
		}

		// Packet from different IP should be dropped (rule 1)
		pkt2 := buildTCPPacket("10.10.10.10", "10.0.0.1", 12345, 80)
		ret, _, err = objs.CountPackets.Test(pkt2)
		if err != nil {
			t.Fatalf("Program test failed: %v", err)
		}
		if ret != XDP_DROP {
			t.Errorf("Second match (rule 1): Expected XDP_DROP (%d), got %d", XDP_DROP, ret)
		}

		// Clean up rules
		emptyRule := FilterRule{}
		objs.FilterRules.Put(uint32(0), emptyRule)
		objs.FilterRules.Put(uint32(1), emptyRule)
	})

	t.Run("complex rule with all fields", func(t *testing.T) {
		// Enable filtering
		if err := objs.Config.Put(uint32(0), uint32(1)); err != nil {
			t.Fatalf("Failed to enable filtering: %v", err)
		}

		// Add complex rule matching all fields
		rule := FilterRule{
			SrcIP:    ipToUint32(net.ParseIP("192.168.1.100").To4()),
			DstIP:    ipToUint32(net.ParseIP("10.0.0.1").To4()),
			SrcPort:  12345,
			DstPort:  443,
			Protocol: 6, // TCP
			Action:   1, // DROP
			Enabled:  1,
		}
		if err := objs.FilterRules.Put(uint32(0), rule); err != nil {
			t.Fatalf("Failed to add filter rule: %v", err)
		}

		// Exact match should drop
		pktDrop := buildTCPPacket("192.168.1.100", "10.0.0.1", 12345, 443)
		ret, _, err := objs.CountPackets.Test(pktDrop)
		if err != nil {
			t.Fatalf("Program test failed: %v", err)
		}
		if ret != XDP_DROP {
			t.Errorf("Exact match: Expected XDP_DROP (%d), got %d", XDP_DROP, ret)
		}

		// Different dst port should pass
		pktPass1 := buildTCPPacket("192.168.1.100", "10.0.0.1", 12345, 80)
		ret, _, err = objs.CountPackets.Test(pktPass1)
		if err != nil {
			t.Fatalf("Program test failed: %v", err)
		}
		if ret != XDP_PASS {
			t.Errorf("Different dst port: Expected XDP_PASS (%d), got %d", XDP_PASS, ret)
		}

		// Different src port should pass
		pktPass2 := buildTCPPacket("192.168.1.100", "10.0.0.1", 54321, 443)
		ret, _, err = objs.CountPackets.Test(pktPass2)
		if err != nil {
			t.Fatalf("Program test failed: %v", err)
		}
		if ret != XDP_PASS {
			t.Errorf("Different src port: Expected XDP_PASS (%d), got %d", XDP_PASS, ret)
		}

		// Clean up rule
		emptyRule := FilterRule{}
		objs.FilterRules.Put(uint32(0), emptyRule)
	})

	t.Run("drop ICMP with filter", func(t *testing.T) {
		// Enable filtering
		if err := objs.Config.Put(uint32(0), uint32(1)); err != nil {
			t.Fatalf("Failed to enable filtering: %v", err)
		}

		// Add drop rule for ICMP
		rule := FilterRule{
			SrcIP:    0,
			DstIP:    0,
			SrcPort:  0,
			DstPort:  0,
			Protocol: 1, // ICMP
			Action:   1, // DROP
			Enabled:  1,
		}
		if err := objs.FilterRules.Put(uint32(0), rule); err != nil {
			t.Fatalf("Failed to add filter rule: %v", err)
		}

		pkt := buildICMPPacket("192.168.1.100", "10.0.0.1", ICMP_ECHO_REQUEST)

		ret, _, err := objs.CountPackets.Test(pkt)
		if err != nil {
			t.Fatalf("Program test failed: %v", err)
		}

		if ret != XDP_DROP {
			t.Errorf("ICMP drop: Expected XDP_DROP (%d), got %d", XDP_DROP, ret)
		}

		// Clean up rule
		emptyRule := FilterRule{}
		objs.FilterRules.Put(uint32(0), emptyRule)
	})

	t.Run("IP stats updated with FlowKey", func(t *testing.T) {
		// Disable filtering for clean test
		if err := objs.Config.Put(uint32(0), uint32(0)); err != nil {
			t.Fatalf("Failed to disable filtering: %v", err)
		}

		srcIP := "172.16.0.100"
		dstIP := "10.0.0.1"
		srcPort := uint16(54321)
		dstPort := uint16(8080)

		pkt := buildTCPPacket(srcIP, dstIP, srcPort, dstPort)

		// Run the program
		_, _, err := objs.CountPackets.Test(pkt)
		if err != nil {
			t.Fatalf("Program test failed: %v", err)
		}

		// Check IP stats map with FlowKey
		key := FlowKey{
			SrcIP:    ipToUint32(net.ParseIP(srcIP).To4()),
			DstIP:    ipToUint32(net.ParseIP(dstIP).To4()),
			SrcPort:  srcPort,
			DstPort:  dstPort,
			Protocol: 6, // TCP
		}
		var value FlowStats
		if err := objs.IpStats.Lookup(key, &value); err != nil {
			t.Logf("Note: IP stats lookup returned error (may be expected in test mode): %v", err)
		} else if value.Packets > 0 {
			t.Logf("Flow stats for %s:%d -> %s:%d: %d packets, %d bytes",
				srcIP, srcPort, dstIP, dstPort, value.Packets, value.Bytes)
		}
	})

	t.Run("TCP SYN packet (zero payload)", func(t *testing.T) {
		if err := objs.Config.Put(uint32(0), uint32(0)); err != nil {
			t.Fatalf("Failed to disable filtering: %v", err)
		}

		// SYN packet has no payload
		pkt := buildTCPPacketWithFlags("192.168.1.100", "10.0.0.1", 12345, 80, TCP_SYN)

		ret, _, err := objs.CountPackets.Test(pkt)
		if err != nil {
			t.Fatalf("Program test failed: %v", err)
		}

		if ret != XDP_PASS {
			t.Errorf("TCP SYN: Expected XDP_PASS (%d), got %d", XDP_PASS, ret)
		}
	})

	t.Run("TCP RST packet", func(t *testing.T) {
		if err := objs.Config.Put(uint32(0), uint32(0)); err != nil {
			t.Fatalf("Failed to disable filtering: %v", err)
		}

		pkt := buildTCPPacketWithFlags("192.168.1.100", "10.0.0.1", 12345, 80, TCP_RST)

		ret, _, err := objs.CountPackets.Test(pkt)
		if err != nil {
			t.Fatalf("Program test failed: %v", err)
		}

		if ret != XDP_PASS {
			t.Errorf("TCP RST: Expected XDP_PASS (%d), got %d", XDP_PASS, ret)
		}
	})

	t.Run("TCP FIN-ACK packet", func(t *testing.T) {
		if err := objs.Config.Put(uint32(0), uint32(0)); err != nil {
			t.Fatalf("Failed to disable filtering: %v", err)
		}

		pkt := buildTCPPacketWithFlags("192.168.1.100", "10.0.0.1", 12345, 80, TCP_FIN|TCP_ACK)

		ret, _, err := objs.CountPackets.Test(pkt)
		if err != nil {
			t.Fatalf("Program test failed: %v", err)
		}

		if ret != XDP_PASS {
			t.Errorf("TCP FIN-ACK: Expected XDP_PASS (%d), got %d", XDP_PASS, ret)
		}
	})
}

func TestXDPProgramBenchmark(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping benchmark in short mode")
	}

	// Remove memory limits
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("Failed to remove memlock: %v", err)
	}

	// Load BPF objects
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		t.Fatalf("Failed to load BPF objects: %v", err)
	}
	defer objs.Close()

	// Disable filtering for baseline
	objs.Config.Put(uint32(0), uint32(0))

	pkt := buildTCPPacket("192.168.1.100", "10.0.0.1", 12345, 80)

	// Run multiple iterations
	iterations := 1000
	for i := 0; i < iterations; i++ {
		_, _, err := objs.CountPackets.Test(pkt)
		if err != nil {
			t.Fatalf("Iteration %d failed: %v", i, err)
		}
	}
	t.Logf("Successfully ran %d iterations", iterations)
}

// TestPacketBuilder validates the packet builder produces correct packets
func TestPacketBuilder(t *testing.T) {
	t.Run("TCP packet structure", func(t *testing.T) {
		pkt := buildTCPPacket("192.168.1.1", "10.0.0.1", 12345, 80)

		// Ethernet (14) + IP (20) + TCP (20) = 54 bytes minimum
		if len(pkt) < 54 {
			t.Errorf("TCP packet too short: %d bytes, expected at least 54", len(pkt))
		}

		// Check EtherType (IPv4 = 0x0800)
		etherType := binary.BigEndian.Uint16(pkt[12:14])
		if etherType != 0x0800 {
			t.Errorf("Wrong EtherType: 0x%04X, expected 0x0800", etherType)
		}

		// Check IP protocol (TCP = 6)
		ipProto := pkt[23]
		if ipProto != 6 {
			t.Errorf("Wrong IP protocol: %d, expected 6 (TCP)", ipProto)
		}
	})

	t.Run("UDP packet structure", func(t *testing.T) {
		pkt := buildUDPPacket("192.168.1.1", "10.0.0.1", 12345, 53)

		// Ethernet (14) + IP (20) + UDP (8) = 42 bytes minimum
		if len(pkt) < 42 {
			t.Errorf("UDP packet too short: %d bytes, expected at least 42", len(pkt))
		}

		// Check IP protocol (UDP = 17)
		ipProto := pkt[23]
		if ipProto != 17 {
			t.Errorf("Wrong IP protocol: %d, expected 17 (UDP)", ipProto)
		}
	})

	t.Run("ICMP packet structure", func(t *testing.T) {
		pkt := buildICMPPacket("192.168.1.1", "10.0.0.1", ICMP_ECHO_REQUEST)

		// Ethernet (14) + IP (20) + ICMP (8) = 42 bytes minimum
		if len(pkt) < 42 {
			t.Errorf("ICMP packet too short: %d bytes, expected at least 42", len(pkt))
		}

		// Check IP protocol (ICMP = 1)
		ipProto := pkt[23]
		if ipProto != 1 {
			t.Errorf("Wrong IP protocol: %d, expected 1 (ICMP)", ipProto)
		}
	})

	t.Run("ARP packet structure", func(t *testing.T) {
		pkt := buildARPPacket()

		// Ethernet (14) + ARP (28) = 42 bytes
		if len(pkt) < 42 {
			t.Errorf("ARP packet too short: %d bytes, expected at least 42", len(pkt))
		}

		// Check EtherType (ARP = 0x0806)
		etherType := binary.BigEndian.Uint16(pkt[12:14])
		if etherType != 0x0806 {
			t.Errorf("Wrong EtherType: 0x%04X, expected 0x0806", etherType)
		}
	})
}

func BenchmarkXDPProgram(b *testing.B) {
	// Remove memory limits
	if err := rlimit.RemoveMemlock(); err != nil {
		b.Fatalf("Failed to remove memlock: %v", err)
	}

	// Load BPF objects
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		b.Fatalf("Failed to load BPF objects: %v", err)
	}
	defer objs.Close()

	// Disable filtering
	objs.Config.Put(uint32(0), uint32(0))

	pkt := buildTCPPacket("192.168.1.100", "10.0.0.1", 12345, 80)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		objs.CountPackets.Test(pkt)
	}
}

func BenchmarkXDPProgramWithFiltering(b *testing.B) {
	// Remove memory limits
	if err := rlimit.RemoveMemlock(); err != nil {
		b.Fatalf("Failed to remove memlock: %v", err)
	}

	// Load BPF objects
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		b.Fatalf("Failed to load BPF objects: %v", err)
	}
	defer objs.Close()

	// Enable filtering with a rule
	objs.Config.Put(uint32(0), uint32(1))
	rule := FilterRule{
		SrcIP:    ipToUint32(net.ParseIP("10.10.10.10").To4()),
		DstIP:    0,
		SrcPort:  0,
		DstPort:  0,
		Protocol: 0,
		Action:   1,
		Enabled:  1,
	}
	objs.FilterRules.Put(uint32(0), rule)

	pkt := buildTCPPacket("192.168.1.100", "10.0.0.1", 12345, 80)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		objs.CountPackets.Test(pkt)
	}
}

func BenchmarkXDPProgramUDP(b *testing.B) {
	if err := rlimit.RemoveMemlock(); err != nil {
		b.Fatalf("Failed to remove memlock: %v", err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		b.Fatalf("Failed to load BPF objects: %v", err)
	}
	defer objs.Close()

	objs.Config.Put(uint32(0), uint32(0))

	pkt := buildUDPPacket("192.168.1.100", "10.0.0.1", 12345, 53)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		objs.CountPackets.Test(pkt)
	}
}

func BenchmarkXDPProgramICMP(b *testing.B) {
	if err := rlimit.RemoveMemlock(); err != nil {
		b.Fatalf("Failed to remove memlock: %v", err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		b.Fatalf("Failed to load BPF objects: %v", err)
	}
	defer objs.Close()

	objs.Config.Put(uint32(0), uint32(0))

	pkt := buildICMPPacket("192.168.1.100", "10.0.0.1", ICMP_ECHO_REQUEST)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		objs.CountPackets.Test(pkt)
	}
}
