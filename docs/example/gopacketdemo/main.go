package main

import (
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
)

func main() {
	// 1. Create a new TPacket (AF_PACKET) source
	// OptFrameSize and OptBlockSize are critical for older kernels
	// to align with memory page sizes.
	handle, err := afpacket.NewTPacket(
		afpacket.OptInterface("eth0"),
		afpacket.OptFrameSize(4096),
		afpacket.OptBlockSize(4096*128), // 512KB blocks
		afpacket.OptNumBlocks(128),      // Total ~64MB ring buffer
	)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// 2. Wrap in gopacket for easy decoding
	packetSource := gopacket.NewPacketSource(handle, layers.LinkTypeEthernet)

	// 3. Stats tracking map
	trafficStats := make(map[string]int64)

	fmt.Println("Starting traffic statistics collection (AF_PACKET)...")

	// 4. Analysis Loop
	for packet := range packetSource.Packets() {
		if netLayer := packet.NetworkLayer(); netLayer != nil {
			src, dst := netLayer.NetworkFlow().Endpoints()
			size := int64(len(packet.Data()))

			// Aggregate stats
			key := fmt.Sprintf("%s -> %s", src, dst)
			trafficStats[key] += size
		}

		// Example: Print stats every 1000 packets
		if len(packet.Data())%1000 == 0 {
			printSummary(trafficStats)
		}
	}
}

func printSummary(stats map[string]int64) {
	fmt.Println("--- Current Traffic Stats ---")
	for flow, bytes := range stats {
		fmt.Printf("%s: %.2f KB\n", flow, float64(bytes)/1024)
	}
}
