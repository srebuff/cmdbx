package probe

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// KernelVersion represents a parsed Linux kernel version
type KernelVersion struct {
	Major int
	Minor int
	Patch int
	Full  string
}

// String returns the kernel version as a string
func (k KernelVersion) String() string {
	return k.Full
}

// AtLeast checks if this kernel version is at least the specified version
func (k KernelVersion) AtLeast(major, minor, patch int) bool {
	if k.Major > major {
		return true
	}
	if k.Major < major {
		return false
	}
	// Major is equal
	if k.Minor > minor {
		return true
	}
	if k.Minor < minor {
		return false
	}
	// Minor is equal
	return k.Patch >= patch
}

// SupportsEBPF checks if the kernel supports eBPF/XDP
// eBPF maps and basic programs: kernel >= 3.18
// XDP: kernel >= 4.8
// BPF Type Format (BTF): kernel >= 4.18
// For reliable eBPF networking: kernel >= 4.15 recommended
func (k KernelVersion) SupportsEBPF() bool {
	return k.AtLeast(4, 15, 0)
}

// SupportsBPFLink checks if the kernel supports bpf_link
// bpf_link for XDP: kernel >= 5.7
func (k KernelVersion) SupportsBPFLink() bool {
	return k.AtLeast(5, 7, 0)
}

// GetKernelVersion reads and parses the current kernel version
func GetKernelVersion() (KernelVersion, error) {
	return GetKernelVersionFromFile("/proc/version")
}

// GetKernelVersionFromFile reads kernel version from a file (for testing)
func GetKernelVersionFromFile(path string) (KernelVersion, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return KernelVersion{}, fmt.Errorf("failed to read kernel version: %w", err)
	}
	return ParseKernelVersion(string(data))
}

// ParseKernelVersion parses a kernel version string
// Supports formats like:
// - "Linux version 5.4.0-42-generic ..."
// - "5.4.0-42-generic"
// - "5.4.0"
func ParseKernelVersion(versionStr string) (KernelVersion, error) {
	kv := KernelVersion{Full: strings.TrimSpace(versionStr)}

	// Try to extract version from "Linux version X.Y.Z..." format
	re := regexp.MustCompile(`(\d+)\.(\d+)\.(\d+)`)
	matches := re.FindStringSubmatch(versionStr)
	if len(matches) < 4 {
		return kv, fmt.Errorf("unable to parse kernel version from: %s", versionStr)
	}

	var err error
	kv.Major, err = strconv.Atoi(matches[1])
	if err != nil {
		return kv, fmt.Errorf("invalid major version: %s", matches[1])
	}

	kv.Minor, err = strconv.Atoi(matches[2])
	if err != nil {
		return kv, fmt.Errorf("invalid minor version: %s", matches[2])
	}

	kv.Patch, err = strconv.Atoi(matches[3])
	if err != nil {
		return kv, fmt.Errorf("invalid patch version: %s", matches[3])
	}

	return kv, nil
}

// DetectBestCollectorType determines the best network collector type
// based on kernel version and available capabilities
func DetectBestCollectorType() CollectorType {
	kv, err := GetKernelVersion()
	if err != nil {
		// Can't determine kernel version, fall back to gopacket
		return CollectorTypeGoPacket
	}

	if kv.SupportsEBPF() {
		// Check if eBPF is actually available (not just kernel version)
		if isEBPFAvailable() {
			return CollectorTypeEBPF
		}
	}

	return CollectorTypeGoPacket
}

// isEBPFAvailable checks if eBPF is actually usable on this system
func isEBPFAvailable() bool {
	// Check if /sys/fs/bpf exists (BPF filesystem)
	if _, err := os.Stat("/sys/fs/bpf"); os.IsNotExist(err) {
		return false
	}

	// Check if we can access /sys/kernel/btf/vmlinux (BTF support)
	// This is optional but indicates good eBPF support
	// BTF is available from kernel 4.18+

	return true
}

// GetCollectorTypeString returns a human-readable description of the collector type
func GetCollectorTypeString(ct CollectorType) string {
	switch ct {
	case CollectorTypeEBPF:
		return "eBPF/XDP (high performance, kernel >= 4.15)"
	case CollectorTypeGoPacket:
		return "AF_PACKET/gopacket (compatible, any kernel)"
	case CollectorTypeNone:
		return "none (network collection disabled)"
	default:
		return "unknown"
	}
}
