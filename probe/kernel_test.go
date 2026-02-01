package probe

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseKernelVersion(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantMajor int
		wantMinor int
		wantPatch int
		wantErr   bool
	}{
		{
			name:      "full proc version format",
			input:     "Linux version 5.4.0-42-generic (buildd@lgw01-amd64-039) (gcc version 9.3.0 (Ubuntu 9.3.0-10ubuntu2)) #46-Ubuntu SMP Fri Jul 10 00:24:02 UTC 2020",
			wantMajor: 5,
			wantMinor: 4,
			wantPatch: 0,
			wantErr:   false,
		},
		{
			name:      "simple version",
			input:     "5.4.0",
			wantMajor: 5,
			wantMinor: 4,
			wantPatch: 0,
			wantErr:   false,
		},
		{
			name:      "version with suffix",
			input:     "4.15.0-112-generic",
			wantMajor: 4,
			wantMinor: 15,
			wantPatch: 0,
			wantErr:   false,
		},
		{
			name:      "old kernel 3.10",
			input:     "Linux version 3.10.0-1160.el7.x86_64",
			wantMajor: 3,
			wantMinor: 10,
			wantPatch: 0,
			wantErr:   false,
		},
		{
			name:      "kernel 6.x",
			input:     "Linux version 6.2.0-39-generic",
			wantMajor: 6,
			wantMinor: 2,
			wantPatch: 0,
			wantErr:   false,
		},
		{
			name:      "WSL kernel",
			input:     "Linux version 5.15.90.1-microsoft-standard-WSL2",
			wantMajor: 5,
			wantMinor: 15,
			wantPatch: 90,
			wantErr:   false,
		},
		{
			name:    "invalid - no version",
			input:   "Linux kernel",
			wantErr: true,
		},
		{
			name:    "invalid - empty",
			input:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kv, err := ParseKernelVersion(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseKernelVersion() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("ParseKernelVersion() error = %v", err)
				return
			}
			if kv.Major != tt.wantMajor {
				t.Errorf("Major = %d, want %d", kv.Major, tt.wantMajor)
			}
			if kv.Minor != tt.wantMinor {
				t.Errorf("Minor = %d, want %d", kv.Minor, tt.wantMinor)
			}
			if kv.Patch != tt.wantPatch {
				t.Errorf("Patch = %d, want %d", kv.Patch, tt.wantPatch)
			}
		})
	}
}

func TestKernelVersionAtLeast(t *testing.T) {
	tests := []struct {
		name   string
		kv     KernelVersion
		major  int
		minor  int
		patch  int
		expect bool
	}{
		{"5.4.0 >= 4.15.0", KernelVersion{Major: 5, Minor: 4, Patch: 0}, 4, 15, 0, true},
		{"5.4.0 >= 5.4.0", KernelVersion{Major: 5, Minor: 4, Patch: 0}, 5, 4, 0, true},
		{"5.4.0 >= 5.4.1", KernelVersion{Major: 5, Minor: 4, Patch: 0}, 5, 4, 1, false},
		{"5.4.0 >= 5.5.0", KernelVersion{Major: 5, Minor: 4, Patch: 0}, 5, 5, 0, false},
		{"5.4.0 >= 6.0.0", KernelVersion{Major: 5, Minor: 4, Patch: 0}, 6, 0, 0, false},
		{"4.15.0 >= 4.15.0", KernelVersion{Major: 4, Minor: 15, Patch: 0}, 4, 15, 0, true},
		{"4.14.0 >= 4.15.0", KernelVersion{Major: 4, Minor: 14, Patch: 0}, 4, 15, 0, false},
		{"3.10.0 >= 4.15.0", KernelVersion{Major: 3, Minor: 10, Patch: 0}, 4, 15, 0, false},
		{"6.2.0 >= 5.7.0", KernelVersion{Major: 6, Minor: 2, Patch: 0}, 5, 7, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.kv.AtLeast(tt.major, tt.minor, tt.patch)
			if result != tt.expect {
				t.Errorf("AtLeast(%d, %d, %d) = %v, want %v", tt.major, tt.minor, tt.patch, result, tt.expect)
			}
		})
	}
}

func TestKernelVersionSupportsEBPF(t *testing.T) {
	tests := []struct {
		name   string
		kv     KernelVersion
		expect bool
	}{
		{"kernel 5.4.0 supports eBPF", KernelVersion{Major: 5, Minor: 4, Patch: 0}, true},
		{"kernel 4.15.0 supports eBPF", KernelVersion{Major: 4, Minor: 15, Patch: 0}, true},
		{"kernel 4.14.0 does not support eBPF", KernelVersion{Major: 4, Minor: 14, Patch: 0}, false},
		{"kernel 3.10.0 does not support eBPF", KernelVersion{Major: 3, Minor: 10, Patch: 0}, false},
		{"kernel 6.2.0 supports eBPF", KernelVersion{Major: 6, Minor: 2, Patch: 0}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.kv.SupportsEBPF()
			if result != tt.expect {
				t.Errorf("SupportsEBPF() = %v, want %v", result, tt.expect)
			}
		})
	}
}

func TestKernelVersionSupportsBPFLink(t *testing.T) {
	tests := []struct {
		name   string
		kv     KernelVersion
		expect bool
	}{
		{"kernel 5.7.0 supports bpf_link", KernelVersion{Major: 5, Minor: 7, Patch: 0}, true},
		{"kernel 5.8.0 supports bpf_link", KernelVersion{Major: 5, Minor: 8, Patch: 0}, true},
		{"kernel 6.0.0 supports bpf_link", KernelVersion{Major: 6, Minor: 0, Patch: 0}, true},
		{"kernel 5.6.0 does not support bpf_link", KernelVersion{Major: 5, Minor: 6, Patch: 0}, false},
		{"kernel 4.15.0 does not support bpf_link", KernelVersion{Major: 4, Minor: 15, Patch: 0}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.kv.SupportsBPFLink()
			if result != tt.expect {
				t.Errorf("SupportsBPFLink() = %v, want %v", result, tt.expect)
			}
		})
	}
}

func TestGetKernelVersionFromFile(t *testing.T) {
	// Create a temp file with mock kernel version
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "version")

	content := "Linux version 5.15.0-91-generic (buildd@lcy02-amd64-033) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023"
	if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	kv, err := GetKernelVersionFromFile(tmpFile)
	if err != nil {
		t.Fatalf("GetKernelVersionFromFile() error = %v", err)
	}

	if kv.Major != 5 || kv.Minor != 15 || kv.Patch != 0 {
		t.Errorf("GetKernelVersionFromFile() = %d.%d.%d, want 5.15.0", kv.Major, kv.Minor, kv.Patch)
	}
}

func TestGetKernelVersionFromFileNotExists(t *testing.T) {
	_, err := GetKernelVersionFromFile("/nonexistent/file")
	if err == nil {
		t.Error("GetKernelVersionFromFile() expected error for non-existent file")
	}
}

func TestGetCollectorTypeString(t *testing.T) {
	tests := []struct {
		ct   CollectorType
		want string
	}{
		{CollectorTypeEBPF, "eBPF/XDP (high performance, kernel >= 4.15)"},
		{CollectorTypeGoPacket, "AF_PACKET/gopacket (compatible, any kernel)"},
		{CollectorTypeNone, "none (network collection disabled)"},
		{CollectorType("invalid"), "unknown"},
	}

	for _, tt := range tests {
		t.Run(string(tt.ct), func(t *testing.T) {
			result := GetCollectorTypeString(tt.ct)
			if result != tt.want {
				t.Errorf("GetCollectorTypeString(%s) = %q, want %q", tt.ct, result, tt.want)
			}
		})
	}
}

func TestKernelVersionString(t *testing.T) {
	kv := KernelVersion{
		Major: 5,
		Minor: 4,
		Patch: 0,
		Full:  "Linux version 5.4.0-42-generic",
	}

	result := kv.String()
	if result != kv.Full {
		t.Errorf("String() = %q, want %q", result, kv.Full)
	}
}
