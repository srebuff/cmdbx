// Package main implements an MVP process collector for CMDB
// Based on the design at agent_cmdb/docs/design.md
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/process"
)

// Service represents an aggregated service (may contain multiple processes)
type Service struct {
	RootPID      int32
	Name         string
	Exe          string
	BinPath      string
	DetailCmd    string
	StartMode    string // k8s, docker, systemd, native
	ListenPorts  []uint32
	CPUPercent   float64
	MemBytes     uint64
	IOReadBytes  uint64
	IOWriteBytes uint64
	IOReadKBps   float64
	IOWriteKBps  float64
	ChildCount   int
	InstanceIP   string
}

// ExcludeList contains process names/patterns to skip
var ExcludeList = []string{
	"kworker",
	"ksoftirqd",
	"kthreadd",
	"migration",
	"rcu_",
	"watchdog",
	"kswapd",
	"kcompactd",
	"khugepaged",
	"kdevtmpfs",
	"kauditd",
	"khungtaskd",
	"oom_reaper",
	"writeback",
	"kblockd",
	"md",
	"edac-poller",
	"cpuhp",
	"netns",
	"rcu_tasks",
	"kworker",
}

// ContainerInfraProcesses are container runtime/infrastructure processes
// These should NOT be considered as service roots - they are just "wrappers"
var ContainerInfraProcesses = []string{
	"containerd-shim",
	"containerd-shim-runc-v2",
	"tini",
	"dumb-init",
	"docker-init",
	"pause",
	"s6-svscan",
	"s6-supervise",
	"runc",
}

// Flags
var (
	intervalSec  = flag.Int("interval", 60, "Collection interval in seconds")
	once         = flag.Bool("once", false, "Run once and exit")
	verbose      = flag.Bool("v", false, "Verbose output")
	outputFormat = flag.String("format", "table", "Output format: line (influx), json, table")
	instanceID   = flag.String("instance-id", "", "Instance ID for tagging (auto-detect if empty)")
	sortBy       = flag.String("sort-by", "cpu", "Sort by: name, cpu, memory, io_r, io_w")
)

type ioSnapshot struct {
	readBytes  uint64
	writeBytes uint64
	ts         time.Time
}

var prevServiceIO = make(map[int32]ioSnapshot)

func main() {
	flag.Parse()

	// Get instance IP for tagging
	instanceIP := getInstanceIP()

	// Auto-detect instance ID if not provided
	if *instanceID == "" {
		hostname, _ := os.Hostname()
		*instanceID = hostname
	}

	fmt.Printf("Process Collector MVP\n")
	fmt.Printf("Instance: %s (%s)\n", *instanceID, instanceIP)
	fmt.Printf("Interval: %ds, Format: %s\n", *intervalSec, *outputFormat)
	fmt.Println(strings.Repeat("=", 60))

	if *once {
		services, err := collectServices(instanceIP)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error collecting services: %v\n", err)
			return
		}
		outputServices(services)
		return
	}

	for {
		services, err := collectServices(instanceIP)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error collecting services: %v\n", err)
		} else {
			outputServices(services)
		}

		time.Sleep(time.Duration(*intervalSec) * time.Second)
	}
}

// collectServices collects all services with process tree convergence
func collectServices(instanceIP string) (map[int32]*Service, error) {
	services := make(map[int32]*Service)

	procs, err := process.Processes()
	if err != nil {
		return nil, fmt.Errorf("failed to get processes: %w", err)
	}

	// First pass: identify all processes and their root PIDs
	processInfo := make(map[int32]*processData)
	for _, p := range procs {
		pid := p.Pid

		// Skip threads (Tgid != Pid)
		if isThread(pid) {
			continue
		}

		// Get process name
		name, err := p.Name()
		if err != nil {
			continue
		}

		// Skip kernel threads and excluded processes
		if shouldExclude(name, pid) {
			continue
		}

		// Get executable path
		exe, _ := p.Exe()
		if exe == "" {
			exe = name
		}

		// Get parent PID
		ppid, _ := p.Ppid()

		processInfo[pid] = &processData{
			pid:  pid,
			ppid: ppid,
			name: name,
			exe:  exe,
			proc: p,
		}
	}

	// Second pass: find service roots and aggregate
	for pid, pdata := range processInfo {
		// Find service root (direct child of systemd/init)
		rootPid := findServiceRoot(pid, processInfo)

		// Get or create service
		svc, exists := services[rootPid]
		if !exists {
			rootData := processInfo[rootPid]
			if rootData == nil {
				rootData = pdata
			}

			// Detect start mode
			startMode := getStartMode(rootPid)
			detailCmd := getCmdline(rootData.proc)

			svc = &Service{
				RootPID:     rootPid,
				Name:        rootData.name,
				Exe:         rootData.exe,
				BinPath:     rootData.exe,
				DetailCmd:   detailCmd,
				StartMode:   startMode,
				ListenPorts: []uint32{},
				InstanceIP:  instanceIP,
			}
			services[rootPid] = svc
		}

		// Only aggregate if same executable (or root itself)
		if pdata.exe == svc.Exe || pid == rootPid {
			// Collect metrics
			metrics := collectProcessMetrics(pdata.proc)

			svc.CPUPercent += metrics.cpu
			svc.MemBytes += metrics.mem
			svc.IOReadBytes += metrics.ioRead
			svc.IOWriteBytes += metrics.ioWrite
			svc.ChildCount++

			// Merge listen ports
			svc.ListenPorts = mergePorts(svc.ListenPorts, metrics.listenPorts)
		}
	}

	// Collect IO rates by sampling 2 points over 3 seconds using goroutines
	if *verbose {
		fmt.Println("Collecting IO rates (sampling for 3 seconds)...")
	}
	collectServiceIORates(services)

	return services, nil
}

type processData struct {
	pid  int32
	ppid int32
	name string
	exe  string
	proc *process.Process
}

type processMetrics struct {
	cpu         float64
	mem         uint64
	ioRead      uint64
	ioWrite     uint64
	listenPorts []uint32
}

// collectProcessMetrics gathers CPU, memory, I/O and ports for a process
func collectProcessMetrics(p *process.Process) processMetrics {
	metrics := processMetrics{}

	// CPU percent (need to call twice with interval for accurate reading)
	cpu, err := p.CPUPercent()
	if err == nil {
		metrics.cpu = cpu
	}

	// Memory
	memInfo, err := p.MemoryInfo()
	if err == nil && memInfo != nil {
		metrics.mem = memInfo.RSS
	}

	// I/O counters
	ioCounters, err := p.IOCounters()
	if err == nil && ioCounters != nil {
		metrics.ioRead = ioCounters.ReadBytes
		metrics.ioWrite = ioCounters.WriteBytes
	}

	// Listen ports
	conns, err := p.Connections()
	if err == nil {
		for _, conn := range conns {
			// Only LISTEN state TCP or UDP
			if conn.Status == "LISTEN" || conn.Type == 2 { // 2 = UDP
				if conn.Laddr.Port > 0 {
					metrics.listenPorts = append(metrics.listenPorts, conn.Laddr.Port)
				}
			}
		}
	}

	return metrics
}

// isThread checks if a PID is actually a thread (skip it)
func isThread(pid int32) bool {
	statusPath := fmt.Sprintf("/proc/%d/status", pid)
	data, err := os.ReadFile(statusPath)
	if err != nil {
		return false
	}

	var tgid, pidVal int
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Tgid:") {
			fmt.Sscanf(line, "Tgid:\t%d", &tgid)
		}
		if strings.HasPrefix(line, "Pid:") {
			fmt.Sscanf(line, "Pid:\t%d", &pidVal)
		}
	}

	// If Tgid != Pid, this is a thread
	return tgid != 0 && tgid != pidVal
}

// shouldExclude checks if a process should be excluded
func shouldExclude(name string, pid int32) bool {
	// Skip kernel threads (PPID 0 or 2)
	ppid := getPPID(pid)
	if ppid == 0 || ppid == 2 {
		return true
	}

	// Check exclude list
	nameLower := strings.ToLower(name)
	for _, pattern := range ExcludeList {
		if strings.Contains(nameLower, strings.ToLower(pattern)) {
			return true
		}
	}

	// Skip container infrastructure processes (they are not real services)
	// e.g., containerd-shim, tini, pause, docker-init
	if isContainerInfraProcess(name) {
		return true
	}

	return false
}

// isContainerInfraProcess checks if a process name is a container infrastructure process
func isContainerInfraProcess(name string) bool {
	nameLower := strings.ToLower(name)
	for _, infra := range ContainerInfraProcesses {
		if strings.Contains(nameLower, strings.ToLower(infra)) {
			return true
		}
	}
	return false
}

// isDockerProcess checks if a process is running inside a Docker container
func isDockerProcess(pid int32) bool {
	cgroupPath := fmt.Sprintf("/proc/%d/cgroup", pid)
	data, err := os.ReadFile(cgroupPath)
	if err != nil {
		return false
	}
	cgroupStr := string(data)
	return strings.Contains(cgroupStr, "docker") ||
		strings.Contains(cgroupStr, "kubepods") ||
		strings.Contains(cgroupStr, "containerd")
}

// findServiceRoot walks up the PPID chain to find the service root
// For Docker containers, it stops at the actual application (not container infra like containerd-shim, tini)
func findServiceRoot(pid int32, processInfo map[int32]*processData) int32 {
	visited := make(map[int32]bool)
	current := pid

	// Check if this process is running in a container
	inContainer := isDockerProcess(pid)

	for {
		if visited[current] {
			return current // Cycle detected
		}
		visited[current] = true

		pdata := processInfo[current]
		if pdata == nil {
			return current
		}

		ppid := pdata.ppid

		// Stop conditions:
		// 1. PPID is 1 (init/systemd) - current is root
		// 2. PPID is 0 (kernel thread)
		// 3. Parent not in our process list (we crossed service boundary)
		if ppid <= 1 {
			return current
		}

		parentData := processInfo[ppid]
		if parentData == nil {
			return current
		}

		// For Docker containers: stop if parent is container infrastructure
		// e.g., containerd-shim → tini → argocd-repo-server
		// We want argocd-repo-server as the root, not containerd-shim
		if inContainer && isContainerInfraProcess(parentData.name) {
			return current
		}

		// Check if parent has different executable (for non-container processes)
		if pdata.exe != parentData.exe {
			return current
		}

		current = ppid
	}
}

// getStartMode detects how a process was started: k8s, docker, systemd, or native
func getStartMode(pid int32) string {
	cgroupPath := fmt.Sprintf("/proc/%d/cgroup", pid)
	data, err := os.ReadFile(cgroupPath)
	if err != nil {
		return "native"
	}

	cgroupStr := string(data)

	// 1. Check for Kubernetes
	if strings.Contains(cgroupStr, "kubepods") {
		return "k8s"
	}

	// 2. Check for Docker/Containerd
	if strings.Contains(cgroupStr, "docker") ||
		strings.Contains(cgroupStr, "containerd") {
		return "docker"
	}

	// 3. Check for systemd
	if strings.Contains(cgroupStr, ".service") ||
		strings.Contains(cgroupStr, "system.slice") {
		return "systemd"
	}

	// 4. Check if parent is systemd (PID 1)
	ppid := getPPID(pid)
	if ppid == 1 {
		return "systemd"
	}

	// 5. Default to native
	return "native"
}

// getPPID gets the parent PID from /proc/PID/stat
func getPPID(pid int32) int32 {
	statPath := fmt.Sprintf("/proc/%d/stat", pid)
	data, err := os.ReadFile(statPath)
	if err != nil {
		return 0
	}

	// Parse: pid (comm) state ppid ...
	// comm can contain spaces and parentheses, so find last )
	statStr := string(data)
	lastParen := strings.LastIndex(statStr, ")")
	if lastParen == -1 || lastParen+2 >= len(statStr) {
		return 0
	}

	// Fields after (comm) are space-separated
	fields := strings.Fields(statStr[lastParen+2:])
	if len(fields) < 2 {
		return 0
	}

	// Field 0 is state, field 1 is ppid
	ppid, _ := strconv.ParseInt(fields[1], 10, 32)
	return int32(ppid)
}

// getContainerID extracts container ID from cgroup if running in Docker
func getContainerID(pid int32) string {
	cgroupPath := fmt.Sprintf("/proc/%d/cgroup", pid)
	data, err := os.ReadFile(cgroupPath)
	if err != nil {
		return ""
	}

	// Docker cgroup v1: /docker/<container_id>
	// Docker cgroup v2: /system.slice/docker-<container_id>.scope
	re := regexp.MustCompile(`docker[/-]([a-f0-9]{64})`)
	matches := re.FindStringSubmatch(string(data))
	if len(matches) > 1 {
		return matches[1][:12] // Short ID
	}

	return ""
}

// getInstanceIP gets the primary IP address of this host
func getInstanceIP() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "127.0.0.1"
	}

	for _, iface := range interfaces {
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			ip := ipNet.IP.To4()
			if ip == nil || ip.IsLoopback() {
				continue
			}

			return ip.String()
		}
	}

	return "127.0.0.1"
}

// mergePorts merges two port lists, removing duplicates
func mergePorts(a, b []uint32) []uint32 {
	seen := make(map[uint32]bool)
	for _, p := range a {
		seen[p] = true
	}
	for _, p := range b {
		seen[p] = true
	}

	result := make([]uint32, 0, len(seen))
	for p := range seen {
		result = append(result, p)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

// outputServices outputs the collected services in the specified format
func outputServices(services map[int32]*Service) {
	timestamp := time.Now().UnixNano()

	switch *outputFormat {
	case "line":
		outputLineProtocol(services, timestamp)
	case "json":
		outputJSON(services)
	case "table":
		outputTable(services)
	default:
		outputLineProtocol(services, timestamp)
	}
}

// outputLineProtocol outputs in InfluxDB line protocol format
func outputLineProtocol(services map[int32]*Service, timestamp int64) {
	for _, svc := range sortedServices(services) {
		// Format listen ports
		portsStr := formatPorts(svc.ListenPorts)
		detailCmd := escapeTagValue(hashDetailCmd(svc.DetailCmd))

		// Escape special characters in tag values
		name := escapeTagValue(svc.Name)
		binPath := escapeTagValue(svc.BinPath)

		// Build line protocol
		// services,instance_id=xxx,name=xxx,bin_path=xxx,start_mode=xxx pid=123i,listen_ports="80,443",detail_cmd="cmd",cpu_pct=2.5,mem_bytes=512000000i,io_read_bytes=102400i,io_write_bytes=51200i timestamp
		ioReadMB := float64(svc.IOReadBytes) / 1024 / 1024
		ioWriteMB := float64(svc.IOWriteBytes) / 1024 / 1024

		fmt.Printf("services,instance_id=%s,name=%s,instance_ip=%s,bin_path=%s,start_mode=%s,detail_cmd=%s pid=%di,listen_ports=\"%s\",cpu_pct=%.2f,mem_bytes=%di,io_read_bytes=%di,io_write_bytes=%di,io_read_mb=%.2f,io_write_mb=%.2f,io_read_kbps=%.2f,io_write_kbps=%.2f,root_pid=%di,child_count=%di %d\n",
			*instanceID,
			name,
			svc.InstanceIP,
			binPath,
			svc.StartMode,
			detailCmd,
			svc.RootPID,
			portsStr,
			svc.CPUPercent,
			svc.MemBytes,
			svc.IOReadBytes,
			svc.IOWriteBytes,
			ioReadMB,
			ioWriteMB,
			svc.IOReadKBps,
			svc.IOWriteKBps,
			svc.RootPID,
			svc.ChildCount,
			timestamp,
		)
	}
}

// outputTable outputs in human-readable table format
func outputTable(services map[int32]*Service) {
	fmt.Printf("\n--- Services [%s] ---\n", time.Now().Format("15:04:05"))
	fmt.Printf("%-20s | %-8s | %-22s | %-10s | %-8s | %-10s | %-10s | %-10s | %-12s | %-12s | %-15s | %s\n",
		"NAME", "PID", "DETAIL_CMD", "START_MODE", "CPU%", "MEM(MB)", "IO_R(MB)", "IO_W(MB)", "IO_R(KB/s)", "IO_W(KB/s)", "PORTS", "EXE")
	fmt.Println(strings.Repeat("-", 180))

	for _, svc := range sortedServices(services) {
		portsStr := formatPorts(svc.ListenPorts)
		memMB := float64(svc.MemBytes) / 1024 / 1024
		ioReadMB := float64(svc.IOReadBytes) / 1024 / 1024
		ioWriteMB := float64(svc.IOWriteBytes) / 1024 / 1024

		// Truncate long names/paths
		name := truncate(svc.Name, 20)
		exe := truncate(filepath.Base(svc.Exe), 30)
		detailCmd := truncate(svc.DetailCmd, 22)

		fmt.Printf("%-20s | %-8d | %-22s | %-10s | %-8.2f | %-10.1f | %-10.1f | %-10.1f | %-12.2f | %-12.2f | %-15s | %s\n",
			name, svc.RootPID, detailCmd, svc.StartMode, svc.CPUPercent, memMB, ioReadMB, ioWriteMB, svc.IOReadKBps, svc.IOWriteKBps, portsStr, exe)
	}
	fmt.Printf("\nTotal services: %d\n", len(services))
}

// outputJSON outputs in JSON format
func outputJSON(services map[int32]*Service) {
	fmt.Println("[")
	first := true
	for _, svc := range sortedServices(services) {
		if !first {
			fmt.Println(",")
		}
		first = false

		portsStr := formatPorts(svc.ListenPorts)
		detailCmd := svc.DetailCmd
		ioReadMB := float64(svc.IOReadBytes) / 1024 / 1024
		ioWriteMB := float64(svc.IOWriteBytes) / 1024 / 1024
		fmt.Printf(`  {"name":"%s","pid":%d,"start_mode":"%s","exe":"%s","detail_cmd":"%s","cpu_pct":%.2f,"mem_bytes":%d,"io_read_bytes":%d,"io_write_bytes":%d,"io_read_mb":%.2f,"io_write_mb":%.2f,"io_read_kbps":%.2f,"io_write_kbps":%.2f,"listen_ports":"%s","child_count":%d,"instance_ip":"%s"}`,
			svc.Name, svc.RootPID, svc.StartMode, svc.Exe, detailCmd, svc.CPUPercent, svc.MemBytes, svc.IOReadBytes, svc.IOWriteBytes, ioReadMB, ioWriteMB, svc.IOReadKBps, svc.IOWriteKBps, portsStr, svc.ChildCount, svc.InstanceIP)
	}
	fmt.Println("\n]")
}

// formatPorts formats a slice of ports as a comma-separated string
func formatPorts(ports []uint32) string {
	if len(ports) == 0 {
		return ""
	}

	strs := make([]string, len(ports))
	for i, p := range ports {
		strs[i] = strconv.FormatUint(uint64(p), 10)
	}
	return strings.Join(strs, ",")
}

// escapeTagValue escapes special characters for InfluxDB line protocol tags
func escapeTagValue(s string) string {
	s = strings.ReplaceAll(s, " ", "\\ ")
	s = strings.ReplaceAll(s, ",", "\\,")
	s = strings.ReplaceAll(s, "=", "\\=")
	return s
}

// escapeFieldString escapes a string field for InfluxDB line protocol.
func escapeFieldString(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	return s
}

func sortedServices(services map[int32]*Service) []*Service {
	var sorted []*Service
	for _, svc := range services {
		sorted = append(sorted, svc)
	}

	sortKey := strings.ToLower(strings.TrimSpace(*sortBy))
	switch sortKey {
	case "cpu":
		sort.Slice(sorted, func(i, j int) bool {
			if sorted[i].CPUPercent == sorted[j].CPUPercent {
				return sorted[i].Name < sorted[j].Name
			}
			return sorted[i].CPUPercent > sorted[j].CPUPercent
		})
	case "memory":
		sort.Slice(sorted, func(i, j int) bool {
			if sorted[i].MemBytes == sorted[j].MemBytes {
				return sorted[i].Name < sorted[j].Name
			}
			return sorted[i].MemBytes > sorted[j].MemBytes
		})
	case "io_r":
		sort.Slice(sorted, func(i, j int) bool {
			if sorted[i].IOReadKBps == sorted[j].IOReadKBps {
				return sorted[i].Name < sorted[j].Name
			}
			return sorted[i].IOReadKBps > sorted[j].IOReadKBps
		})
	case "io_w":
		sort.Slice(sorted, func(i, j int) bool {
			if sorted[i].IOWriteKBps == sorted[j].IOWriteKBps {
				return sorted[i].Name < sorted[j].Name
			}
			return sorted[i].IOWriteKBps > sorted[j].IOWriteKBps
		})
	default:
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i].Name < sorted[j].Name
		})
	}

	return sorted
}

// getCmdline returns a ps-like COMMAND string for the process.
func getCmdline(p *process.Process) string {
	if p == nil {
		return ""
	}
	cmdline, err := p.Cmdline()
	if err == nil && cmdline != "" {
		return cmdline
	}
	exe, _ := p.Exe()
	if exe != "" {
		return exe
	}
	name, _ := p.Name()
	return name
}

// hashDetailCmd returns a SHA-256 hex string for line protocol.
func hashDetailCmd(cmd string) string {
	if cmd == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(cmd))
	hexStr := hex.EncodeToString(sum[:])
	return hexStr
}

// ioRateCollectorConfig holds configuration for IO rate collection
type ioRateCollectorConfig struct {
	duration time.Duration // duration between two sample points
}

var defaultIOConfig = ioRateCollectorConfig{
	duration: 3 * time.Second, // collect 2 points with 3s interval
}

// collectServiceIORates starts a goroutine to collect IO rates by sampling
// IO counters multiple times and calculating the average rate.
// It blocks until all samples are collected and rates are calculated.
func collectServiceIORates(services map[int32]*Service) {
	collectServiceIORatesWithConfig(services, defaultIOConfig)
}

// collectServiceIORatesWithConfig collects IO rates with custom configuration
func collectServiceIORatesWithConfig(services map[int32]*Service, cfg ioRateCollectorConfig) {
	if len(services) == 0 {
		return
	}

	// Channel to receive final IO rates
	type ioRateResult struct {
		pid       int32
		readKBps  float64
		writeKBps float64
	}
	resultChan := make(chan ioRateResult, len(services))

	// Start goroutines for each service to collect IO samples
	for pid, svc := range services {
		go func(pid int32, svc *Service) {
			readKBps, writeKBps := sampleIORate(pid, cfg)
			resultChan <- ioRateResult{
				pid:       pid,
				readKBps:  readKBps,
				writeKBps: writeKBps,
			}
		}(pid, svc)
	}

	// Collect results from all goroutines
	for i := 0; i < len(services); i++ {
		result := <-resultChan
		if svc, ok := services[result.pid]; ok {
			svc.IOReadKBps = result.readKBps
			svc.IOWriteKBps = result.writeKBps
		}
	}
}

// sampleIORate collects 2 IO samples for a specific PID and returns KB/s rates
func sampleIORate(pid int32, cfg ioRateCollectorConfig) (readKBps, writeKBps float64) {
	p, err := process.NewProcess(pid)
	if err != nil {
		return 0, 0
	}

	// Collect first sample
	ioStart, err := p.IOCounters()
	if err != nil {
		return 0, 0
	}
	startTime := time.Now()

	// Wait for the configured duration
	time.Sleep(cfg.duration)

	// Collect second sample
	ioEnd, err := p.IOCounters()
	if err != nil {
		// Process may have exited
		return 0, 0
	}
	endTime := time.Now()

	// Calculate rate
	dt := endTime.Sub(startTime).Seconds()
	if dt <= 0 {
		return 0, 0
	}

	// Handle counter wraparound
	var readDelta, writeDelta uint64
	if ioEnd.ReadBytes >= ioStart.ReadBytes {
		readDelta = ioEnd.ReadBytes - ioStart.ReadBytes
	}
	if ioEnd.WriteBytes >= ioStart.WriteBytes {
		writeDelta = ioEnd.WriteBytes - ioStart.WriteBytes
	}

	readKBps = float64(readDelta) / 1024.0 / dt
	writeKBps = float64(writeDelta) / 1024.0 / dt

	return readKBps, writeKBps
}

// updateServiceIORates calculates per-service IO rates in KB/s (pidstat -d style).
// Deprecated: Use collectServiceIORates for more accurate sampling-based rates.
func updateServiceIORates(services map[int32]*Service, now time.Time) {
	for pid, svc := range services {
		prev, ok := prevServiceIO[pid]
		if ok {
			dt := now.Sub(prev.ts).Seconds()
			if dt > 0 {
				readDelta := svc.IOReadBytes
				if svc.IOReadBytes >= prev.readBytes {
					readDelta = svc.IOReadBytes - prev.readBytes
				}
				writeDelta := svc.IOWriteBytes
				if svc.IOWriteBytes >= prev.writeBytes {
					writeDelta = svc.IOWriteBytes - prev.writeBytes
				}
				svc.IOReadKBps = float64(readDelta) / 1024.0 / dt
				svc.IOWriteKBps = float64(writeDelta) / 1024.0 / dt
			}
		}
		prevServiceIO[pid] = ioSnapshot{
			readBytes:  svc.IOReadBytes,
			writeBytes: svc.IOWriteBytes,
			ts:         now,
		}
	}
}

// truncate truncates a string to max length
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
