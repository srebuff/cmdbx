package probe

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/process"
)

// DefaultServiceCollector implements ServiceCollector interface
type DefaultServiceCollector struct {
	instanceID     string
	instanceIP     string
	ioRateDuration time.Duration
	verbose        bool
}

// ServiceCollectorOption is a functional option for DefaultServiceCollector
type ServiceCollectorOption func(*DefaultServiceCollector)

// WithInstanceID sets the instance ID
func WithInstanceID(id string) ServiceCollectorOption {
	return func(c *DefaultServiceCollector) {
		c.instanceID = id
	}
}

// WithInstanceIP sets the instance IP
func WithInstanceIP(ip string) ServiceCollectorOption {
	return func(c *DefaultServiceCollector) {
		c.instanceIP = ip
	}
}

// WithIORateDuration sets the IO rate sampling duration
func WithIORateDuration(d time.Duration) ServiceCollectorOption {
	return func(c *DefaultServiceCollector) {
		c.ioRateDuration = d
	}
}

// WithVerbose enables verbose logging
func WithVerbose(v bool) ServiceCollectorOption {
	return func(c *DefaultServiceCollector) {
		c.verbose = v
	}
}

// NewServiceCollector creates a new DefaultServiceCollector
func NewServiceCollector(opts ...ServiceCollectorOption) *DefaultServiceCollector {
	c := &DefaultServiceCollector{
		ioRateDuration: 3 * time.Second,
	}

	for _, opt := range opts {
		opt(c)
	}

	// Auto-detect instance ID if not provided
	if c.instanceID == "" {
		hostname, _ := os.Hostname()
		c.instanceID = hostname
	}

	// Auto-detect instance IP if not provided
	if c.instanceIP == "" {
		c.instanceIP = getInstanceIP()
	}

	return c
}

// SetInstanceID sets the instance ID for tagging
func (c *DefaultServiceCollector) SetInstanceID(id string) {
	c.instanceID = id
}

// SetInstanceIP sets the instance IP for tagging
func (c *DefaultServiceCollector) SetInstanceIP(ip string) {
	c.instanceIP = ip
}

// processData holds intermediate process information
type processData struct {
	pid  int32
	ppid int32
	name string
	exe  string
	proc *process.Process
}

// Collect gathers all services and returns them
func (c *DefaultServiceCollector) Collect() ([]Service, error) {
	services := make(map[int32]*Service)
	timestamp := time.Now().UnixNano()

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
				InstanceID:  c.instanceID,
				InstanceIP:  c.instanceIP,
				RootPID:     rootPid,
				PID:         rootPid,
				Name:        rootData.name,
				BinPath:     rootData.exe,
				DetailCmd:   hashDetailCmd(detailCmd),
				StartMode:   startMode,
				ContainerID: getContainerID(rootPid),
				ListenPorts: []uint32{},
				Timestamp:   timestamp,
			}
			services[rootPid] = svc
		}

		// Only aggregate if same executable (or root itself)
		if pdata.exe == svc.BinPath || pid == rootPid {
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

	// Collect IO rates
	c.collectServiceIORates(services)

	// Calculate derived fields and convert to slice
	result := make([]Service, 0, len(services))
	for _, svc := range services {
		svc.IOReadMB = float64(svc.IOReadBytes) / 1024 / 1024
		svc.IOWriteMB = float64(svc.IOWriteBytes) / 1024 / 1024
		result = append(result, *svc)
	}

	// Sort by name
	sort.Slice(result, func(i, j int) bool {
		return result[i].Name < result[j].Name
	})

	return result, nil
}

// collectServiceIORates collects IO rates by sampling
func (c *DefaultServiceCollector) collectServiceIORates(services map[int32]*Service) {
	if len(services) == 0 || c.ioRateDuration == 0 {
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
	for pid := range services {
		go func(pid int32) {
			readKBps, writeKBps := sampleIORate(pid, c.ioRateDuration)
			resultChan <- ioRateResult{
				pid:       pid,
				readKBps:  readKBps,
				writeKBps: writeKBps,
			}
		}(pid)
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
func sampleIORate(pid int32, duration time.Duration) (readKBps, writeKBps float64) {
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
	time.Sleep(duration)

	// Collect second sample
	ioEnd, err := p.IOCounters()
	if err != nil {
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

// processMetrics holds collected metrics for a process
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

	// CPU percent
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
			_, _ = fmt.Sscanf(line, "Tgid:\t%d", &tgid)
		}
		if strings.HasPrefix(line, "Pid:") {
			_, _ = fmt.Sscanf(line, "Pid:\t%d", &pidVal)
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

	// Skip container infrastructure processes
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
		// 3. Parent not in our process list
		if ppid <= 1 {
			return current
		}

		parentData := processInfo[ppid]
		if parentData == nil {
			return current
		}

		// For Docker containers: stop if parent is container infrastructure
		if inContainer && isContainerInfraProcess(parentData.name) {
			return current
		}

		// Check if parent has different executable
		if pdata.exe != parentData.exe {
			return current
		}

		current = ppid
	}
}

// getStartMode detects how a process was started
func getStartMode(pid int32) string {
	cgroupPath := fmt.Sprintf("/proc/%d/cgroup", pid)
	data, err := os.ReadFile(cgroupPath)
	if err != nil {
		return "native"
	}

	cgroupStr := string(data)

	// Check for Kubernetes
	if strings.Contains(cgroupStr, "kubepods") {
		return "k8s"
	}

	// Check for Docker/Containerd
	if strings.Contains(cgroupStr, "docker") ||
		strings.Contains(cgroupStr, "containerd") {
		return "docker"
	}

	// Check for systemd
	if strings.Contains(cgroupStr, ".service") ||
		strings.Contains(cgroupStr, "system.slice") {
		return "systemd"
	}

	// Check if parent is systemd (PID 1)
	ppid := getPPID(pid)
	if ppid == 1 {
		return "systemd"
	}

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
	statStr := string(data)
	lastParen := strings.LastIndex(statStr, ")")
	if lastParen == -1 || lastParen+2 >= len(statStr) {
		return 0
	}

	fields := strings.Fields(statStr[lastParen+2:])
	if len(fields) < 2 {
		return 0
	}

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

// getCmdline returns a ps-like COMMAND string for the process
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

// hashDetailCmd returns a SHA-256 hex string
func hashDetailCmd(cmd string) string {
	if cmd == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(cmd))
	return hex.EncodeToString(sum[:])
}

// FormatPorts formats a slice of ports as a comma-separated string
func FormatPorts(ports []uint32) string {
	if len(ports) == 0 {
		return ""
	}

	strs := make([]string, len(ports))
	for i, p := range ports {
		strs[i] = strconv.FormatUint(uint64(p), 10)
	}
	return strings.Join(strs, ",")
}

// FormatLineProtocol formats a service as InfluxDB line protocol
func FormatLineProtocol(svc Service) string {
	portsStr := FormatPorts(svc.ListenPorts)
	name := escapeTagValue(svc.Name)
	binPath := escapeTagValue(svc.BinPath)
	detailCmd := escapeTagValue(svc.DetailCmd)

	// Build container_id tag only if present
	containerTag := ""
	if svc.ContainerID != "" {
		containerTag = ",container_id=" + escapeTagValue(svc.ContainerID)
	}

	return fmt.Sprintf(
		"services,instance_id=%s,name=%s,instance_ip=%s,bin_path=%s,start_mode=%s,detail_cmd=%s%s "+
			"pid=%di,listen_ports=\"%s\",cpu_pct=%.2f,mem_bytes=%di,io_read_bytes=%di,io_write_bytes=%di,"+
			"io_read_mb=%.2f,io_write_mb=%.2f,io_read_kbps=%.2f,io_write_kbps=%.2f,root_pid=%di,child_count=%di %d",
		svc.InstanceID,
		name,
		svc.InstanceIP,
		binPath,
		svc.StartMode,
		detailCmd,
		containerTag,
		svc.PID,
		portsStr,
		svc.CPUPercent,
		svc.MemBytes,
		svc.IOReadBytes,
		svc.IOWriteBytes,
		svc.IOReadMB,
		svc.IOWriteMB,
		svc.IOReadKBps,
		svc.IOWriteKBps,
		svc.RootPID,
		svc.ChildCount,
		svc.Timestamp,
	)
}

// escapeTagValue escapes special characters for InfluxDB line protocol tags
func escapeTagValue(s string) string {
	s = strings.ReplaceAll(s, " ", "\\ ")
	s = strings.ReplaceAll(s, ",", "\\,")
	s = strings.ReplaceAll(s, "=", "\\=")
	return s
}
