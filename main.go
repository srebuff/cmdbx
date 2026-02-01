// Package main provides the entry point for the agent_cmdb agent.
// This agent collects process/service information and network traffic data
// for CMDB (Configuration Management Database) purposes.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gops/agent_cmdb/probe"
)

// Version information (set by build flags)
var (
	Version   = "dev"
	BuildTime = "unknown"
	GitCommit = "unknown"
)

// Config holds the agent configuration
type Config struct {
	// General options
	InstanceID string
	InstanceIP string
	Verbose    bool
	Once       bool

	// Service collection options
	CollectServices bool
	ServiceInterval time.Duration
	IORateDuration  time.Duration
	SortBy          string
	OutputFormat    string // line, json
	TopN            int

	// Network collection options
	CollectNetwork   bool
	NetworkInterval  time.Duration
	NetworkInterface string
	CollectorType    string // auto, ebpf, gopacket

	// Output options
	OutputFile string
}

func main() {
	cfg := parseFlags()

	if cfg.Verbose {
		log.Printf("agent_cmdb %s (built: %s, commit: %s)", Version, BuildTime, GitCommit)
		log.Printf("Configuration: %+v", cfg)
	}

	// Setup signal handling for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		log.Printf("Received signal %v, shutting down...", sig)
		cancel()
	}()

	// Run the agent
	if err := run(ctx, cfg); err != nil {
		log.Fatalf("Error: %v", err)
	}
}

func parseFlags() *Config {
	cfg := &Config{}

	// Version flag
	showVersion := flag.Bool("version", false, "Show version information")

	// General options
	flag.StringVar(&cfg.InstanceID, "instance-id", "", "Instance ID (default: hostname)")
	flag.StringVar(&cfg.InstanceIP, "instance-ip", "", "Instance IP (default: auto-detect)")
	flag.BoolVar(&cfg.Verbose, "verbose", false, "Enable verbose logging")
	flag.BoolVar(&cfg.Once, "once", false, "Run once and exit")

	// Service collection options
	flag.BoolVar(&cfg.CollectServices, "services", true, "Collect service information")
	flag.DurationVar(&cfg.ServiceInterval, "service-interval", 60*time.Second, "Service collection interval")
	flag.DurationVar(&cfg.IORateDuration, "io-rate-duration", 3*time.Second, "IO rate sampling duration")
	flag.StringVar(&cfg.SortBy, "sort", "cpu", "Sort services by: name, cpu, memory, io_r, io_w")
	flag.IntVar(&cfg.TopN, "top", 0, "Show only top N services (0 = all)")

	// Network collection options
	flag.BoolVar(&cfg.CollectNetwork, "network", false, "Collect network traffic")
	flag.DurationVar(&cfg.NetworkInterval, "network-interval", 30*time.Second, "Network stats collection interval")
	flag.StringVar(&cfg.NetworkInterface, "interface", "", "Network interface (default: auto-detect)")
	flag.StringVar(&cfg.CollectorType, "collector", "auto", "Network collector: auto, ebpf, gopacket")

	// Output options
	flag.StringVar(&cfg.OutputFormat, "format", "line", "Output format: line, json")
	flag.StringVar(&cfg.OutputFile, "output", "", "Output file (default: stdout)")

	flag.Parse()

	if *showVersion {
		fmt.Printf("agent_cmdb %s\n", Version)
		fmt.Printf("Build Time: %s\n", BuildTime)
		fmt.Printf("Git Commit: %s\n", GitCommit)
		os.Exit(0)
	}

	return cfg
}

func run(ctx context.Context, cfg *Config) error {
	var output *os.File
	var err error

	// Setup output
	if cfg.OutputFile != "" {
		output, err = os.OpenFile(cfg.OutputFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return fmt.Errorf("failed to open output file: %w", err)
		}
		defer output.Close()
	} else {
		output = os.Stdout
	}

	// Initialize service collector
	var serviceCollector *probe.DefaultServiceCollector
	if cfg.CollectServices {
		opts := []probe.ServiceCollectorOption{
			probe.WithIORateDuration(cfg.IORateDuration),
			probe.WithVerbose(cfg.Verbose),
		}
		if cfg.InstanceID != "" {
			opts = append(opts, probe.WithInstanceID(cfg.InstanceID))
		}
		if cfg.InstanceIP != "" {
			opts = append(opts, probe.WithInstanceIP(cfg.InstanceIP))
		}
		serviceCollector = probe.NewServiceCollector(opts...)

		if cfg.Verbose {
			log.Printf("Service collector initialized")
		}
	}

	// Initialize network collector
	var networkCollector *probe.NetworkTrafficCollector
	if cfg.CollectNetwork {
		opts := []probe.NetworkCollectorOption{}
		if cfg.NetworkInterface != "" {
			opts = append(opts, probe.WithInterface(cfg.NetworkInterface))
		}
		if cfg.CollectorType != "auto" {
			switch cfg.CollectorType {
			case "ebpf":
				opts = append(opts, probe.WithCollectorType(probe.CollectorTypeEBPF))
			case "gopacket":
				opts = append(opts, probe.WithCollectorType(probe.CollectorTypeGoPacket))
			}
		}

		networkCollector, err = probe.NewNetworkTrafficCollector(opts...)
		if err != nil {
			return fmt.Errorf("failed to create network collector: %w", err)
		}

		if err := networkCollector.Start(); err != nil {
			return fmt.Errorf("failed to start network collector: %w", err)
		}
		defer func() {
			if err := networkCollector.Stop(); err != nil {
				log.Printf("Warning: failed to stop network collector: %v", err)
			}
		}()

		if cfg.Verbose {
			log.Printf("Network collector started (type: %s, interface: %s)",
				networkCollector.GetCollectorType(),
				networkCollector.GetInterfaceName())
		}
	}

	// Run once mode
	if cfg.Once {
		return collectOnce(cfg, serviceCollector, networkCollector, output)
	}

	// Continuous collection mode
	return collectLoop(ctx, cfg, serviceCollector, networkCollector, output)
}

func collectOnce(cfg *Config, serviceCollector *probe.DefaultServiceCollector, networkCollector *probe.NetworkTrafficCollector, output *os.File) error {
	timestamp := time.Now().UnixNano()

	// Collect services
	if cfg.CollectServices && serviceCollector != nil {
		services, err := serviceCollector.Collect()
		if err != nil {
			return fmt.Errorf("service collection failed: %w", err)
		}

		// Sort services
		sortServices(services, cfg.SortBy)

		// Apply top N filter
		if cfg.TopN > 0 && len(services) > cfg.TopN {
			services = services[:cfg.TopN]
		}

		// Output services
		if err := outputServices(services, cfg.OutputFormat, output, timestamp); err != nil {
			return fmt.Errorf("failed to output services: %w", err)
		}

		if cfg.Verbose {
			log.Printf("Collected %d services", len(services))
		}
	}

	// Collect network traffic
	if cfg.CollectNetwork && networkCollector != nil {
		// Wait a bit for some traffic to accumulate
		if cfg.Verbose {
			log.Printf("Waiting for network traffic collection...")
		}
		time.Sleep(cfg.NetworkInterval)

		traffic, err := networkCollector.GetStats()
		if err != nil {
			return fmt.Errorf("network collection failed: %w", err)
		}

		if err := outputNetworkTraffic(traffic, cfg.OutputFormat, output, cfg.InstanceID); err != nil {
			return fmt.Errorf("failed to output network traffic: %w", err)
		}

		if cfg.Verbose {
			log.Printf("Collected %d network flows", len(traffic))
		}
	}

	return nil
}

func collectLoop(ctx context.Context, cfg *Config, serviceCollector *probe.DefaultServiceCollector, networkCollector *probe.NetworkTrafficCollector, output *os.File) error {
	// Create tickers for collection intervals
	var serviceTicker *time.Ticker
	var networkTicker *time.Ticker

	if cfg.CollectServices && serviceCollector != nil {
		serviceTicker = time.NewTicker(cfg.ServiceInterval)
		defer serviceTicker.Stop()

		// Initial collection
		if err := collectAndOutputServices(cfg, serviceCollector, output); err != nil {
			log.Printf("Warning: initial service collection failed: %v", err)
		}
	}

	if cfg.CollectNetwork && networkCollector != nil {
		networkTicker = time.NewTicker(cfg.NetworkInterval)
		defer networkTicker.Stop()
	}

	for {
		select {
		case <-ctx.Done():
			log.Println("Shutting down collection loop...")
			return nil

		case <-func() <-chan time.Time {
			if serviceTicker != nil {
				return serviceTicker.C
			}
			return nil
		}():
			if err := collectAndOutputServices(cfg, serviceCollector, output); err != nil {
				log.Printf("Warning: service collection failed: %v", err)
			}

		case <-func() <-chan time.Time {
			if networkTicker != nil {
				return networkTicker.C
			}
			return nil
		}():
			if err := collectAndOutputNetwork(cfg, networkCollector, output); err != nil {
				log.Printf("Warning: network collection failed: %v", err)
			}
		}
	}
}

func collectAndOutputServices(cfg *Config, serviceCollector *probe.DefaultServiceCollector, output *os.File) error {
	timestamp := time.Now().UnixNano()

	services, err := serviceCollector.Collect()
	if err != nil {
		return err
	}

	sortServices(services, cfg.SortBy)

	if cfg.TopN > 0 && len(services) > cfg.TopN {
		services = services[:cfg.TopN]
	}

	if cfg.Verbose {
		log.Printf("Collected %d services", len(services))
	}

	return outputServices(services, cfg.OutputFormat, output, timestamp)
}

func collectAndOutputNetwork(cfg *Config, networkCollector *probe.NetworkTrafficCollector, output *os.File) error {
	traffic, err := networkCollector.GetStats()
	if err != nil {
		return err
	}

	if cfg.Verbose {
		log.Printf("Collected %d network flows", len(traffic))
	}

	return outputNetworkTraffic(traffic, cfg.OutputFormat, output, cfg.InstanceID)
}

func sortServices(services []probe.Service, sortBy string) {
	switch sortBy {
	case "name":
		sortByName(services)
	case "cpu":
		sortByCPU(services)
	case "memory":
		sortByMemory(services)
	case "io_r":
		sortByIORead(services)
	case "io_w":
		sortByIOWrite(services)
	default:
		sortByName(services)
	}
}

func sortByName(services []probe.Service) {
	for i := 0; i < len(services)-1; i++ {
		for j := i + 1; j < len(services); j++ {
			if services[i].Name > services[j].Name {
				services[i], services[j] = services[j], services[i]
			}
		}
	}
}

func sortByCPU(services []probe.Service) {
	for i := 0; i < len(services)-1; i++ {
		for j := i + 1; j < len(services); j++ {
			if services[i].CPUPercent < services[j].CPUPercent {
				services[i], services[j] = services[j], services[i]
			}
		}
	}
}

func sortByMemory(services []probe.Service) {
	for i := 0; i < len(services)-1; i++ {
		for j := i + 1; j < len(services); j++ {
			if services[i].MemBytes < services[j].MemBytes {
				services[i], services[j] = services[j], services[i]
			}
		}
	}
}

func sortByIORead(services []probe.Service) {
	for i := 0; i < len(services)-1; i++ {
		for j := i + 1; j < len(services); j++ {
			if services[i].IOReadKBps < services[j].IOReadKBps {
				services[i], services[j] = services[j], services[i]
			}
		}
	}
}

func sortByIOWrite(services []probe.Service) {
	for i := 0; i < len(services)-1; i++ {
		for j := i + 1; j < len(services); j++ {
			if services[i].IOWriteKBps < services[j].IOWriteKBps {
				services[i], services[j] = services[j], services[i]
			}
		}
	}
}

func outputServices(services []probe.Service, format string, output *os.File, timestamp int64) error {
	switch format {
	case "json":
		encoder := json.NewEncoder(output)
		encoder.SetIndent("", "  ")
		return encoder.Encode(services)
	case "line":
		for _, svc := range services {
			// Update timestamp for line protocol output
			svc.Timestamp = timestamp
			line := probe.FormatLineProtocol(svc)
			fmt.Fprintln(output, line)
		}
		return nil
	default:
		return fmt.Errorf("unknown output format: %s", format)
	}
}

func outputNetworkTraffic(traffic []probe.NetworkTraffic, format string, output *os.File, instanceID string) error {
	switch format {
	case "json":
		encoder := json.NewEncoder(output)
		encoder.SetIndent("", "  ")
		return encoder.Encode(traffic)
	case "line":
		for _, t := range traffic {
			line := formatNetworkTrafficLine(t, instanceID)
			fmt.Fprintln(output, line)
		}
		return nil
	default:
		return fmt.Errorf("unknown output format: %s", format)
	}
}

// formatNetworkTrafficLine formats network traffic as InfluxDB line protocol
func formatNetworkTrafficLine(t probe.NetworkTraffic, instanceID string) string {
	// Format: network_traffic,instance_id=<id>,src_ip=<ip>,dst_ip=<ip>,protocol=<proto> src_port=<port>i,dst_port=<port>i,packets=<n>i,bytes=<n>i <timestamp>
	tags := fmt.Sprintf("network_traffic,instance_id=%s,src_ip=%s,dst_ip=%s,protocol=%s",
		escapeTag(instanceID),
		escapeTag(t.SrcIP),
		escapeTag(t.DstIP),
		escapeTag(t.Protocol))

	fields := fmt.Sprintf("src_port=%di,dst_port=%di,packets=%di,bytes=%di",
		t.SrcPort,
		t.DstPort,
		t.Packets,
		t.Bytes)

	timestamp := t.Timestamp.UnixNano()

	return fmt.Sprintf("%s %s %d", tags, fields, timestamp)
}

// escapeTag escapes special characters in InfluxDB line protocol tag values
func escapeTag(s string) string {
	s = strings.ReplaceAll(s, " ", "\\ ")
	s = strings.ReplaceAll(s, ",", "\\,")
	s = strings.ReplaceAll(s, "=", "\\=")
	return s
}
