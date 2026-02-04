package main

import (
	"testing"
	"time"

	"github.com/gops/agent_cmdb/probe"
)

func TestApplyCollectIntervalOverrides(t *testing.T) {
	cfg := &Config{
		ServiceInterval: 10 * time.Second,
		NetworkInterval: 20 * time.Second,
		CollectInterval: 3 * time.Second,
	}

	applyCollectInterval(cfg)

	if cfg.ServiceInterval != 3*time.Second {
		t.Fatalf("ServiceInterval = %s, want %s", cfg.ServiceInterval, 3*time.Second)
	}
	if cfg.NetworkInterval != 3*time.Second {
		t.Fatalf("NetworkInterval = %s, want %s", cfg.NetworkInterval, 3*time.Second)
	}
}

func TestApplyCollectIntervalNoop(t *testing.T) {
	cfg := &Config{
		ServiceInterval: 10 * time.Second,
		NetworkInterval: 20 * time.Second,
		CollectInterval: 0,
	}

	applyCollectInterval(cfg)

	if cfg.ServiceInterval != 10*time.Second {
		t.Fatalf("ServiceInterval = %s, want %s", cfg.ServiceInterval, 10*time.Second)
	}
	if cfg.NetworkInterval != 20*time.Second {
		t.Fatalf("NetworkInterval = %s, want %s", cfg.NetworkInterval, 20*time.Second)
	}
}

func TestUseSharedTicker(t *testing.T) {
	cfg := &Config{
		CollectServices: true,
		CollectNetwork:  true,
		CollectInterval: 2 * time.Second,
	}

	if useSharedTicker(cfg, nil, nil) {
		t.Fatal("useSharedTicker() should be false with nil collectors")
	}

	if !useSharedTicker(cfg, &probe.DefaultServiceCollector{}, &probe.NetworkTrafficCollector{}) {
		t.Fatal("useSharedTicker() should be true with non-nil collectors and interval")
	}
}
