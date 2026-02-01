// +build ignore
//
// eBPF XDP program for network traffic counting
// Compatible with kernel 4.15+ (avoids newer atomic instructions)
//
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>

// Filter rule structure
struct filter_rule {
    __u32 src_ip;       // Source IP (0 = any)
    __u32 dst_ip;       // Destination IP (0 = any)
    __u16 src_port;     // Source port (0 = any)
    __u16 dst_port;     // Destination port (0 = any)
    __u8  protocol;     // Protocol: 0=any, 6=TCP, 17=UDP
    __u8  action;       // 0=count, 1=drop, 2=pass
    __u8  enabled;      // 1=enabled, 0=disabled
    __u8  _pad;
};

#define MAX_RULES 16

// Flow key structure for tracking connections
struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u8  _pad[3];
};

// Flow stats structure for tracking packets and bytes
struct flow_stats {
    __u64 packets;
    __u64 bytes;
};

// Map to store dynamic filter rules (up to 16 rules)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_RULES);
    __type(key, __u32);
    __type(value, struct filter_rule);
} filter_rules SEC(".maps");

// Map to store packet/byte counts per flow (src_ip, dst_ip, src_port, dst_port)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct flow_key);
    __type(value, struct flow_stats);
} ip_stats SEC(".maps");

// Map for per-rule match counts
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_RULES);
    __type(key, __u32);
    __type(value, __u64);
} rule_stats SEC(".maps");

// Global config: 0=disabled, 1=enabled filtering
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} config SEC(".maps");

static __always_inline int match_rule(struct filter_rule *rule, __u32 src_ip, __u32 dst_ip, 
                                       __u16 src_port, __u16 dst_port, __u8 protocol) {
    if (!rule->enabled)
        return 0;
    if (rule->src_ip != 0 && rule->src_ip != src_ip)
        return 0;
    if (rule->dst_ip != 0 && rule->dst_ip != dst_ip)
        return 0;
    if (rule->protocol != 0 && rule->protocol != protocol)
        return 0;
    if (rule->src_port != 0 && rule->src_port != src_port)
        return 0;
    if (rule->dst_port != 0 && rule->dst_port != dst_port)
        return 0;
    return 1;
}

SEC("xdp")
int count_packets(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    // Parse IP header
    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->ihl < 5)
        return XDP_PASS;
    __u32 ihl_len = ip->ihl * 4;
    if ((void *)ip + ihl_len > data_end)
        return XDP_PASS;

    __u32 src_ip = ip->saddr;
    __u32 dst_ip = ip->daddr;
    __u8 protocol = ip->protocol;
    __u16 src_port = 0, dst_port = 0;

    // Parse TCP/UDP ports
    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ihl_len;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        src_port = __constant_ntohs(tcp->source);
        dst_port = __constant_ntohs(tcp->dest);
    } else if (protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + ihl_len;
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        src_port = __constant_ntohs(udp->source);
        dst_port = __constant_ntohs(udp->dest);
    }

    // Check if filtering is enabled
    __u32 cfg_key = 0;
    __u32 *filtering_enabled = bpf_map_lookup_elem(&config, &cfg_key);
    
    int action = 0; // default: count and pass
    int matched = 0; // track if any rule matched
    
    if (filtering_enabled && *filtering_enabled) {
#define CHECK_RULE(idx)                                                     \
        do {                                                                \
            __u32 i = (idx);                                                \
            struct filter_rule *rule =                                      \
                bpf_map_lookup_elem(&filter_rules, &i);                     \
            if (rule && match_rule(rule, src_ip, dst_ip,                    \
                                   src_port, dst_port, protocol)) {         \
                __u64 *count = bpf_map_lookup_elem(&rule_stats, &i);        \
                if (count)                                                  \
                    (*count)++;                                             \
                action = rule->action;                                      \
                matched = 1;                                                \
                goto out_rules;                                             \
            }                                                               \
        } while (0)

        CHECK_RULE(0);
        CHECK_RULE(1);
        CHECK_RULE(2);
        CHECK_RULE(3);
        CHECK_RULE(4);
        CHECK_RULE(5);
        CHECK_RULE(6);
        CHECK_RULE(7);
        CHECK_RULE(8);
        CHECK_RULE(9);
        CHECK_RULE(10);
        CHECK_RULE(11);
        CHECK_RULE(12);
        CHECK_RULE(13);
        CHECK_RULE(14);
        CHECK_RULE(15);

#undef CHECK_RULE
    }

out_rules:;

    // Update flow stats: 
    // - If filtering disabled: record ALL packets
    // - If filtering enabled: only record packets matching a rule
    if (!filtering_enabled || !*filtering_enabled || matched) {
        struct flow_key fkey = {
            .src_ip = src_ip,
            .dst_ip = dst_ip,
            .src_port = src_port,
            .dst_port = dst_port,
            .protocol = protocol,
        };
        __u64 pkt_len = data_end - data;
        struct flow_stats *stats = bpf_map_lookup_elem(&ip_stats, &fkey);
        if (stats) {
            // Use simple increment instead of atomic (kernel 5.4 compatible)
            // Note: May have slight inaccuracy under high concurrency
            stats->packets += 1;
            stats->bytes += pkt_len;
        } else {
            struct flow_stats new_stats = {
                .packets = 1,
                .bytes = pkt_len,
            };
            bpf_map_update_elem(&ip_stats, &fkey, &new_stats, BPF_ANY);
        }
    }

    // Apply action
    if (action == 1)
        return XDP_DROP;
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
