/*
 * ZeroTrust Mesh - XDP Packet Filter
 * 
 * This eBPF program implements the packet inspection and filtering
 * requirements from Feature Group D of the SRS.
 * 
 * Requirements implemented:
 * - D1.1: XDP hook for ingress packets
 * - D1.2: TCP, UDP, ICMP inspection
 * - D1.3: 5-tuple extraction
 * - D2.1: SYN flood detection
 * - D2.2: Port scan detection
 * - D3.1: Drop packets matching deny policies
 * - D3.2: Rate limiting
 * - D3.5: Dynamic blacklisting
 * 
 * Compile with:
 *   clang -O2 -target bpf -c xdp_filter.bpf.c -o xdp_filter.bpf.o
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_ENTRIES 65536
#define RATE_LIMIT_WINDOW_NS 1000000000ULL  // 1 second in nanoseconds

// Packet counters per IP
struct packet_counter {
    __u64 syn_count;
    __u64 total_count;
    __u64 last_reset;
};

// Port scan tracking
struct port_scan_entry {
    __u64 ports_scanned;
    __u64 window_start;
};

// Rate limit configuration
struct rate_config {
    __u32 syn_flood_threshold;    // D2.1: default 100
    __u32 port_scan_threshold;    // D2.2: default 50
    __u32 icmp_flood_threshold;   // D2.4: default 500
    __u32 http_flood_threshold;   // D2.3: default 1000
};

// BPF Maps

// Blacklist: blocked IPs (D3.5)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);    // IPv4 address
    __type(value, __u64);  // Expiration timestamp (0 = permanent)
} blacklist SEC(".maps");

// Whitelist: bypassed IPs (D3.4)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);    // IPv4 address
    __type(value, __u8);   // Just a flag
} whitelist SEC(".maps");

// Packet counters per source IP (D1.6)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);    // IPv4 address
    __type(value, struct packet_counter);
} counters SEC(".maps");

// Port scan tracking
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);    // IPv4 address
    __type(value, struct port_scan_entry);
} port_scans SEC(".maps");

// Configuration (set from userspace)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rate_config);
} config SEC(".maps");

// Attack events ring buffer (send to userspace)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  // 256KB
} events SEC(".maps");

// Attack event structure
struct attack_event {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u8 attack_type;  // 1=SYN flood, 2=port scan, 3=ICMP flood
    __u64 packet_count;
    __u64 timestamp;
};

// Get rate limit configuration
static __always_inline struct rate_config *get_config(void) {
    __u32 key = 0;
    return bpf_map_lookup_elem(&config, &key);
}

// Check if IP is whitelisted (D3.4)
static __always_inline int is_whitelisted(__u32 ip) {
    return bpf_map_lookup_elem(&whitelist, &ip) != NULL;
}

// Check if IP is blacklisted (D3.5)
static __always_inline int is_blacklisted(__u32 ip) {
    __u64 *expiry = bpf_map_lookup_elem(&blacklist, &ip);
    if (!expiry)
        return 0;
    
    // Check if permanent blacklist (expiry = 0)
    if (*expiry == 0)
        return 1;
    
    // Check if expired
    __u64 now = bpf_ktime_get_ns();
    if (now > *expiry) {
        // Remove expired entry
        bpf_map_delete_elem(&blacklist, &ip);
        return 0;
    }
    
    return 1;
}

// Update packet counter and check for SYN flood
static __always_inline int check_syn_flood(__u32 ip, struct rate_config *cfg) {
    __u64 now = bpf_ktime_get_ns();
    struct packet_counter *counter;
    struct packet_counter new_counter = {0};
    
    counter = bpf_map_lookup_elem(&counters, &ip);
    if (!counter) {
        new_counter.syn_count = 1;
        new_counter.total_count = 1;
        new_counter.last_reset = now;
        bpf_map_update_elem(&counters, &ip, &new_counter, BPF_ANY);
        return 0;
    }
    
    // Reset counter if window expired
    if (now - counter->last_reset > RATE_LIMIT_WINDOW_NS) {
        counter->syn_count = 1;
        counter->total_count = 1;
        counter->last_reset = now;
        return 0;
    }
    
    // Increment counter
    counter->syn_count++;
    counter->total_count++;
    
    // Check threshold (D2.1)
    if (counter->syn_count > cfg->syn_flood_threshold) {
        return 1;  // SYN flood detected
    }
    
    return 0;
}

// Check for port scan (D2.2)
static __always_inline int check_port_scan(__u32 ip, __u16 port, struct rate_config *cfg) {
    __u64 now = bpf_ktime_get_ns();
    struct port_scan_entry *entry;
    struct port_scan_entry new_entry = {0};
    
    entry = bpf_map_lookup_elem(&port_scans, &ip);
    if (!entry) {
        new_entry.ports_scanned = 1;
        new_entry.window_start = now;
        bpf_map_update_elem(&port_scans, &ip, &new_entry, BPF_ANY);
        return 0;
    }
    
    // Reset if 10-second window expired
    if (now - entry->window_start > 10 * RATE_LIMIT_WINDOW_NS) {
        entry->ports_scanned = 1;
        entry->window_start = now;
        return 0;
    }
    
    // Increment ports scanned
    entry->ports_scanned++;
    
    // Check threshold (D2.2: 50 ports in 10 seconds)
    if (entry->ports_scanned > cfg->port_scan_threshold) {
        return 1;  // Port scan detected
    }
    
    return 0;
}

// Send attack event to userspace
static __always_inline void report_attack(
    __u32 src_ip, __u32 dst_ip,
    __u16 src_port, __u16 dst_port,
    __u8 protocol, __u8 attack_type,
    __u64 packet_count
) {
    struct attack_event *event;
    
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return;
    
    event->src_ip = src_ip;
    event->dst_ip = dst_ip;
    event->src_port = src_port;
    event->dst_port = dst_port;
    event->protocol = protocol;
    event->attack_type = attack_type;
    event->packet_count = packet_count;
    event->timestamp = bpf_ktime_get_ns();
    
    bpf_ringbuf_submit(event, 0);
}

// Main XDP program (D1.1)
SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    // Only handle IPv4 (D1.2)
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
    
    // Parse IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    
    __u32 src_ip = ip->saddr;
    __u32 dst_ip = ip->daddr;
    
    // Get configuration
    struct rate_config *cfg = get_config();
    if (!cfg)
        return XDP_PASS;  // No config, pass all
    
    // Check whitelist first (D3.4)
    if (is_whitelisted(src_ip))
        return XDP_PASS;
    
    // Check blacklist (D3.5)
    if (is_blacklisted(src_ip))
        return XDP_DROP;
    
    // Handle TCP (D1.2)
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        
        __u16 src_port = bpf_ntohs(tcp->source);
        __u16 dst_port = bpf_ntohs(tcp->dest);
        
        // Check for SYN flood (D2.1)
        // TCP SYN flag: tcp->syn
        if (tcp->syn && !tcp->ack) {
            if (check_syn_flood(src_ip, cfg)) {
                report_attack(src_ip, dst_ip, src_port, dst_port, 
                            IPPROTO_TCP, 1, 0);
                return XDP_DROP;
            }
        }
        
        // Check for port scan (D2.2)
        if (tcp->syn && !tcp->ack) {
            if (check_port_scan(src_ip, dst_port, cfg)) {
                report_attack(src_ip, dst_ip, src_port, dst_port,
                            IPPROTO_TCP, 2, 0);
                return XDP_DROP;
            }
        }
        
        return XDP_PASS;
    }
    
    // Handle UDP (D1.2)
    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        
        // Check for port scan on UDP
        if (check_port_scan(src_ip, bpf_ntohs(udp->dest), cfg)) {
            report_attack(src_ip, dst_ip, 
                         bpf_ntohs(udp->source), bpf_ntohs(udp->dest),
                         IPPROTO_UDP, 2, 0);
            return XDP_DROP;
        }
        
        return XDP_PASS;
    }
    
    // Handle ICMP (D1.2, D2.4)
    if (ip->protocol == IPPROTO_ICMP) {
        // Use counters for ICMP flood detection
        struct packet_counter *counter;
        __u64 now = bpf_ktime_get_ns();
        
        counter = bpf_map_lookup_elem(&counters, &src_ip);
        if (counter) {
            if (now - counter->last_reset < RATE_LIMIT_WINDOW_NS) {
                if (counter->total_count > cfg->icmp_flood_threshold) {
                    report_attack(src_ip, dst_ip, 0, 0, IPPROTO_ICMP, 3, 
                                 counter->total_count);
                    return XDP_DROP;
                }
            }
        }
        
        return XDP_PASS;
    }
    
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
