//go:build ignore
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>

/*
 * PHANTOM GRID - eBPF KERNEL MODULE
 * XDP Layer for Transparent Redirection & Stealth Trapping
 * 
 * ALL CONFIGURATION IS AUTO-GENERATED FROM Go CONFIG
 * Do not edit constants manually - update internal/config/config.go and ports.go instead
 * Run 'make generate-config' to regenerate
 */

// Include auto-generated configuration (constants and port definitions)
// This file is generated from internal/config/config.go and ports.go by 'make generate-config'
// ALL ports, SPA settings, and OS fingerprint values are defined in phantom_ports.h
#include "phantom_ports.h"

// Include auto-generated port checking functions
// This file is generated from internal/config/ports.go by 'make generate-config'
#include "phantom_ports_functions.c"

// Standard protocol definitions (not configurable, part of IP specification)
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif
#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 1
#endif

// MAP DEFINITIONS
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} attack_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} stealth_drops SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} os_mutations SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100);
    __type(key, __be32);
    __type(value, __u64);
} spa_whitelist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} spa_auth_success SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} spa_auth_failed SEC(".maps");

// Connection tracking map for transparent redirection
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key, __u64);
    __type(value, __be16);
} redirect_map SEC(".maps");

static __always_inline void mutate_os_personality(struct iphdr *ip, struct tcphdr *tcp) {
    __u16 src_port = bpf_ntohs(tcp->source);
    __u8 os_type = (src_port % 4);
    
    __u8 old_ttl = ip->ttl;
    __u8 new_ttl;
    __be16 old_window = tcp->window;
    __be16 new_window;
    
    switch (os_type) {
        case 0: new_ttl = TTL_WINDOWS; new_window = bpf_htons(WINDOW_WINDOWS); break;
        case 1: new_ttl = TTL_LINUX; new_window = bpf_htons(WINDOW_LINUX); break;
        case 2: new_ttl = TTL_FREEBSD; new_window = bpf_htons(WINDOW_FREEBSD); break;
        case 3: new_ttl = TTL_SOLARIS; new_window = bpf_htons(WINDOW_LINUX); break;
        default: new_ttl = TTL_WINDOWS; new_window = bpf_htons(WINDOW_WINDOWS);
    }
    
    if (old_ttl != new_ttl) {
        ip->ttl = new_ttl;
        ip->check = 0; // Kernel will recalculate checksum
    }
    
    if (old_window != new_window) {
        tcp->window = new_window;
        tcp->check = 0; // Kernel will recalculate checksum
    }
    
    __u32 key = 0;
    __u64 *val = bpf_map_lookup_elem(&os_mutations, &key);
    if (val) __sync_fetch_and_add(val, 1);
}

static __always_inline int is_spa_whitelisted(__be32 src_ip) {
    __u64 *expiry = bpf_map_lookup_elem(&spa_whitelist, &src_ip);
    if (expiry == NULL) {
        return 0;
    }
    
    // Check if whitelist entry has expired
    __u64 current_time = bpf_ktime_get_ns();
    if (current_time > *expiry) {
        // Entry expired, remove it
        bpf_map_delete_elem(&spa_whitelist, &src_ip);
        return 0;
    }
    
    return 1;
}

// Port checking functions are now auto-generated in phantom_ports_functions.c
// Do not define is_critical_asset_port() or is_fake_port() here - they are included above

// Verify magic packet token
// This function only verifies the default token (SPA_TOKEN_LEN bytes)
// For custom tokens with different lengths, packet will be passed to user-space
static __always_inline int verify_magic_packet(void *payload, void *data_end) {
    // Check if payload is long enough
    if ((void *)payload + SPA_TOKEN_LEN > data_end) return 0;
    
    // Calculate actual payload length
    __u32 payload_len = (__u32)((void *)data_end - (void *)payload);
    
    // Only verify if payload length matches default token length
    // If length doesn't match, return 0 (not matched) so packet is passed to user-space
    // User-space will handle tokens with different lengths
    if (payload_len != SPA_TOKEN_LEN) {
        return 0; // Length mismatch - pass to user-space for custom token handling
    }

    const char *token = SPA_SECRET_TOKEN;
    unsigned char *p = (unsigned char *)payload;
    const unsigned char *t = (const unsigned char *)token;
    
    #pragma clang loop unroll(full)
    for (int i = 0; i < SPA_TOKEN_LEN; i++) {
        if (p[i] != t[i]) return 0;
    }
    return 1;
}

static __always_inline void spa_whitelist_ip(__be32 src_ip) {
    // Calculate expiry time: current time + duration
    __u64 current_time = bpf_ktime_get_ns();
    __u64 expiry = current_time + SPA_WHITELIST_DURATION_NS;
    
    bpf_map_update_elem(&spa_whitelist, &src_ip, &expiry, BPF_ANY);
    
    __u32 key = 0;
    __u64 *val = bpf_map_lookup_elem(&spa_auth_success, &key);
    if (val) __sync_fetch_and_add(val, 1);
}

static __always_inline int is_stealth_scan(struct tcphdr *tcp) {
    __u8 *flags_byte = ((__u8 *)tcp + 13);
    __u8 flags = *flags_byte;
    
    __u8 fin = flags & 0x01;
    __u8 syn = flags & 0x02;
    __u8 rst = flags & 0x04;
    __u8 psh = flags & 0x08;
    __u8 ack = flags & 0x10;
    __u8 urg = flags & 0x20;
    
    if (fin && urg && psh && !syn && !rst) return 1; // Xmas scan
    if (flags == 0) return 1; // Null scan
    if (fin && !syn && !rst && !psh && !ack && !urg) return 1; // FIN scan
    if (ack && !syn && !fin && !rst) return 1; // ACK scan
    return 0;
}

SEC("xdp")
int phantom_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    __be32 src_ip = ip->saddr;

    // Allow all ICMP traffic (ping, etc.)
    if (ip->protocol == IPPROTO_ICMP) {
        return XDP_PASS;
    }

    // SPA Logic (UDP)
    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(ip + 1);
        if ((void *)(udp + 1) > data_end) return XDP_PASS;
        
        // Allow DNS (UDP port 53) - critical for internet connectivity
        if (udp->dest == bpf_htons(53) || udp->source == bpf_htons(53)) {
            return XDP_PASS;
        }
        
        if (udp->dest == bpf_htons(SPA_MAGIC_PORT)) {
            void *payload = (void *)(udp + 1);
            __u32 payload_len = (__u32)((void *)data_end - (void *)payload);
            
            // Check if packet matches default token (exact length match)
            if (verify_magic_packet(payload, data_end)) {
                // Default token matched (21 bytes) - whitelist in eBPF
                spa_whitelist_ip(src_ip);
                return XDP_DROP;
            } else {
                // Token doesn't match default - could be:
                // 1. Dynamic SPA packet (starts with version byte 1)
                // 2. Custom static token with different length
                // 3. Invalid packet
                
                // Check if it's a dynamic packet (starts with version byte 1)
                if (payload_len > 0) {
                    __u8 first_byte = *((__u8 *)payload);
                    // Dynamic packets start with version byte 1
                    if (first_byte == 1) {
                        // This is likely a dynamic SPA packet - pass to user-space for verification
                        // Don't count as failed yet - user-space will verify and count if needed
                        return XDP_PASS;
                    }
                }
                
                // Not default token and not dynamic packet
                // This could be:
                // 1. Custom static token with different length (e.g., 4 bytes, 10 bytes, etc.)
                // 2. Invalid packet
                // Pass to user-space to let it handle - user-space supports tokens with any length
                // Don't count as failed yet - user-space will verify and count if needed
                return XDP_PASS;
            }
        }
        return XDP_PASS;
    }

    // TCP Logic (Defense & Redirection)
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(ip + 1);
        if ((void *)(tcp + 1) > data_end) return XDP_PASS;

        // Extract TCP flags
        __u8 *flags_byte = ((__u8 *)tcp + 13);
        __u8 flags = *flags_byte;
        __u8 syn = flags & 0x02;
        __u8 ack = flags & 0x10;
        __u8 rst = flags & 0x04;
        __u8 fin = flags & 0x01;

        // Allow established connections (ACK without SYN) - critical for internet
        // This allows outbound connections and established inbound connections
        if (ack && !syn) {
            return XDP_PASS;
        }

        // Allow RST and FIN packets (connection teardown)
        if (rst || fin) {
            return XDP_PASS;
        }

        // Pass all packets to honeypot port (before other checks)
        if (tcp->dest == bpf_htons(HONEYPOT_PORT)) {
            return XDP_PASS;
        }

        // Get destination port
        __be16 dest_port = tcp->dest;
        __be16 src_port = tcp->source;

        // Allow common outbound ports (HTTP, HTTPS) - critical for internet
        // Also allow high ports (ephemeral ports > 32768) for outbound connections
        if (dest_port == bpf_htons(80) || dest_port == bpf_htons(443)) {
            return XDP_PASS;
        }

        // Allow high ports (ephemeral ports) - these are typically outbound connections
        // Ephemeral ports are usually > 32768, but we use > 1024 to be safe
        if (bpf_ntohs(dest_port) > 1024 && bpf_ntohs(src_port) < 1024) {
            // Outbound connection from server (source port < 1024, dest port > 1024)
            return XDP_PASS;
        }

        // Protect ALL Critical Asset ports (Phantom Protocol) - only allow if whitelisted via SPA
        // This includes: SSH (22), MySQL (3306), PostgreSQL (5432), MongoDB (27017), 
        // Redis (6379), Admin Panels (8080, 8443, 9000)
        // IMPORTANT: Check critical ports BEFORE fake ports to protect REAL services
        // If a port is both critical AND fake, priority goes to protection (SPA required)
        if (is_critical_asset_port(tcp->dest)) {
            if (!is_spa_whitelisted(src_ip)) {
                return XDP_DROP;  // Server appears "dead" to attackers
            }
            return XDP_PASS;  // Whitelisted IP can access
        }

        // Pass fake ports directly (The Mirage) - these are honeypot ports
        // These ports are NOT critical assets, so they can be accessed without SPA
        if (is_fake_port(tcp->dest)) {
            // Only count on SYN packets to avoid spam
            if (syn) {
                __u32 key = 0;
                __u64 *val = bpf_map_lookup_elem(&attack_stats, &key);
                if (val) __sync_fetch_and_add(val, 1);
            }
            return XDP_PASS;
        }

        // Block stealth scans (only on SYN packets)
        if (syn && is_stealth_scan(tcp)) {
            __u32 key = 0;
            __u64 *val = bpf_map_lookup_elem(&stealth_drops, &key);
            if (val) __sync_fetch_and_add(val, 1);
            return XDP_DROP;
        }

        // For other SYN packets (new inbound connections to unknown ports), redirect to honeypot
        // Only redirect if destination port is low (< 1024) to avoid redirecting outbound connections
        if (syn && bpf_ntohs(dest_port) < 1024) {
            __u32 key = 0;
            __u64 *val = bpf_map_lookup_elem(&attack_stats, &key);
            if (val) __sync_fetch_and_add(val, 1);

            __be16 new_port = bpf_htons(HONEYPOT_PORT);
            
            tcp->dest = new_port;
            tcp->check = 0; // Kernel will recalculate checksum
            
            mutate_os_personality(ip, tcp);
            
            return XDP_PASS;
        }

        // For all other TCP packets, pass through
        return XDP_PASS;
    }
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";