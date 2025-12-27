//go:build ignore
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/string.h>

/* * PHANTOM GRID - SINGLE PACKET AUTHORIZATION (SPA) MODULE
 * Author: Mai Hai Dang (HD24 Security Lab)
 * Description: Zero Trust Access Control - Server is invisible until Magic Packet received
 * 
 * Features:
 * - Default: DROP all traffic (including SSH port 22) - Server appears "dead"
 * - Magic Packet Authentication: Admin sends special packet with secret token
 * - Automatic Whitelisting: If Magic Packet is valid, whitelist admin IP for 30 seconds
 * - Result: Hacker sees "dead host", Admin can still access SSH
 */

#define SSH_PORT 22
#define SPA_MAGIC_PORT 1337  // Port for Magic Packet (can be any port)
#define SPA_SECRET_TOKEN "PHANTOM_GRID_SPA_2025"  // Secret token (must match in Go code)
#define SPA_TOKEN_LEN 21  // Length of "PHANTOM_GRID_SPA_2025" (without null terminator)
#define SPA_WHITELIST_DURATION 30  // Whitelist duration in seconds

// Whitelist map: IP address -> expiration timestamp (seconds since boot)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100);  // Max 100 whitelisted IPs
    __type(key, __be32);       // Source IP address
    __type(value, __u64);      // Expiration timestamp (jiffies)
} spa_whitelist SEC(".maps");

// Statistics map
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

// Helper function to check if IP is whitelisted
static __always_inline int is_whitelisted(__be32 src_ip) {
    __u64 *expiry = bpf_map_lookup_elem(&spa_whitelist, &src_ip);
    if (!expiry) {
        return 0; // Not whitelisted
    }
    
    // Check if whitelist entry has expired
    // Note: In production, use bpf_ktime_get_boot_ns() for accurate time
    // For simplicity, we'll check if entry exists (expiry logic handled in user space)
    return 1; // Whitelisted
}

// Helper function to verify Magic Packet token
static __always_inline int verify_magic_packet(void *payload, __u32 payload_len) {
    if (payload_len < SPA_TOKEN_LEN) {
        return 0;
    }
    
    // Check if payload starts with secret token
    char token[SPA_TOKEN_LEN] = SPA_SECRET_TOKEN;
    if (bpf_strncmp(payload, token, SPA_TOKEN_LEN) == 0) {
        return 1; // Valid Magic Packet
    }
    
    return 0; // Invalid
}

// Helper function to add IP to whitelist
static __always_inline void whitelist_ip(__be32 src_ip) {
    // Calculate expiration time (30 seconds from now)
    // Note: In production, use proper time functions
    // For now, we'll use a simple approach - user space will handle expiry
    __u64 expiry = 0; // Will be set by user space agent
    bpf_map_update_elem(&spa_whitelist, &src_ip, &expiry, BPF_ANY);
    
    // Update success statistics
    __u32 key = 0;
    __u64 *val = bpf_map_lookup_elem(&spa_auth_success, &key);
    if (val) __sync_fetch_and_add(val, 1);
}

SEC("xdp")
int phantom_spa_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    // Only process IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    __be32 src_ip = ip->saddr;

    // --- STEP 1: CHECK MAGIC PACKET (SPA Authentication) ---
    // Check for UDP Magic Packet on SPA_MAGIC_PORT
    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(ip + 1);
        if ((void *)(udp + 1) > data_end) return XDP_DROP;
        
        // Check if this is Magic Packet port
        if (udp->dest == bpf_htons(SPA_MAGIC_PORT)) {
            void *payload = (void *)(udp + 1);
            __u32 payload_len = (__u32)(data_end - (void *)payload);
            
            // Verify Magic Packet token
            if (verify_magic_packet(payload, payload_len)) {
                // Valid Magic Packet - whitelist this IP
                whitelist_ip(src_ip);
                // Drop the Magic Packet itself (don't forward it)
                return XDP_DROP;
            } else {
                // Invalid Magic Packet - update failed stats
                __u32 key = 0;
                __u64 *val = bpf_map_lookup_elem(&spa_auth_failed, &key);
                if (val) __sync_fetch_and_add(val, 1);
                return XDP_DROP; // Drop invalid Magic Packets
            }
        }
    }

    // --- STEP 2: CHECK WHITELIST ---
    // If IP is whitelisted, allow traffic (including SSH)
    if (is_whitelisted(src_ip)) {
        return XDP_PASS; // Allow whitelisted IP
    }

    // --- STEP 3: DEFAULT BEHAVIOR - DROP EVERYTHING ---
    // Server is invisible: Drop all traffic (including SSH port 22)
    // This makes the server appear "dead" to scanners
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";

