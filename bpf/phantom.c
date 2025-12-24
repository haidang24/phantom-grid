//go:build ignore
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

/* * PHANTOM GRID - eBPF KERNEL MODULE
 * Author: Mai Hai Dang (HD24 Security Lab)
 * Description: XDP Layer for Transparent Redirection & Stealth Trapping
 * 
 * Features:
 * - Transparent port redirection with checksum recalculation
 * - Stealth scan detection and dropping (Xmas, Null, FIN scans)
 * - OS Personality Mutation (TTL, Window Size manipulation)
 * - Attack statistics tracking
 */

#define HONEYPOT_PORT 9999
#define SSH_PORT 22
#define SPA_MAGIC_PORT 1337  // Port for Magic Packet (SPA authentication)
#define SPA_SECRET_TOKEN "PHANTOM_GRID_SPA_2024"
#define SPA_TOKEN_LEN 24

// OS Fingerprint Values (for OS Personality Mutation)
// These values mimic different operating systems to confuse fingerprinting tools
#define TTL_WINDOWS 128      // Windows default TTL
#define TTL_LINUX 64         // Linux default TTL
#define TTL_FREEBSD 64       // FreeBSD default TTL
#define TTL_SOLARIS 255      // Solaris default TTL

#define WINDOW_WINDOWS 65535 // Windows default window size
#define WINDOW_LINUX 29200   // Linux default window size
#define WINDOW_FREEBSD 65535 // FreeBSD default window size

// Map to track attack statistics for Dashboard
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} attack_stats SEC(".maps");

// Map to track stealth scan drops
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} stealth_drops SEC(".maps");

// Map to track OS personality mutations
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} os_mutations SEC(".maps");

// SPA (Single Packet Authorization) Whitelist
// IP address -> expiration timestamp (managed by user space)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100);
    __type(key, __be32);
    __type(value, __u64);
} spa_whitelist SEC(".maps");

// SPA statistics
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

// Helper function to mutate OS fingerprint (OS Personality Mutation)
// This confuses fingerprinting tools like Nmap by changing TTL and Window Size
static __always_inline void mutate_os_personality(struct iphdr *ip, struct tcphdr *tcp, struct xdp_md *ctx, void *data) {
    // Use source port as seed for consistent mutation per connection
    // This ensures same connection always shows same OS fingerprint
    __u16 src_port = bpf_ntohs(tcp->source);
    
    // Select OS personality based on source port hash (consistent per connection)
    __u8 os_type = (src_port % 4); // 0=Windows, 1=Linux, 2=FreeBSD, 3=Solaris
    
    __u8 old_ttl = ip->ttl;
    __u8 new_ttl;
    __be16 old_window = tcp->window;
    __be16 new_window;
    
    // Mutate TTL and Window Size based on selected OS
    switch (os_type) {
        case 0: // Windows
            new_ttl = TTL_WINDOWS;
            new_window = bpf_htons(WINDOW_WINDOWS);
            break;
        case 1: // Linux (keep original to confuse)
            new_ttl = TTL_LINUX;
            new_window = bpf_htons(WINDOW_LINUX);
            break;
        case 2: // FreeBSD
            new_ttl = TTL_FREEBSD;
            new_window = bpf_htons(WINDOW_FREEBSD);
            break;
        case 3: // Solaris
            new_ttl = TTL_SOLARIS;
            new_window = bpf_htons(WINDOW_LINUX); // Use Linux window for Solaris
            break;
        default:
            new_ttl = TTL_WINDOWS; // Default to Windows
            new_window = bpf_htons(WINDOW_WINDOWS);
    }
    
    // Mutate IP TTL
    if (old_ttl != new_ttl) {
        ip->ttl = new_ttl;
        
        // Recalculate IP checksum (TTL is part of IP header checksum)
        __u64 ip_offset = (__u64)((void *)ip - (void *)data);
        __u64 ip_checksum_offset = ip_offset + offsetof(struct iphdr, check);
        
        // Calculate checksum difference for TTL change
        __s64 ip_csum_diff = bpf_csum_diff((__be32 *)&old_ttl, 1, (__be32 *)&new_ttl, 1, 0);
        bpf_l3_csum_replace(ctx, ip_checksum_offset, 0, ip_csum_diff, 0);
    }
    
    // Mutate TCP Window Size
    if (old_window != new_window) {
        tcp->window = new_window;
        
        // Recalculate TCP checksum (Window Size is part of TCP header checksum)
        __u64 tcp_offset = (__u64)((void *)tcp - (void *)data);
        __u64 tcp_checksum_offset = tcp_offset + offsetof(struct tcphdr, check);
        
        // Calculate checksum difference for window size change
        __s64 tcp_csum_diff = bpf_csum_diff((__be32 *)&old_window, 2, (__be32 *)&new_window, 2, 0);
        bpf_l4_csum_replace(ctx, tcp_checksum_offset, 0, tcp_csum_diff, 0);
    }
    
    // Update mutation statistics
    __u32 key = 0;
    __u64 *val = bpf_map_lookup_elem(&os_mutations, &key);
    if (val) __sync_fetch_and_add(val, 1);
}

// Helper function to check if IP is whitelisted for SPA
static __always_inline int is_spa_whitelisted(__be32 src_ip) {
    __u64 *expiry = bpf_map_lookup_elem(&spa_whitelist, &src_ip);
    return (expiry != NULL); // If entry exists, IP is whitelisted
}

// Helper function to verify Magic Packet token
static __always_inline int verify_magic_packet(void *payload, __u32 payload_len) {
    if (payload_len < SPA_TOKEN_LEN) {
        return 0;
    }
    char token[SPA_TOKEN_LEN] = SPA_SECRET_TOKEN;
    return (bpf_strncmp(payload, token, SPA_TOKEN_LEN) == 0);
}

// Helper function to whitelist IP for SPA
static __always_inline void spa_whitelist_ip(__be32 src_ip) {
    __u64 expiry = 0; // Will be managed by user space
    bpf_map_update_elem(&spa_whitelist, &src_ip, &expiry, BPF_ANY);
    __u32 key = 0;
    __u64 *val = bpf_map_lookup_elem(&spa_auth_success, &key);
    if (val) __sync_fetch_and_add(val, 1);
}

// Helper function to detect stealth scans
static __always_inline int is_stealth_scan(struct tcphdr *tcp) {
    // Read TCP flags byte (offset 13 in TCP header)
    // TCP header structure: src port (2), dst port (2), seq (4), ack_seq (4), 
    //                        data_offset/reserved/flags (2 bytes)
    // Flags byte is at offset 13: FIN(0x01), SYN(0x02), RST(0x04), PSH(0x08), ACK(0x10), URG(0x20)
    __u8 *flags_byte = ((__u8 *)tcp + 13);
    __u8 flags = *flags_byte;
    
    // Extract individual flags
    __u8 fin = flags & 0x01;
    __u8 syn = flags & 0x02;
    __u8 rst = flags & 0x04;
    __u8 psh = flags & 0x08;
    __u8 ack = flags & 0x10;
    __u8 urg = flags & 0x20;
    
    // Xmas Scan: FIN + URG + PSH flags set, no SYN/RST
    if (fin && urg && psh && !syn && !rst) {
        return 1;
    }
    
    // Null Scan: No flags set at all
    if (flags == 0) {
        return 1;
    }
    
    // FIN Scan: Only FIN flag set
    if (fin && !syn && !rst && !psh && !ack && !urg) {
        return 1;
    }
    
    // ACK Scan: Only ACK flag set (used for port scanning, no SYN)
    if (ack && !syn && !fin && !rst) {
        return 1;
    }
    
    return 0;
}

SEC("xdp")
int phantom_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    // Only process IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    __be32 src_ip = ip->saddr;

    // --- STEP 0: SINGLE PACKET AUTHORIZATION (SPA) ---
    // Check for Magic Packet (UDP on SPA_MAGIC_PORT)
    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(ip + 1);
        if ((void *)(udp + 1) > data_end) return XDP_DROP;
        
        if (udp->dest == bpf_htons(SPA_MAGIC_PORT)) {
            void *payload = (void *)(udp + 1);
            __u32 payload_len = (__u32)(data_end - (void *)payload);
            
            if (verify_magic_packet(payload, payload_len)) {
                // Valid Magic Packet - whitelist admin IP
                spa_whitelist_ip(src_ip);
                return XDP_DROP; // Drop Magic Packet itself
            } else {
                // Invalid Magic Packet
                __u32 key = 0;
                __u64 *val = bpf_map_lookup_elem(&spa_auth_failed, &key);
                if (val) __sync_fetch_and_add(val, 1);
                return XDP_DROP;
            }
        }
    }

    // Only process TCP
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(ip + 1);
        if ((void *)(tcp + 1) > data_end) return XDP_PASS;

        // --- STEP 0.5: SPA WHITELIST CHECK FOR SSH ---
        // If traffic is for SSH port 22, check SPA whitelist
        // Server is invisible (appears dead) unless IP is whitelisted
        if (tcp->dest == bpf_htons(SSH_PORT)) {
            if (!is_spa_whitelisted(src_ip)) {
                // Not whitelisted - server appears "dead" to scanners
                return XDP_DROP;
            }
            // Whitelisted - allow SSH access
            return XDP_PASS;
        }

        // --- STEP 1: STEALTH SCAN DETECTION & DROP ---
        // Detect and drop malicious scan packets immediately (save resources)
        if (is_stealth_scan(tcp)) {
            __u32 key = 0;
            __u64 *val = bpf_map_lookup_elem(&stealth_drops, &key);
            if (val) __sync_fetch_and_add(val, 1);
            
            // Drop stealth scans silently - don't waste honeypot resources
            return XDP_DROP;
        }

        // --- STEP 2: ACTIVE DEFENSE REDIRECTION ---
        // If traffic is NOT for the real SSH port (22) and NOT the Honeypot itself
        // Redirect it to the Honeypot (Port 9999)
        if (tcp->dest != bpf_htons(SSH_PORT) && tcp->dest != bpf_htons(HONEYPOT_PORT)) {
            
            // 1. Telemetry: Update stats map
            __u32 key = 0;
            __u64 *val = bpf_map_lookup_elem(&attack_stats, &key);
            if (val) __sync_fetch_and_add(val, 1);

            // 2. Redirection: Modify Destination Port
            __be16 old_port = tcp->dest;
            __be16 new_port = bpf_htons(HONEYPOT_PORT);
            tcp->dest = new_port;
            
            // 3. OS Personality Mutation (OS Fingerprint Spoofing)
            // Mutate TTL and Window Size to confuse fingerprinting tools like Nmap
            // This makes attackers think they're attacking Windows/Linux/FreeBSD/Solaris
            // when they're actually attacking Linux, causing wrong exploits to be used
            mutate_os_personality(ip, tcp, ctx, data);
            
            // 4. Recalculate TCP Checksum (Production-ready)
            // TCP checksum needs to be recalculated when we modify the port
            // Note: mutate_os_personality already recalculated checksums for TTL/Window
            // We still need to recalculate for port change
            
            // Calculate offset of dest port field from start of packet
            __u64 tcp_offset = (__u64)((void *)tcp - (void *)data);
            __u64 checksum_offset = tcp_offset + offsetof(struct tcphdr, check);
            
            // Calculate checksum difference: old_port -> new_port
            // bpf_csum_diff calculates the checksum difference between two buffers
            __s64 csum_diff = bpf_csum_diff((__be32 *)&old_port, 2, (__be32 *)&new_port, 2, 0);
            
            // Update TCP checksum using the difference
            // bpf_l4_csum_replace(ctx, offset, from, to, flags)
            // offset: position of checksum field
            // from: old checksum value (0 means we're adding the diff)
            // to: checksum difference to add
            // flags: 0 = add, BPF_F_PSEUDO_HDR = use pseudo-header
            bpf_l4_csum_replace(ctx, checksum_offset, 0, csum_diff, 0);
        }
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";


