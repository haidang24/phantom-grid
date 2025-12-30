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
 */

#define HONEYPOT_PORT 9999
#define SSH_PORT 22
#define SPA_MAGIC_PORT 1337
#define SPA_SECRET_TOKEN "PHANTOM_GRID_SPA_2025"
#define SPA_TOKEN_LEN 21
#define SPA_WHITELIST_DURATION_NS (30ULL * 1000000000ULL) // 30 seconds in nanoseconds

// Critical asset ports protected by Phantom Protocol (default: DROP all traffic)
#define MYSQL_PORT 3306
#define POSTGRES_PORT 5432
#define MONGODB_PORT 27017
#define REDIS_PORT 6379
#define ADMIN_PANEL_PORT_1 8080
#define ADMIN_PANEL_PORT_2 8443
#define ADMIN_PANEL_PORT_3 9000

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif
#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 1
#endif

// OS Fingerprint Values
#define TTL_WINDOWS 128
#define TTL_LINUX 64
#define TTL_FREEBSD 64
#define TTL_SOLARIS 255

#define WINDOW_WINDOWS 65535
#define WINDOW_LINUX 29200
#define WINDOW_FREEBSD 65535

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

// Manual checksum update for 16-bit values
static __always_inline void update_csum16(__u16 *csum, __be16 old_val, __be16 new_val) {
    __u32 sum = (~(*csum) & 0xffff);
    // Convert to host byte order for arithmetic, then back
    __u16 old = bpf_ntohs(old_val);
    __u16 new = bpf_ntohs(new_val);
    sum += (~old & 0xffff);
    sum += (new & 0xffff);
    sum = (sum & 0xffff) + (sum >> 16);
    *csum = ~((sum & 0xffff) + (sum >> 16));
}

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

// Helper: Check if port is a Critical Asset (protected by Phantom Protocol)
static __always_inline int is_critical_asset_port(__be16 port) {
    __u16 p = bpf_ntohs(port);
    return (p == SSH_PORT || 
            p == MYSQL_PORT || 
            p == POSTGRES_PORT || 
            p == MONGODB_PORT || 
            p == REDIS_PORT || 
            p == ADMIN_PANEL_PORT_1 || 
            p == ADMIN_PANEL_PORT_2 || 
            p == ADMIN_PANEL_PORT_3);
}

// Check if port is a fake port (The Mirage - honeypot will bind these ports)
// This list must match fakePorts in cmd/agent/main.go
static __always_inline int is_fake_port(__be16 port) {
    __u16 p = bpf_ntohs(port);
    if (p == HONEYPOT_PORT) return 0;
    
    return (p == 80 ||      // HTTP
            p == 443 ||     // HTTPS
            p == 3306 ||    // MySQL (fake)
            p == 5432 ||    // PostgreSQL (fake)
            p == 6379 ||    // Redis (fake)
            p == 27017 ||   // MongoDB (fake)
            p == 8080 ||    // Admin Panel (fake)
            p == 8443 ||    // HTTPS Alt (fake)
            p == 9000 ||    // Admin Panel (fake)
            p == 21 ||      // FTP (fake)
            p == 23 ||      // Telnet (fake)
            p == 3389 ||    // RDP (fake)
            p == 5900 ||    // VNC (fake)
            p == 1433 ||    // MSSQL (fake)
            p == 1521 ||    // Oracle (fake)
            p == 5433 ||    // PostgreSQL Alt (fake)
            p == 11211 ||   // Memcached (fake)
            p == 27018 ||   // MongoDB Shard (fake)
            p == 9200 ||    // Elasticsearch (fake)
            p == 5601 ||    // Kibana (fake)
            p == 3000 ||    // Node.js (fake)
            p == 5000 ||    // Flask (fake)
            p == 8000 ||    // Django (fake)
            p == 8888);     // Jupyter (fake)
}

// Verify magic packet token
static __always_inline int verify_magic_packet(void *payload, void *data_end) {
    if ((void *)payload + SPA_TOKEN_LEN > data_end) return 0;

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
        
        if (udp->dest == bpf_htons(SPA_MAGIC_PORT)) {
            void *payload = (void *)(udp + 1);
            
            if (verify_magic_packet(payload, data_end)) {
                spa_whitelist_ip(src_ip);
                return XDP_DROP;
            } else {
                __u32 key = 0;
                __u64 *val = bpf_map_lookup_elem(&spa_auth_failed, &key);
                if (val) __sync_fetch_and_add(val, 1);
                return XDP_DROP;
            }
        }
        return XDP_PASS;
    }

    // TCP Logic (Defense & Redirection)
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(ip + 1);
        if ((void *)(tcp + 1) > data_end) return XDP_PASS;

        // Pass all packets to honeypot port (before other checks)
        if (tcp->dest == bpf_htons(HONEYPOT_PORT)) {
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
            __u32 key = 0;
            __u64 *val = bpf_map_lookup_elem(&attack_stats, &key);
            if (val) __sync_fetch_and_add(val, 1);
            return XDP_PASS;
        }

        // Block stealth scans
        if (is_stealth_scan(tcp)) {
            __u32 key = 0;
            __u64 *val = bpf_map_lookup_elem(&stealth_drops, &key);
            if (val) __sync_fetch_and_add(val, 1);
            return XDP_DROP;
        }

        // Redirect other ports to honeypot fallback
        __u32 key = 0;
        __u64 *val = bpf_map_lookup_elem(&attack_stats, &key);
        if (val) __sync_fetch_and_add(val, 1);

        __be16 old_port = tcp->dest;
        __be16 new_port = bpf_htons(HONEYPOT_PORT);
        
        tcp->dest = new_port;
        tcp->check = 0; // Kernel will recalculate checksum
        
        mutate_os_personality(ip, tcp);
        
        return XDP_PASS;
    }
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";