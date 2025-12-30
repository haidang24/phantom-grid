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
// IMPORTANT: When adding ports here, also update CriticalPorts in internal/config/config.go
// and add the port check in is_critical_asset_port() function below
// Databases
#define MYSQL_PORT 3306
#define POSTGRES_PORT 5432
#define POSTGRES_ALT_PORT 5433
#define MONGODB_PORT 27017
#define MONGODB_SHARD_PORT 27018
#define REDIS_PORT 6379
#define MSSQL_PORT 1433
#define MSSQL_BROWSER_PORT 2702
#define MSSQL_MONITOR_PORT 1434
#define ORACLE_PORT 1521
#define DERBY_PORT 1527
#define DB2_PORT 50000
#define DB2_SSL_PORT 50001
// Admin Panels & Management
#define ADMIN_PANEL_PORT_1 8080
#define ADMIN_PANEL_PORT_2 8443
#define ADMIN_PANEL_PORT_3 9000
#define ELASTICSEARCH_PORT 9200
#define KIBANA_PORT 5601
#define GRAFANA_PORT 3000
#define PROMETHEUS_PORT 9090
#define PROMETHEUS_PUSH_PORT 9091
#define RABBITMQ_MGMT_PORT 15672
#define RABBITMQ_MGMT_ERLANG_PORT 25672
#define COUCHDB_PORT 5984
#define ACTIVEMQ_WEB_PORT 8161
#define ACTIVEMQ_WEB_SSL_PORT 8162
#define ACTIVEMQ_PORT 61616
#define ACTIVEMQ_SSL_PORT 61617
#define ZOOKEEPER_PORT 2181
#define WEBLOGIC_PORT 7001
#define WEBLOGIC_SSL_PORT 7002
#define GLASSFISH_ADMIN_PORT 4848
#define GLASSFISH_ADMIN_SSL_PORT 4849
#define WILDFLY_ADMIN_PORT 9990
#define WILDFLY_ADMIN_SSL_PORT 9993
// Remote Access
#define RDP_PORT 3389
#define WINRM_HTTP_PORT 5985
#define WINRM_HTTPS_PORT 5986
// Container Services
#define DOCKER_PORT 2375
#define DOCKER_TLS_PORT 2376
#define DOCKER_REGISTRY_PORT 5000
// Application Frameworks
#define NODEJS_PORT 3000
#define FLASK_PORT 5000
#define DJANGO_PORT 8000
#define JUPYTER_PORT 8888
// Directory Services
#define LDAP_PORT 389
#define LDAP_SSL_PORT 636
#define LDAP_GC_PORT 3268
#define LDAP_GC_SSL_PORT 3269
// Cache Services
#define MEMCACHED_PORT 11211
#define MEMCACHED_SSL_PORT 11214
// File Services
#define NFS_PORT 2049
#define RPC_PORTMAPPER_PORT 111
// Messaging Protocols
#define MQTT_PORT 1883
#define MQTT_SSL_PORT 8883
#define STOMP_PORT 61613
#define STOMP_SSL_PORT 61614
#define RABBITMQ_AMQP_PORT 5672
#define RABBITMQ_AMQP_SSL_PORT 5671
#define ERLANG_PORTMAPPER_PORT 4369

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
// This function checks if a port requires SPA authentication before allowing access
// IMPORTANT: Keep this list synchronized with CriticalPorts in internal/config/config.go
// Ports are grouped by category for better performance and maintainability
static __always_inline int is_critical_asset_port(__be16 port) {
    __u16 p = bpf_ntohs(port);
    
    // Core services
    if (p == SSH_PORT) return 1;
    
    // Databases (most common, check first)
    if (p == MYSQL_PORT || p == POSTGRES_PORT || p == POSTGRES_ALT_PORT || 
        p == MONGODB_PORT || p == MONGODB_SHARD_PORT || p == REDIS_PORT || 
        p == MSSQL_PORT || p == MSSQL_BROWSER_PORT || p == MSSQL_MONITOR_PORT ||
        p == ORACLE_PORT || p == DERBY_PORT || p == DB2_PORT || p == DB2_SSL_PORT) return 1;
    
    // Admin panels and management interfaces
    if (p == ADMIN_PANEL_PORT_1 || p == ADMIN_PANEL_PORT_2 || p == ADMIN_PANEL_PORT_3 ||
        p == ELASTICSEARCH_PORT || p == KIBANA_PORT || p == GRAFANA_PORT || 
        p == PROMETHEUS_PORT || p == PROMETHEUS_PUSH_PORT || p == RABBITMQ_MGMT_PORT ||
        p == RABBITMQ_MGMT_ERLANG_PORT || p == COUCHDB_PORT || p == ACTIVEMQ_WEB_PORT ||
        p == ACTIVEMQ_WEB_SSL_PORT || p == ACTIVEMQ_PORT || p == ACTIVEMQ_SSL_PORT ||
        p == ZOOKEEPER_PORT || p == WEBLOGIC_PORT || p == WEBLOGIC_SSL_PORT ||
        p == GLASSFISH_ADMIN_PORT || p == GLASSFISH_ADMIN_SSL_PORT ||
        p == WILDFLY_ADMIN_PORT || p == WILDFLY_ADMIN_SSL_PORT) return 1;
    
    // Remote access
    if (p == RDP_PORT || p == WINRM_HTTP_PORT || p == WINRM_HTTPS_PORT) return 1;
    
    // Container/Docker services
    if (p == DOCKER_PORT || p == DOCKER_TLS_PORT || p == DOCKER_REGISTRY_PORT) return 1;
    
    // Application frameworks (if used for admin interfaces)
    if (p == NODEJS_PORT || p == FLASK_PORT || p == DJANGO_PORT || p == JUPYTER_PORT) return 1;
    
    // Directory services
    if (p == LDAP_PORT || p == LDAP_SSL_PORT || p == LDAP_GC_PORT || p == LDAP_GC_SSL_PORT) return 1;
    
    // Cache services
    if (p == MEMCACHED_PORT || p == MEMCACHED_SSL_PORT) return 1;
    
    // File services
    if (p == NFS_PORT || p == RPC_PORTMAPPER_PORT) return 1;
    
    // Messaging protocols
    if (p == MQTT_PORT || p == MQTT_SSL_PORT || p == STOMP_PORT || p == STOMP_SSL_PORT ||
        p == RABBITMQ_AMQP_PORT || p == RABBITMQ_AMQP_SSL_PORT || p == ERLANG_PORTMAPPER_PORT) return 1;
    
    return 0;
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

        __be16 new_port = bpf_htons(HONEYPOT_PORT);
        
        tcp->dest = new_port;
        tcp->check = 0; // Kernel will recalculate checksum
        
        mutate_os_personality(ip, tcp);
        
        return XDP_PASS;
    }
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";