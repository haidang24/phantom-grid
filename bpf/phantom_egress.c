//go:build ignore
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/string.h>

/* * PHANTOM GRID - TC EGRESS MODULE (Data Loss Prevention)
 * Author: Mai Hai Dang (HD24 Security Lab)
 * Description: TC eBPF Hook for Egress Traffic Control & Data Exfiltration Prevention
 * 
 * This module implements DLP (Data Loss Prevention) at kernel level:
 * - Monitors outbound traffic from honeypot connections
 * - Detects suspicious data patterns (file contents, credentials, etc.)
 * - Blocks or logs data exfiltration attempts
 */

#define HONEYPOT_PORT 9999
#define MAX_PAYLOAD_SCAN 512  // Scan first 512 bytes of payload

// Map to track egress blocks (data exfiltration attempts)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} egress_blocks SEC(".maps");

// Map to track suspicious patterns detected
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 10);
    __type(key, __u32);
    __type(value, __u64);
} suspicious_patterns SEC(".maps");

// Helper function to detect suspicious data patterns in payload
static __always_inline int detect_suspicious_pattern(void *data, __u32 data_len) {
    if (data_len == 0 || data_len > MAX_PAYLOAD_SCAN) {
        return 0;
    }
    
    // Pattern 1: /etc/passwd content indicators
    char passwd_pattern[] = "root:x:0:0:";
    if (bpf_strncmp(data, passwd_pattern, sizeof(passwd_pattern) - 1) == 0) {
        return 1; // Suspicious: password file content
    }
    
    // Pattern 2: SSH private key indicators
    char ssh_key_pattern[] = "-----BEGIN";
    if (bpf_strncmp(data, ssh_key_pattern, sizeof(ssh_key_pattern) - 1) == 0) {
        return 2; // Suspicious: SSH private key
    }
    
    // Pattern 3: Base64 encoded data (common for exfiltration)
    // Check for high ratio of base64 characters
    __u32 base64_count = 0;
    for (__u32 i = 0; i < data_len && i < 64; i++) {
        char c = ((char *)data)[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || 
            (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=') {
            base64_count++;
        }
    }
    if (base64_count > data_len * 0.8 && data_len > 32) {
        return 3; // Suspicious: likely base64 encoded data
    }
    
    // Pattern 4: Database dump indicators
    char db_pattern[] = "INSERT INTO";
    if (bpf_strncmp(data, db_pattern, sizeof(db_pattern) - 1) == 0) {
        return 4; // Suspicious: SQL dump
    }
    
    // Pattern 5: Credit card pattern (simplified - 16 digits)
    // This is a basic check, real implementation would use Luhn algorithm
    __u32 digit_count = 0;
    for (__u32 i = 0; i < data_len && i < 32; i++) {
        char c = ((char *)data)[i];
        if (c >= '0' && c <= '9') {
            digit_count++;
        } else if (c != ' ' && c != '-' && c != '\n') {
            digit_count = 0; // Reset if non-digit separator
        }
    }
    if (digit_count >= 13) {
        return 5; // Suspicious: potential credit card number
    }
    
    return 0;
}

SEC("tc")
int phantom_egress_prog(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
    
    // Only process IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;
    
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return TC_ACT_OK;
    
    // Only process TCP
    if (ip->protocol != IPPROTO_TCP) return TC_ACT_OK;
    
    struct tcphdr *tcp = (void *)(ip + 1);
    if ((void *)(tcp + 1) > data_end) return TC_ACT_OK;
    
    // Check if this is traffic FROM the honeypot port (egress)
    // Source port is honeypot port, meaning data is leaving honeypot
    if (tcp->source != bpf_htons(HONEYPOT_PORT)) {
        return TC_ACT_OK; // Not from honeypot, allow
    }
    
    // Calculate TCP payload offset
    __u32 tcp_hdr_len = (tcp->doff) * 4;
    void *payload = (void *)(tcp + 1);
    if ((void *)(payload + tcp_hdr_len) > data_end) return TC_ACT_OK;
    
    // Get payload length
    __u32 payload_len = (__u32)(data_end - (void *)payload);
    if (payload_len == 0) return TC_ACT_OK;
    
    // Limit scan to first MAX_PAYLOAD_SCAN bytes
    if (payload_len > MAX_PAYLOAD_SCAN) {
        payload_len = MAX_PAYLOAD_SCAN;
    }
    
    // Detect suspicious patterns in payload
    int pattern_type = detect_suspicious_pattern(payload, payload_len);
    
    if (pattern_type > 0) {
        // Update statistics
        __u32 key = 0;
        __u64 *val = bpf_map_lookup_elem(&egress_blocks, &key);
        if (val) __sync_fetch_and_add(val, 1);
        
        // Track pattern type
        __u32 pattern_key = (__u32)pattern_type;
        __u64 *pattern_val = bpf_map_lookup_elem(&suspicious_patterns, &pattern_key);
        if (pattern_val) __sync_fetch_and_add(pattern_val, 1);
        
        // BLOCK: Drop packet to prevent data exfiltration
        // This is the core DLP functionality - data never leaves the server
        return TC_ACT_SHOT; // Drop packet silently
    }
    
    // No suspicious pattern detected, allow packet
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";

