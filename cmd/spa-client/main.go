package main

import (
	"fmt"
	"net"
	"os"
	"time"
)

// SPA Configuration (must match bpf/phantom.c)
const (
	SPA_MAGIC_PORT   = 1337
	SPA_SECRET_TOKEN = "PHANTOM_GRID_SPA_2025"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Usage: %s <server_ip>\n", os.Args[0])
		fmt.Println("\nSingle Packet Authorization (SPA) Client")
		fmt.Println("Sends Magic Packet to whitelist your IP for SSH access")
		os.Exit(1)
	}

	serverIP := os.Args[1]

	fmt.Printf("[*] Sending Magic Packet to %s:%d...\n", serverIP, SPA_MAGIC_PORT)

	// Create UDP connection
	conn, err := net.Dial("udp", fmt.Sprintf("%s:%d", serverIP, SPA_MAGIC_PORT))
	if err != nil {
		fmt.Printf("[!] Failed to create UDP connection: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	// Send Magic Packet with secret token (exactly 21 bytes, no null terminator)
	tokenBytes := []byte(SPA_SECRET_TOKEN)
	if len(tokenBytes) != 21 {
		fmt.Printf("[!] Error: Token length mismatch (expected 21, got %d)\n", len(tokenBytes))
		os.Exit(1)
	}
	_, err = conn.Write(tokenBytes)
	if err != nil {
		fmt.Printf("[!] Failed to send Magic Packet: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[*] Sent %d bytes: %s\n", len(tokenBytes), SPA_SECRET_TOKEN)

	fmt.Println("[+] Magic Packet sent successfully!")
	fmt.Println("[+] Your IP has been whitelisted for 30 seconds")
	fmt.Println("[+] You can now SSH to the server:")
	fmt.Printf("    ssh user@%s\n", serverIP)
	fmt.Println("\n[*] Note: Whitelist expires in 30 seconds")

	// Wait a moment to ensure packet is sent
	time.Sleep(100 * time.Millisecond)
}
