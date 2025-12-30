package main

import (
	"fmt"
	"os"

	"phantom-grid/internal/config"
	"phantom-grid/pkg/spa"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Usage: %s <server_ip>\n", os.Args[0])
		fmt.Println("\nSingle Packet Authorization (SPA) Client")
		fmt.Println("Sends Magic Packet to whitelist your IP for SSH access")
		os.Exit(1)
	}

	serverIP := os.Args[1]
	client := spa.NewClient(serverIP)

	fmt.Printf("[*] Sending Magic Packet to %s:%d...\n", serverIP, config.SPAMagicPort)

	if err := client.SendMagicPacket(); err != nil {
		fmt.Printf("[!] Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[*] Sent %d bytes: %s\n", config.SPATokenLen, config.SPASecretToken)
	fmt.Println("[+] Magic Packet sent successfully!")
	fmt.Printf("[+] Your IP has been whitelisted for %d seconds\n", config.SPAWhitelistDuration)
	fmt.Println("[+] You can now SSH to the server:")
	fmt.Printf("    ssh user@%s\n", serverIP)
	fmt.Println("\n[*] Note: Whitelist expires in 30 seconds")
}
