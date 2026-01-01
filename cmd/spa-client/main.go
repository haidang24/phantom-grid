package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"phantom-grid/internal/config"
	"phantom-grid/pkg/spa"
)

func main() {
	// Parse command line arguments
	serverIP := flag.String("server", "", "Server IP address (required)")
	mode := flag.String("mode", "static", "SPA mode: 'static', 'dynamic', or 'asymmetric'")
	keyPath := flag.String("key", "", "Path to private key file (required for asymmetric mode)")
	totpSecretPath := flag.String("totp", "", "Path to TOTP secret file (optional)")
	flag.Parse()

	// Validate server IP
	if *serverIP == "" {
		flag.Usage()
		fmt.Println("\nExamples:")
		fmt.Println("  Static SPA:")
		fmt.Println("    ./spa-client -server 192.168.1.100")
		fmt.Println("  Dynamic Asymmetric SPA:")
		fmt.Println("    ./spa-client -server 192.168.1.100 -mode asymmetric -key ~/.phantom-grid/spa_private.key")
		fmt.Println("  With TOTP:")
		fmt.Println("    ./spa-client -server 192.168.1.100 -mode asymmetric -key ~/.phantom-grid/spa_private.key -totp ~/.phantom-grid/totp_secret.txt")
		os.Exit(1)
	}

	// Handle static mode (legacy)
	if *mode == "static" {
		client := spa.NewClient(*serverIP)
		fmt.Printf("[*] Sending Static SPA Magic Packet to %s:%d...\n", *serverIP, config.SPAMagicPort)
		if err := client.SendMagicPacket(); err != nil {
			fmt.Printf("[!] Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[*] Sent %d bytes: %s\n", config.SPATokenLen, config.SPASecretToken)
		fmt.Println("[+] Magic Packet sent successfully!")
		fmt.Printf("[+] Your IP has been whitelisted for %d seconds\n", config.SPAWhitelistDuration)
		fmt.Println("[+] You can now connect to protected services:")
		fmt.Printf("    ssh user@%s\n", *serverIP)
		fmt.Printf("    ftp %s\n", *serverIP)
		fmt.Println("\n[*] Note: Whitelist expires in 30 seconds")
		return
	}

	// Handle dynamic modes
	spaConfig := config.DefaultDynamicSPAConfig()

	// Set mode
	switch *mode {
	case "dynamic":
		spaConfig.Mode = config.SPAModeDynamic
	case "asymmetric":
		spaConfig.Mode = config.SPAModeAsymmetric
	default:
		log.Fatalf("Invalid mode: %s. Use 'static', 'dynamic', or 'asymmetric'", *mode)
	}

	// Load private key for asymmetric mode
	if spaConfig.Mode == config.SPAModeAsymmetric {
		if *keyPath == "" {
			// Try default locations
			defaultPaths := []string{
				"./keys/spa_private.key",
				filepath.Join(os.Getenv("HOME"), ".phantom-grid", "spa_private.key"),
				filepath.Join(os.Getenv("USERPROFILE"), ".phantom-grid", "spa_private.key"), // Windows
			}
			for _, path := range defaultPaths {
				if _, err := os.Stat(path); err == nil {
					*keyPath = path
					break
				}
			}
		}

		if *keyPath == "" {
			log.Fatal("Error: Private key required for asymmetric mode. Use -key flag or place key at ~/.phantom-grid/spa_private.key")
		}

		fmt.Printf("[*] Loading private key from %s...\n", *keyPath)
		_, privateKey, err := config.LoadKeysFromFile("", *keyPath)
		if err != nil {
			log.Fatalf("Failed to load private key: %v\nMake sure the key file exists and has correct permissions (chmod 600)", err)
		}
		spaConfig.PrivateKey = privateKey
		fmt.Println("[+] Private key loaded")
	}

	// Load TOTP secret if provided
	if *totpSecretPath != "" {
		fmt.Printf("[*] Loading TOTP secret from %s...\n", *totpSecretPath)
		totpSecret, err := os.ReadFile(*totpSecretPath)
		if err != nil {
			log.Fatalf("Failed to load TOTP secret: %v\nMake sure the secret file exists", err)
		}
		// Remove newline if present
		if len(totpSecret) > 0 && totpSecret[len(totpSecret)-1] == '\n' {
			totpSecret = totpSecret[:len(totpSecret)-1]
		}
		spaConfig.TOTPSecret = totpSecret
		fmt.Println("[+] TOTP secret loaded")
	}

	// Create dynamic client
	fmt.Printf("[*] Creating %s SPA client for server %s...\n", *mode, *serverIP)
	client, err := spa.NewDynamicClient(*serverIP, spaConfig)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	// Send magic packet
	fmt.Printf("[*] Sending %s SPA packet to %s:%d...\n", *mode, *serverIP, config.SPAMagicPort)
	if err := client.SendMagicPacket(); err != nil {
		log.Fatalf("Failed to send packet: %v", err)
	}

	fmt.Println("[+] SPA packet sent successfully!")
	fmt.Printf("[+] Your IP has been whitelisted for %d seconds\n", config.SPAWhitelistDuration)
	fmt.Println("[+] You can now connect to protected services:")
	fmt.Printf("    ssh user@%s\n", *serverIP)
	fmt.Printf("    ftp %s\n", *serverIP)
	fmt.Println("\n[*] Note: Whitelist expires in 30 seconds")
}
