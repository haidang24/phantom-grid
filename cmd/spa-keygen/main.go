package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"phantom-grid/internal/config"
)

func main() {
	keyDir := flag.String("dir", "./keys", "Directory to save keys")
	force := flag.Bool("force", false, "Overwrite existing keys")
	flag.Parse()

	// Check if keys already exist
	publicKeyPath := filepath.Join(*keyDir, "spa_public.key")
	privateKeyPath := filepath.Join(*keyDir, "spa_private.key")

	if !*force {
		if _, err := os.Stat(publicKeyPath); err == nil {
			fmt.Fprintf(os.Stderr, "Error: Keys already exist at %s\n", *keyDir)
			fmt.Fprintf(os.Stderr, "Use -force to overwrite\n")
			os.Exit(1)
		}
	}

	// Generate Ed25519 key pair
	fmt.Println("Generating Ed25519 key pair...")
	publicKey, privateKey, err := config.GenerateEd25519Keys()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating keys: %v\n", err)
		os.Exit(1)
	}

	// Save keys
	if err := config.SaveKeysToFile(publicKey, privateKey, *keyDir); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving keys: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Keys generated successfully!\n")
	fmt.Printf("Public key:  %s\n", publicKeyPath)
	fmt.Printf("Private key: %s\n", privateKeyPath)
	fmt.Printf("\n")
	fmt.Printf("IMPORTANT: Keep the private key secure! It should only be on client machines.\n")
	fmt.Printf("The public key will be loaded into the server's eBPF maps.\n")
}

