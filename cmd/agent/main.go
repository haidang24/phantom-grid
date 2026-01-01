package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"phantom-grid/internal/agent"
	"phantom-grid/internal/config"
	"phantom-grid/internal/dashboard"
)

func main() {
	// Parse command line arguments
	interfaceFlag := flag.String("interface", "", "Network interface name (e.g., eth0, ens33). If not specified, auto-detect will be used.")
	outputModeFlag := flag.String("output", "dashboard", "Output mode: 'dashboard', 'elk', or 'both'")
	elkAddressFlag := flag.String("elk-address", "http://localhost:9200", "Elasticsearch address (comma-separated for multiple)")
	elkIndexFlag := flag.String("elk-index", "phantom-grid", "Elasticsearch index name")
	elkUserFlag := flag.String("elk-user", "", "Elasticsearch username (optional)")
	elkPassFlag := flag.String("elk-pass", "", "Elasticsearch password (optional)")
	elkTLSFlag := flag.Bool("elk-tls", false, "Enable TLS for Elasticsearch")
	elkSkipVerifyFlag := flag.Bool("elk-skip-verify", false, "Skip TLS certificate verification")
	
	// SPA Configuration flags
	spaModeFlag := flag.String("spa-mode", "static", "SPA mode: 'static', 'dynamic', or 'asymmetric'")
	spaKeyDirFlag := flag.String("spa-key-dir", "./keys", "Directory containing SPA keys")
	spaTOTPSecretFlag := flag.String("spa-totp-secret", "", "TOTP secret (base64 encoded, 32 bytes)")
	flag.Parse()

	// Parse output mode
	var outputMode config.OutputMode
	switch strings.ToLower(*outputModeFlag) {
	case "dashboard":
		outputMode = config.OutputModeDashboard
	case "elk":
		outputMode = config.OutputModeELK
	case "both":
		outputMode = config.OutputModeBoth
	default:
		log.Fatalf("[!] Invalid output mode: %s. Use 'dashboard', 'elk', or 'both'", *outputModeFlag)
	}

	// Configure ELK
	elkConfig := config.DefaultELKConfig()
	if outputMode == config.OutputModeELK || outputMode == config.OutputModeBoth {
		elkConfig.Enabled = true
		elkConfig.Addresses = strings.Split(*elkAddressFlag, ",")
		for i := range elkConfig.Addresses {
			elkConfig.Addresses[i] = strings.TrimSpace(elkConfig.Addresses[i])
		}
		elkConfig.Index = *elkIndexFlag
		elkConfig.Username = *elkUserFlag
		elkConfig.Password = *elkPassFlag
		elkConfig.UseTLS = *elkTLSFlag
		elkConfig.SkipVerify = *elkSkipVerifyFlag

		log.Printf("[SYSTEM] ELK output enabled: %s (index: %s)", strings.Join(elkConfig.Addresses, ", "), elkConfig.Index)
	}

	// Create dashboard channel (only if dashboard is enabled)
	var dashboardChan chan string
	if outputMode == config.OutputModeDashboard || outputMode == config.OutputModeBoth {
		dashboardChan = make(chan string, 1000)
	}

	// Configure Dynamic SPA
	var spaConfig *config.DynamicSPAConfig
	if *spaModeFlag != "static" {
		spaConfig = config.DefaultDynamicSPAConfig()
		
		// Set mode
		switch *spaModeFlag {
		case "dynamic":
			spaConfig.Mode = config.SPAModeDynamic
		case "asymmetric":
			spaConfig.Mode = config.SPAModeAsymmetric
		default:
			log.Fatalf("[!] Invalid SPA mode: %s. Use 'static', 'dynamic', or 'asymmetric'", *spaModeFlag)
		}
		
		// Load keys if asymmetric mode
		if spaConfig.Mode == config.SPAModeAsymmetric {
			publicKey, _, err := config.LoadKeysFromFile(
				fmt.Sprintf("%s/spa_public.key", *spaKeyDirFlag),
				"",
			)
			if err != nil {
				log.Printf("[!] Warning: Failed to load public key: %v", err)
				log.Printf("[!] Falling back to static SPA mode")
				spaConfig = nil
			} else {
				spaConfig.PublicKey = publicKey
			}
		}
		
		// Load TOTP secret if provided
		if *spaTOTPSecretFlag != "" {
			totpSecretBytes := []byte(*spaTOTPSecretFlag)
			// Remove newline if present
			if len(totpSecretBytes) > 0 && totpSecretBytes[len(totpSecretBytes)-1] == '\n' {
				totpSecretBytes = totpSecretBytes[:len(totpSecretBytes)-1]
			}
			spaConfig.TOTPSecret = totpSecretBytes
			log.Printf("[SPA] TOTP secret loaded from command line")
		} else {
			// Try to load from file
			totpSecretPath := fmt.Sprintf("%s/totp_secret.txt", *spaKeyDirFlag)
			if totpSecretData, err := os.ReadFile(totpSecretPath); err == nil {
				// Remove newline if present
				if len(totpSecretData) > 0 && totpSecretData[len(totpSecretData)-1] == '\n' {
					totpSecretData = totpSecretData[:len(totpSecretData)-1]
				}
				spaConfig.TOTPSecret = totpSecretData
				log.Printf("[SPA] TOTP secret loaded from file: %s", totpSecretPath)
			} else {
				log.Printf("[!] Warning: TOTP secret not found at %s, using default (may cause authentication failures)", totpSecretPath)
				log.Printf("[!] To fix: Create %s or use -spa-totp-secret flag", totpSecretPath)
			}
		}
	}

	// Create and start agent
	agentInstance, err := agent.New(*interfaceFlag, outputMode, elkConfig, dashboardChan, spaConfig)
	if err != nil {
		log.Fatalf("[!] Failed to initialize agent: %v", err)
	}
	defer agentInstance.Close()

	// Start agent services
	if err := agentInstance.Start(); err != nil {
		log.Fatalf("[!] Failed to start agent: %v", err)
	}

	// Start dashboard only if enabled
	if outputMode == config.OutputModeDashboard || outputMode == config.OutputModeBoth {
		// Get eBPF objects for dashboard
		phantomObjs, egressObjs := agentInstance.GetEBPFObjects()

		// Start dashboard
		dashboardInstance := dashboard.New(
			agentInstance.GetInterfaceName(),
			phantomObjs,
			egressObjs,
			dashboardChan,
		)
		dashboardInstance.Start()
	} else {
		// ELK-only mode: wait for interrupt
		log.Printf("[SYSTEM] Running in ELK-only mode. Press Ctrl+C to stop.")
		fmt.Println("[SYSTEM] Logs are being sent to Elasticsearch. No dashboard will be displayed.")
		select {} // Block forever
	}
}
