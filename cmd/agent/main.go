package main

import (
	"flag"
	"fmt"
	"log"
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

	// Create and start agent
	agentInstance, err := agent.New(*interfaceFlag, outputMode, elkConfig, dashboardChan)
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
