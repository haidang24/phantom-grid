package main

import (
	"flag"
	"log"

	"phantom-grid/internal/agent"
	"phantom-grid/internal/dashboard"
	"phantom-grid/internal/logger"
)

func main() {
	// Parse command line arguments
	interfaceFlag := flag.String("interface", "", "Network interface name (e.g., eth0, ens33, wlx00127b2163a6). If not specified, auto-detect will be used.")
	flag.Parse()

	// Create and start agent
	agentInstance, err := agent.New(*interfaceFlag)
	if err != nil {
		log.Fatalf("[!] Failed to initialize agent: %v", err)
	}
	defer agentInstance.Close()

	// Start agent services
	if err := agentInstance.Start(); err != nil {
		log.Fatalf("[!] Failed to start agent: %v", err)
	}

	// Get eBPF objects for dashboard
	phantomObjs, egressObjs := agentInstance.GetEBPFObjects()

	// Start dashboard
	dashboardInstance := dashboard.New(
		agentInstance.GetInterfaceName(),
		phantomObjs,
		egressObjs,
		logger.LogChannel,
	)
	dashboardInstance.Start()
}
