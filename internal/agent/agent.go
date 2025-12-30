package agent

import (
	"fmt"
	"log"
	"net"
	"os"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"phantom-grid/internal/config"
	"phantom-grid/internal/ebpf"
	"phantom-grid/internal/honeypot"
	"phantom-grid/internal/logger"
	"phantom-grid/internal/network"
	"phantom-grid/internal/spa"
)

// Agent represents the main Phantom Grid agent
type Agent struct {
	ebpfLoader *ebpf.Loader
	iface      *net.Interface
	ifaceName  string
	honeypot   *honeypot.Honeypot
	spaManager *spa.Manager
	logChan    chan<- string
	logManager *logger.Manager
}

// New creates a new Agent instance
func New(interfaceName string, outputMode config.OutputMode, elkConfig config.ELKConfiguration, dashboardChan chan<- string) (*Agent, error) {
	// Detect network interface
	iface, ifaceName, err := network.DetectInterface(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to detect interface: %w", err)
	}

	// Initialize eBPF loader
	ebpfLoader, err := ebpf.NewLoader()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize eBPF loader: %w", err)
	}

	// Load egress program (optional)
	if err := ebpfLoader.LoadEgress(); err != nil {
		log.Printf("[!] Warning: Failed to load TC egress objects: %v", err)
		log.Printf("[!] TC Egress DLP will be disabled. Main XDP protection still active.")
	}

	// Initialize logger manager
	logManager, err := logger.NewManager(outputMode, elkConfig, dashboardChan)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize logger manager: %w", err)
	}

	agent := &Agent{
		ebpfLoader: ebpfLoader,
		iface:      iface,
		ifaceName:  ifaceName,
		logChan:    logManager.LogChannel(),
		logManager: logManager,
	}

	return agent, nil
}

// Start initializes and starts the agent
func (a *Agent) Start() error {
	// Attach XDP
	_, err := a.ebpfLoader.AttachXDP(a.iface.Index)
	if err != nil {
		return fmt.Errorf("failed to attach XDP: %w", err)
	}
	// Note: XDP link is stored in ebpfLoader and will be closed via ebpfLoader.Close()

	log.Printf("[*] XDP attached to interface: %s (index: %d)", a.ifaceName, a.iface.Index)
	a.logChan <- fmt.Sprintf("[SYSTEM] XDP attached to interface: %s (index: %d)", a.ifaceName, a.iface.Index)

	// Attach TC Egress (if loaded)
	if a.ebpfLoader.EgressObjs != nil {
		if err := a.attachTCEgress(); err != nil {
			log.Printf("[!] Warning: Failed to attach TC egress: %v", err)
			log.Printf("[!] TC Egress DLP will be disabled. Main XDP protection still active.")
		} else {
			a.logChan <- "[SYSTEM] TC Egress Hook attached (DLP Active)"
		}
	}

	// Start SPA Manager
	spaWrapper := spa.NewWrapper(
		a.ebpfLoader.PhantomObjs.SpaAuthSuccess,
		a.ebpfLoader.PhantomObjs.SpaAuthFailed,
	)
	a.spaManager = spa.NewManager(spaWrapper, a.logChan, config.SPAWhitelistDuration)
	go a.spaManager.Start()

	// Log system info
	a.logChan <- fmt.Sprintf("[SYSTEM] SPA Magic Packet port: %d", config.SPAMagicPort)
	a.logChan <- fmt.Sprintf("[SYSTEM] SSH port %d protected - requires SPA whitelist", config.SSHPort)

	// Log interface IP addresses
	addrs, err := a.iface.Addrs()
	if err != nil {
		log.Printf("[DEBUG] Failed to get interface addresses: %v", err)
	} else {
		for _, addr := range addrs {
			a.logChan <- fmt.Sprintf("[DEBUG] Interface %s has IP: %s", a.ifaceName, addr.String())
		}
	}

	// Warn if using loopback interface
	if a.ifaceName == "lo" {
		a.logChan <- "[!] WARNING: XDP attached to LOOPBACK interface!"
		a.logChan <- "[!] WARNING: Traffic from external hosts (Kali) will NOT be captured!"
		a.logChan <- "[!] WARNING: For VMware NAT, ensure XDP attaches to external interface (ens33, eth0, etc.)"
		a.logChan <- "[!] WARNING: Check if interface detection is working correctly"
	}

	// Start Honeypot
	a.honeypot = honeypot.New(a.logChan)
	honeypotErrChan := make(chan error, 1)
	go func() {
		if err := a.honeypot.Start(); err != nil {
			honeypotErrChan <- err
			log.Printf("[!] Failed to start honeypot: %v", err)
		}
	}()

	// Check if honeypot started successfully (non-blocking)
	select {
	case err := <-honeypotErrChan:
		return fmt.Errorf("honeypot failed to start: %w", err)
	default:
		// Honeypot started successfully
	}

	return nil
}

// attachTCEgress attaches TC egress program using netlink
func (a *Agent) attachTCEgress() error {
	_, err := netlink.LinkByIndex(a.iface.Index)
	if err != nil {
		return fmt.Errorf("could not get link: %w", err)
	}

	// Add clsact qdisc
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: a.iface.Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}

	if err := netlink.QdiscAdd(qdisc); err != nil && !isExist(err) {
		return fmt.Errorf("failed to add qdisc: %w", err)
	}

	// Add BPF Filter to Egress
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: a.iface.Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    1,
			Protocol:  unix.ETH_P_ALL,
			Priority:  1,
		},
		Fd:           a.ebpfLoader.EgressObjs.PhantomEgressProg.FD(),
		Name:         "phantom_egress",
		DirectAction: true,
	}

	if err := netlink.FilterAdd(filter); err != nil {
		return fmt.Errorf("failed to add filter: %w", err)
	}

	return nil
}

func isExist(err error) bool {
	if err == nil {
		return false
	}
	return os.IsExist(err)
}

// GetEBPFObjects returns eBPF objects for dashboard
func (a *Agent) GetEBPFObjects() (*ebpf.PhantomObjects, *ebpf.EgressObjects) {
	return a.ebpfLoader.PhantomObjs, a.ebpfLoader.EgressObjs
}

// GetInterfaceName returns the interface name
func (a *Agent) GetInterfaceName() string {
	return a.ifaceName
}

// Close cleans up agent resources
func (a *Agent) Close() error {
	if a.honeypot != nil {
		if err := a.honeypot.Close(); err != nil {
			return err
		}
	}
	if a.logManager != nil {
		if err := a.logManager.Close(); err != nil {
			return err
		}
	}
	if a.ebpfLoader != nil {
		return a.ebpfLoader.Close()
	}
	return nil
}
