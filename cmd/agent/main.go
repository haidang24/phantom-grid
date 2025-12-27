package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	ui "github.com/gizak/termui/v3"
	"github.com/gizak/termui/v3/widgets"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go Phantom ../../bpf/phantom.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go Egress ../../bpf/phantom_egress.c

// Log Channel for TUI
var logChan = make(chan string, 100)

// Fake Banner Database - "The Mirage" Module
var (
	sshBanners = []string{
		"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n",
		"SSH-2.0-OpenSSH_7.4 Debian-10+deb9u7\r\n",
		"SSH-2.0-OpenSSH_8.0 FreeBSD-20200214\r\n",
		"SSH-2.0-OpenSSH_7.9 CentOS-7.9\r\n",
		"SSH-2.0-OpenSSH_8.1 RedHat-8.1\r\n",
		"SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u4\r\n",
		"SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3\r\n",
		"SSH-2.0-OpenSSH_8.4p1 Arch Linux\r\n",
	}

	httpBanners = []string{
		"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)\r\n\r\n",
		"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Debian)\r\n\r\n",
		"HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\n\r\n",
		"HTTP/1.1 200 OK\r\nServer: nginx/1.20.1\r\n\r\n",
	}

	mysqlBanners = []string{
		"\x0a5.7.35-0ubuntu0.18.04.1\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
		"\x0a8.0.27-0ubuntu0.20.04.1\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
		"\x0a10.3.34-MariaDB-1:10.3.34+maria~focal\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	}

	redisBanners = []string{
		"$6\r\nRedis\r\n",
		"$7\r\nRedis 6.2.6\r\n",
		"$7\r\nRedis 5.0.7\r\n",
	}

	ftpBanners = []string{
		"220 ProFTPD 1.3.6 Server (ProFTPD Default Installation) [::ffff:192.168.1.1]\r\n",
		"220 (vsFTPd 3.0.3)\r\n",
		"220 Microsoft FTP Service\r\n",
	}

	telnetBanners = []string{
		"Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-74-generic x86_64)\r\n\r\n* Documentation:  https://help.ubuntu.com\r\n* Management:     https://landscape.canonical.com\r\n* Support:        https://ubuntu.com/advantage\r\n\r\n  System information as of ",
		"Red Hat Enterprise Linux Server release 7.9 (Maipo)\r\nKernel 3.10.0-1160.el7.x86_64 on an x86_64\r\n\r\nlogin: ",
		"CentOS Linux 7 (Core)\r\nKernel 3.10.0-1160.el7.x86_64 on an x86_64\r\n\r\nlocalhost login: ",
		"Debian GNU/Linux 10\r\n\r\nlocalhost login: ",
	}

	// Service type probabilities (for randomization) - The Mirage effect
	// Mỗi kết nối sẽ nhận được một dịch vụ ngẫu nhiên, tạo "Ghost Grid"
	serviceTypes = []string{"ssh", "http", "mysql", "redis", "ftp", "telnet"}
)

// AttackLog is the structured format used by the Shadow Recorder
type AttackLog struct {
	Timestamp  string `json:"timestamp"`
	AttackerIP string `json:"src_ip"`
	Command    string `json:"command"`
	RiskLevel  string `json:"risk_level"`
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

func main() {
	// 1. Initialize System
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("[!] Failed to lock memory:", err)
	}

	// 2. Load eBPF Programs
	objs := PhantomObjects{}
	if err := LoadPhantomObjects(&objs, nil); err != nil {
		log.Fatal("[!] Failed to load eBPF objects:", err)
	}
	defer objs.Close()

	// 3. Attach XDP to Interface
	// QUAN TRỌNG: Hãy đảm bảo tên interface (eth0, ens33, lo...) đúng với máy bạn
	// Tự động detect interface: ưu tiên eth0, ens33, sau đó fallback về lo
	ifaceName := ""
	var iface *net.Interface
	var err error
	
	// Try common interface names - ưu tiên external interface trước
	// Để "The Mirage" hoạt động, cần attach vào interface nhận traffic từ bên ngoài
	interfaceNames := []string{"eth0", "ens33", "enp0s3", "enp0s8"}
	var foundExternal bool
	for _, name := range interfaceNames {
		iface, err = net.InterfaceByName(name)
		if err == nil {
			// Kiểm tra xem interface có IP address không (không phải loopback)
			addrs, _ := iface.Addrs()
			if len(addrs) > 0 {
				ifaceName = name
				foundExternal = true
				log.Printf("[*] Using network interface: %s (index: %d)", ifaceName, iface.Index)
				break
			}
		}
	}
	
	// Fallback to loopback nếu không tìm thấy external interface
	if !foundExternal {
		iface, err = net.InterfaceByName("lo")
		if err == nil {
			ifaceName = "lo"
			log.Printf("[*] Using loopback interface: %s (index: %d) - for local testing only", ifaceName, iface.Index)
			log.Printf("[!] WARNING: For production, attach to external interface (eth0, ens33, etc.)")
		}
	}
	
	if ifaceName == "" {
		log.Fatal("[!] No suitable network interface found. Please check your network configuration.")
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.PhantomProg,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatal("[!] Failed to attach XDP:", err)
	}
	defer l.Close()

	// 3.1 Load and attach TC Egress Program (DLP) using netlink
	var egressObjs EgressObjects
	var egressObjsPtr *EgressObjects

	if err := LoadEgressObjects(&egressObjs, nil); err != nil {
		log.Printf("[!] Warning: Failed to load TC egress objects: %v", err)
	} else {
		// Setup TC Egress using netlink
		if err := attachTCEgress(iface, &egressObjs); err != nil {
			log.Printf("[!] Warning: Failed to attach TC egress: %v", err)
			egressObjs.Close()
			egressObjsPtr = nil
		} else {
			// Success
			egressObjsPtr = &egressObjs
			logChan <- "[SYSTEM] TC Egress Hook attached (DLP Active)"

			defer func() {
				egressObjs.Close()
			}()
		}
	}

	// 3.2 Start SPA Whitelist Manager
	go manageSPAWhitelist(&objs)
	
	// Log interface info for debugging
	logChan <- fmt.Sprintf("[SYSTEM] XDP attached to interface: %s (index: %d)", ifaceName, iface.Index)
	logChan <- fmt.Sprintf("[SYSTEM] SPA Magic Packet port: 1337")
	logChan <- fmt.Sprintf("[SYSTEM] SSH port 22 protected - requires SPA whitelist")

	// 4. Start Internal Honeypot
	go startHoneypot()

	// 5. Start Dashboard
	startDashboard(ifaceName, &objs, egressObjsPtr)
}

// Helper function to attach TC Egress using netlink
func attachTCEgress(iface *net.Interface, objs *EgressObjects) error {
	// FIX: Sử dụng _ để bỏ qua biến không dùng, tránh lỗi "declared and not used"
	_, err := netlink.LinkByIndex(iface.Index)
	if err != nil {
		return fmt.Errorf("could not get link: %v", err)
	}

	// 1. Add clsact qdisc (allows attaching BPF to ingress/egress)
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: iface.Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}

	if err := netlink.QdiscAdd(qdisc); err != nil && !os.IsExist(err) {
		// Just log, might fail if already exists which is fine
	}

	// 2. Add BPF Filter to Egress
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: iface.Index,
			Parent:    netlink.HANDLE_MIN_EGRESS, // Egress hook
			Handle:    1,
			Protocol:  unix.ETH_P_ALL,
			Priority:  1,
		},
		Fd:           objs.PhantomEgressProg.FD(),
		Name:         "phantom_egress",
		DirectAction: true,
	}

	if err := netlink.FilterAdd(filter); err != nil {
		return fmt.Errorf("failed to add filter: %v", err)
	}

	return nil
}

// manageSPAWhitelist periodically checks SPA statistics and logs changes
func manageSPAWhitelist(objs *PhantomObjects) {
	ticker := time.NewTicker(2 * time.Second)
	var lastSuccessCount uint64 = 0
	var lastFailedCount uint64 = 0
	
	for range ticker.C {
		// Check SPA auth success counter
		var key uint32 = 0
		var successVal uint64
		if err := objs.SpaAuthSuccess.Lookup(key, &successVal); err == nil {
			if successVal > lastSuccessCount {
				logChan <- fmt.Sprintf("[SPA] ✅ Successful authentication! (Total: %d)", successVal)
				lastSuccessCount = successVal
			}
		}
		
		// Check SPA auth failed counter
		var failedVal uint64
		if err := objs.SpaAuthFailed.Lookup(key, &failedVal); err == nil {
			if failedVal > lastFailedCount {
				logChan <- fmt.Sprintf("[SPA] ❌ Failed authentication attempt (Total: %d)", failedVal)
				lastFailedCount = failedVal
			}
		}
	}
}

// logAttack writes a structured AttackLog entry
func logAttack(ip string, cmd string) {
	entry := AttackLog{
		Timestamp:  time.Now().Format(time.RFC3339),
		AttackerIP: ip,
		Command:    cmd,
		RiskLevel:  "HIGH",
	}
	if err := os.MkdirAll("logs", 0o755); err != nil {
		return
	}
	file, err := os.OpenFile("logs/audit.json", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer file.Close()
	if err := json.NewEncoder(file).Encode(entry); err != nil {
		// Silent fail for logging errors
		_ = err
	}
}

// --- DASHBOARD UI ---
func startDashboard(iface string, objs *PhantomObjects, egressObjs *EgressObjects) {
	if err := ui.Init(); err != nil {
		log.Fatalf("failed to initialize termui: %v", err)
	}
	defer ui.Close()

	startTime := time.Now()

	// Thread-safe statistics
	var statsMutex sync.RWMutex
	honeypotConnections := uint64(0)
	totalCommands := uint64(0)
	activeSessions := uint64(0)

	// Get terminal dimensions
	termWidth, termHeight := ui.TerminalDimensions()
	if termWidth < 100 {
		termWidth = 100
	}
	if termHeight < 30 {
		termHeight = 30
	}

	// Header with enhanced information
	header := widgets.NewParagraph()
	header.Title = " ═══ PHANTOM GRID - ACTIVE DEFENSE SYSTEM ═══ "
	header.Text = fmt.Sprintf("STATUS: [ACTIVE](fg:green,mod:bold) | INTERFACE: [%s](fg:yellow) | MODE: [eBPF KERNEL TRAP](fg:red) | UPTIME: [00:00:00](fg:cyan)", iface)
	header.SetRect(0, 0, termWidth, 3)
	header.TextStyle.Fg = ui.ColorCyan
	header.BorderStyle.Fg = ui.ColorCyan

	// Real-time forensics log (left side, larger)
	logList := widgets.NewList()
	logList.Title = " ═══ REAL-TIME FORENSICS & EVENT LOG ═══ "
	logList.Rows = []string{
		"[SYSTEM] Phantom Grid initialized...",
		"[SYSTEM] eBPF XDP Hook attached...",
		"[SYSTEM] TC Egress Hook attached (DLP Active)...",
		"[SYSTEM] Honeypot service listening on port 9999...",
		"[SYSTEM] Dashboard ready. Monitoring traffic...",
	}
	logList.SetRect(0, 3, termWidth/2+10, termHeight-8)
	logList.TextStyle.Fg = ui.ColorGreen
	logList.SelectedRowStyle.Fg = ui.ColorWhite
	logList.SelectedRowStyle.Bg = ui.ColorBlue
	logList.BorderStyle.Fg = ui.ColorGreen

	// Threat Level Gauge
	gauge := widgets.NewGauge()
	gauge.Title = " ═══ THREAT LEVEL ═══ "
	gauge.Percent = 0
	gauge.SetRect(termWidth/2+10, 3, termWidth, 6)
	gauge.BarColor = ui.ColorGreen
	gauge.Label = "0%"
	gauge.BorderStyle.Fg = ui.ColorYellow

	// Statistics Section - Row 1
	redirectedBox := widgets.NewParagraph()
	redirectedBox.Title = " ═══ REDIRECTED TO HONEYPOT ═══ "
	redirectedBox.Text = "\n\n       0"
	redirectedBox.SetRect(termWidth/2+10, 6, termWidth/2+25, 11)
	redirectedBox.TextStyle.Fg = ui.ColorYellow
	redirectedBox.BorderStyle.Fg = ui.ColorYellow

	stealthBox := widgets.NewParagraph()
	stealthBox.Title = " ═══ STEALTH SCAN DROPS ═══ "
	stealthBox.Text = "\n\n       0"
	stealthBox.SetRect(termWidth/2+25, 6, termWidth/2+40, 11)
	stealthBox.TextStyle.Fg = ui.ColorRed
	stealthBox.BorderStyle.Fg = ui.ColorRed

	egressBox := widgets.NewParagraph()
	egressBox.Title = " ═══ EGRESS BLOCKS (DLP) ═══ "
	egressBox.Text = "\n\n       0"
	egressBox.SetRect(termWidth/2+40, 6, termWidth, 11)
	egressBox.TextStyle.Fg = ui.ColorMagenta
	egressBox.BorderStyle.Fg = ui.ColorMagenta

	// Statistics Section - Row 2
	osMutationsBox := widgets.NewParagraph()
	osMutationsBox.Title = " ═══ OS PERSONALITY MUTATIONS ═══ "
	osMutationsBox.Text = "\n\n       0"
	osMutationsBox.SetRect(termWidth/2+10, 11, termWidth/2+25, 16)
	osMutationsBox.TextStyle.Fg = ui.ColorCyan
	osMutationsBox.BorderStyle.Fg = ui.ColorCyan

	spaSuccessBox := widgets.NewParagraph()
	spaSuccessBox.Title = " ═══ SPA AUTH SUCCESS ═══ "
	spaSuccessBox.Text = "\n\n       0"
	spaSuccessBox.SetRect(termWidth/2+25, 11, termWidth/2+40, 16)
	spaSuccessBox.TextStyle.Fg = ui.ColorGreen
	spaSuccessBox.BorderStyle.Fg = ui.ColorGreen

	spaFailedBox := widgets.NewParagraph()
	spaFailedBox.Title = " ═══ SPA AUTH FAILED ═══ "
	spaFailedBox.Text = "\n\n       0"
	spaFailedBox.SetRect(termWidth/2+40, 11, termWidth, 16)
	spaFailedBox.TextStyle.Fg = ui.ColorRed
	spaFailedBox.BorderStyle.Fg = ui.ColorRed

	// System Information Section
	systemInfoBox := widgets.NewParagraph()
	systemInfoBox.Title = " ═══ SYSTEM INFORMATION ═══ "
	egressStatus := "INACTIVE"
	egressColor := "red"
	if egressObjs != nil {
		egressStatus = "ACTIVE"
		egressColor = "green"
	}
	systemInfoBox.Text = fmt.Sprintf("\nInterface: %s\nXDP Hook: [ACTIVE](fg:green)\nTC Egress: [%s](fg:%s)\nHoneypot: [LISTENING](fg:green)\nPort: 9999\nSPA Port: 1337\nSSH Port: 22 (Protected)",
		iface, egressStatus, egressColor)
	systemInfoBox.SetRect(termWidth/2+10, 16, termWidth, termHeight-8)
	systemInfoBox.BorderStyle.Fg = ui.ColorBlue

	// Connection Statistics
	connStatsBox := widgets.NewParagraph()
	connStatsBox.Title = " ═══ CONNECTION STATISTICS ═══ "
	connStatsBox.Text = "\n\nHoneypot Connections: 0\nActive Sessions: 0\nTotal Commands: 0"
	connStatsBox.SetRect(0, termHeight-8, termWidth/2+10, termHeight-3)
	connStatsBox.BorderStyle.Fg = ui.ColorMagenta

	// Footer with instructions
	footer := widgets.NewParagraph()
	footer.Title = " CONTROLS "
	footer.Text = "Press [q](fg:yellow) or [Ctrl+C](fg:yellow) to exit | [SPACE](fg:yellow) to pause/resume logs"
	footer.SetRect(0, termHeight-3, termWidth, termHeight)
	footer.BorderStyle.Fg = ui.ColorWhite

	// Initial render
	ui.Render(header, logList, gauge, redirectedBox, stealthBox, egressBox,
		osMutationsBox, spaSuccessBox, spaFailedBox, systemInfoBox, connStatsBox, footer)

	ticker := time.NewTicker(200 * time.Millisecond)
	statsTicker := time.NewTicker(1 * time.Second)
	uptimeTicker := time.NewTicker(1 * time.Second)
	uiEvents := ui.PollEvents()
	threatCount := 0
	paused := false

	// Update uptime
	go func() {
		for range uptimeTicker.C {
			uptime := time.Since(startTime)
			hours := int(uptime.Hours())
			minutes := int(uptime.Minutes()) % 60
			seconds := int(uptime.Seconds()) % 60
			header.Text = fmt.Sprintf("STATUS: [ACTIVE](fg:green,mod:bold) | INTERFACE: [%s](fg:yellow) | MODE: [eBPF KERNEL TRAP](fg:red) | UPTIME: [%02d:%02d:%02d](fg:cyan)",
				iface, hours, minutes, seconds)
			ui.Render(header)
		}
	}()

	// Update statistics
	go func() {
		for range statsTicker.C {
			var attackKey uint32 = 0
			var attackVal uint64
			if err := objs.AttackStats.Lookup(attackKey, &attackVal); err == nil {
				redirectedBox.Text = fmt.Sprintf("\n\n   %d", attackVal)
			}

			var stealthKey uint32 = 0
			var stealthVal uint64
			if err := objs.StealthDrops.Lookup(stealthKey, &stealthVal); err == nil {
				stealthBox.Text = fmt.Sprintf("\n\n   %d", stealthVal)
			}

			var osKey uint32 = 0
			var osVal uint64
			if err := objs.OsMutations.Lookup(osKey, &osVal); err == nil {
				osMutationsBox.Text = fmt.Sprintf("\n\n   %d", osVal)
			}

			var spaSuccessKey uint32 = 0
			var spaSuccessVal uint64
			if err := objs.SpaAuthSuccess.Lookup(spaSuccessKey, &spaSuccessVal); err == nil {
				spaSuccessBox.Text = fmt.Sprintf("\n\n   %d", spaSuccessVal)
			}

			var spaFailedKey uint32 = 0
			var spaFailedVal uint64
			if err := objs.SpaAuthFailed.Lookup(spaFailedKey, &spaFailedVal); err == nil {
				spaFailedBox.Text = fmt.Sprintf("\n\n   %d", spaFailedVal)
			}

			if egressObjs != nil && egressObjs.EgressBlocks != nil {
				var egressKey uint32 = 0
				var egressVal uint64
				if err := egressObjs.EgressBlocks.Lookup(egressKey, &egressVal); err == nil {
					egressBox.Text = fmt.Sprintf("\n\n   %d", egressVal)
				}
			}

			// Update connection statistics (thread-safe read)
			statsMutex.RLock()
			connCount := honeypotConnections
			sessionCount := activeSessions
			cmdCount := totalCommands
			statsMutex.RUnlock()

			connStatsBox.Text = fmt.Sprintf("\n\nHoneypot Connections: %d\nActive Sessions: %d\nTotal Commands: %d",
				connCount, sessionCount, cmdCount)

			// Calculate threat level based on multiple factors
			totalThreats := attackVal + stealthVal
			if totalThreats > 0 {
				threatLevel := int((totalThreats * 10) % 100)
				if threatLevel > 100 {
					threatLevel = 100
				}
				gauge.Percent = threatLevel
				if threatLevel < 30 {
					gauge.BarColor = ui.ColorGreen
					gauge.Label = fmt.Sprintf("%d%% - LOW", threatLevel)
				} else if threatLevel < 70 {
					gauge.BarColor = ui.ColorYellow
					gauge.Label = fmt.Sprintf("%d%% - MEDIUM", threatLevel)
				} else {
					gauge.BarColor = ui.ColorRed
					gauge.Label = fmt.Sprintf("%d%% - HIGH", threatLevel)
				}
			}

			ui.Render(redirectedBox, stealthBox, egressBox, osMutationsBox,
				spaSuccessBox, spaFailedBox, gauge, connStatsBox)
		}
	}()

	for {
		select {
		case e := <-uiEvents:
			if e.Type == ui.KeyboardEvent {
				if e.ID == "q" || e.ID == "<C-c>" {
					return
				}
				if e.ID == " " {
					paused = !paused
					if paused {
						logChan <- "[SYSTEM] Log scrolling paused"
					} else {
						logChan <- "[SYSTEM] Log scrolling resumed"
					}
				}
			}
		case msg := <-logChan:
			if !paused {
				logList.Rows = append(logList.Rows, msg)
				if len(logList.Rows) > termHeight-15 {
					logList.Rows = logList.Rows[1:]
				}
				logList.ScrollBottom()
			}

			// Track statistics from log messages (thread-safe write)
			statsMutex.Lock()
			if strings.Contains(msg, "TRAP HIT") {
				honeypotConnections++
				activeSessions++
			}
			if strings.Contains(msg, "COMMAND") {
				totalCommands++
			}
			if strings.Contains(msg, "exit") {
				if activeSessions > 0 {
					activeSessions--
				}
			}
			statsMutex.Unlock()

			threatCount++
			ui.Render(logList, connStatsBox)
		case <-ticker.C:
			ui.Render(logList, connStatsBox)
		}
	}
}

// Fake Ports - "The Mirage": Các port giả mà honeypot sẽ bind
// Khi quét từ bên ngoài, nmap sẽ thấy các port này "mở"
var fakePorts = []int{
	80,    // HTTP
	443,   // HTTPS
	3306,  // MySQL
	5432,  // PostgreSQL
	6379,  // Redis
	27017, // MongoDB
	8080,  // Admin Panel
	8443,  // HTTPS Alt
	9000,  // Admin Panel
	21,    // FTP
	23,    // Telnet
	3389,  // RDP
	5900,  // VNC
	1433,  // MSSQL
	1521,  // Oracle
	5433,  // PostgreSQL Alt
	11211, // Memcached
	27018, // MongoDB Shard
	9200,  // Elasticsearch
	5601,  // Kibana
	3000,  // Node.js
	5000,  // Flask
	8000,  // Django
	8888,  // Jupyter
	9999,  // Honeypot (fallback)
}

// --- HONEYPOT LOGIC ---
// "The Mirage": Bind nhiều port giả để tạo "Ghost Grid"
// Khi quét từ bên ngoài, nmap sẽ thấy nhiều port "mở" thay vì chỉ thấy port 9999
func startHoneypot() {
	var listeners []net.Listener
	var wg sync.WaitGroup

	// Bind tất cả các port giả
	for _, port := range fakePorts {
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			// Port có thể đã được sử dụng, skip
			continue
		}
		listeners = append(listeners, ln)
		logChan <- fmt.Sprintf("[SYSTEM] Honeypot listening on port %d", port)

		wg.Add(1)
		go func(l net.Listener, p int) {
			defer wg.Done()
			for {
				conn, err := l.Accept()
				if err != nil {
					logChan <- fmt.Sprintf("[ERROR] Honeypot accept error on port %d: %v", p, err)
					continue
				}
				// Lưu port gốc vào connection context để honeypot biết port nào đang được connect
				go handleConnection(conn, p)
			}
		}(ln, port)
	}

	if len(listeners) == 0 {
		logChan <- "[ERROR] Failed to bind any fake ports"
		return
	}

	logChan <- fmt.Sprintf("[SYSTEM] Honeypot bound to %d fake ports (The Mirage active)", len(listeners))
	
	// Cleanup on exit
	defer func() {
		for _, ln := range listeners {
			ln.Close()
		}
	}()

	wg.Wait()
}

func getRandomBanner(serviceType string) string {
	switch serviceType {
	case "ssh":
		return sshBanners[rand.Intn(len(sshBanners))]
	case "http":
		return httpBanners[rand.Intn(len(httpBanners))]
	case "mysql":
		return mysqlBanners[rand.Intn(len(mysqlBanners))]
	case "redis":
		return redisBanners[rand.Intn(len(redisBanners))]
	case "ftp":
		return ftpBanners[rand.Intn(len(ftpBanners))]
	case "telnet":
		return telnetBanners[rand.Intn(len(telnetBanners))]
	default:
		return sshBanners[rand.Intn(len(sshBanners))]
	}
}

func selectRandomService() string {
	return serviceTypes[rand.Intn(len(serviceTypes))]
}

// selectServiceByPort: Chọn service type dựa trên port để tạo ảo giác thực tế hơn
// "The Mirage": Mỗi port sẽ có service type phù hợp, tạo "Ghost Grid" chân thực
func selectServiceByPort(port int) string {
	switch port {
	case 80, 443, 8080, 8443, 8000, 8888:
		return "http"
	case 3306, 5432, 1433, 1521:
		return "mysql"
	case 6379, 11211:
		return "redis"
	case 27017, 27018:
		return "mysql" // MongoDB handshake tương tự MySQL
	case 21:
		return "ftp"
	case 23:
		return "telnet"
	case 3389, 5900:
		return "ssh" // RDP/VNC giả lập như SSH
	case 9200, 5601:
		return "http" // Elasticsearch/Kibana giả lập như HTTP
	case 3000, 5000:
		return "http" // Node.js/Flask giả lập như HTTP
	default:
		// Random cho các port khác
		return selectRandomService()
	}
}

func handleConnection(conn net.Conn, originalPort int) {
	defer conn.Close()
	remoteAddr := conn.RemoteAddr()
	if remoteAddr == nil {
		return
	}
	remote := remoteAddr.String()
	// Extract IP address only (remove port)
	ip := strings.Split(remote, ":")[0]
	t := time.Now().Format("15:04:05")

	// Chọn service type dựa trên port (để tạo ảo giác thực tế hơn)
	serviceType := selectServiceByPort(originalPort)
	banner := getRandomBanner(serviceType)

	logChan <- fmt.Sprintf("[%s] TRAP HIT! IP: %s | Port: %d | Service: %s", t, ip, originalPort, strings.ToUpper(serviceType))
	logAttack(ip, fmt.Sprintf("TRAP_HIT_PORT_%d", originalPort))

	if _, err := conn.Write([]byte(banner)); err != nil {
		logChan <- fmt.Sprintf("[%s] Error sending banner to %s: %v", t, ip, err)
		return
	}

	// The Mirage: Mỗi kết nối nhận một dịch vụ ngẫu nhiên
	// Tạo "Ghost Grid" - hacker thấy hàng ngàn cổng "mở" với các dịch vụ khác nhau
	switch serviceType {
	case "ssh":
		handleSSHInteraction(conn, remote, t)
	case "http":
		handleHTTPInteraction(conn, remote, t)
	case "telnet":
		handleTelnetInteraction(conn, remote, t)
	default:
		handleSSHInteraction(conn, remote, t)
	}
}

func handleSSHInteraction(conn net.Conn, remote, t string) {
	buf := make([]byte, 1024)
	for {
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			return
		}
		input := strings.TrimSpace(string(buf[:n]))
		if len(input) > 0 {
			logChan <- fmt.Sprintf("[%s] COMMAND: %s", t, input)
			// Extract IP from remote address
			ip := strings.Split(remote, ":")[0]
			logAttack(ip, input)
		}
		if input == "exit" {
			return
		}
		if _, err := conn.Write([]byte("bash: command not found\n")); err != nil {
			return
		}
	}
}

func handleHTTPInteraction(conn net.Conn, remote, t string) {
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}
	if n > 0 {
		// Extract IP from remote address
		ip := strings.Split(remote, ":")[0]
		logAttack(ip, fmt.Sprintf("HTTP_REQUEST: %s", strings.TrimSpace(string(buf[:n]))))
	}
	if _, err := conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\nServer Running")); err != nil {
		return
	}
}

func handleTelnetInteraction(conn net.Conn, remote, t string) {
	buf := make([]byte, 1024)
	for {
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			return
		}
		input := strings.TrimSpace(string(buf[:n]))
		if len(input) > 0 {
			logChan <- fmt.Sprintf("[%s] TELNET COMMAND: %s", t, input)
			// Extract IP from remote address
			ip := strings.Split(remote, ":")[0]
			logAttack(ip, fmt.Sprintf("TELNET: %s", input))
		}
		if input == "exit" || input == "quit" {
			return
		}
		// Simulate telnet response
		if _, err := conn.Write([]byte("Command not found.\r\n")); err != nil {
			return
		}
	}
}
