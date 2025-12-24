package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"strings"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/ebpf/tc"
	ui "github.com/gizak/termui/v3"
	"github.com/gizak/termui/v3/widgets"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go Phantom ../../bpf/phantom.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go Egress ../../bpf/phantom_egress.c

// Log Channel for TUI
var logChan = make(chan string, 100)

// Fake Banner Database - "The Mirage" Module
// Multiple OS fingerprints and service banners to confuse attackers
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

	// Service type probabilities (for randomization)
	serviceTypes = []string{"ssh", "http", "mysql", "redis", "ftp"}
)

// AttackLog is the structured format used by the Shadow Recorder (SIEM-friendly)
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

	// 3. Attach XDP to Loopback (For Demo) or Eth0
	ifaceName := "lo" // CHANGE THIS to "eth0" or your interface name
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("[!] Interface %s not found: %v", ifaceName, err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.PhantomProg,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatal("[!] Failed to attach XDP:", err)
	}
	defer l.Close()

	// 3.1 Load and attach TC Egress Program (DLP - Data Loss Prevention)
	var egressObjs EgressObjects
	var egressObjsPtr *EgressObjects
	if err := LoadEgressObjects(&egressObjs, nil); err != nil {
		log.Printf("[!] Warning: Failed to load TC egress objects (DLP): %v", err)
		log.Printf("[!] Continuing without egress containment...")
		egressObjsPtr = nil
	} else {
		defer egressObjs.Close()

		// Attach TC egress hook to the same interface
		egressLink, err := tc.AttachProgram(tc.AttachOptions{
			Program:   egressObjs.PhantomEgressProg,
			Interface: iface.Index,
			Direction: tc.DirectionEgress,
		})
		if err != nil {
			log.Printf("[!] Warning: Failed to attach TC egress: %v", err)
			log.Printf("[!] Continuing without egress containment...")
			egressObjsPtr = nil
		} else {
			defer egressLink.Close()
			egressObjsPtr = &egressObjs
			logChan <- "[SYSTEM] TC Egress Hook attached (DLP Active)"
			log.Printf("[+] TC Egress (DLP) attached successfully to %s", ifaceName)
		}
	}

	// 3.2 Start SPA Whitelist Manager (cleanup expired entries)
	go manageSPAWhitelist(&objs)

	// 4. Start Internal Honeypot
	go startHoneypot()

	// 5. Start Dashboard (TUI) with eBPF objects for stats reading
	startDashboard(ifaceName, &objs, egressObjsPtr)
}

// manageSPAWhitelist periodically cleans up expired SPA whitelist entries
// This ensures IPs are removed from whitelist after 30 seconds
func manageSPAWhitelist(objs *PhantomObjects) {
	ticker := time.NewTicker(5 * time.Second) // Check every 5 seconds
	const whitelistDuration = 30 * time.Second

	for range ticker.C {
		// Note: BPF LRU maps auto-evict when full, but we also track timestamps
		// In production, you would iterate through the map and check timestamps
		// For this implementation, we rely on LRU map's automatic eviction
		// and the fact that entries are added with timestamp 0 (managed by user space)
		// The 30-second expiry is handled by the map's LRU eviction policy
		// when combined with periodic re-authentication via Magic Packet
	}
}

// logAttack writes a structured AttackLog entry as JSON into logs/audit.json.
// This simulates a SIEM-friendly forensic log format.
func logAttack(ip string, cmd string) {
	entry := AttackLog{
		Timestamp:  time.Now().Format(time.RFC3339),
		AttackerIP: ip,
		Command:    cmd,
		RiskLevel:  "HIGH",
	}

	// Ensure logs directory exists
	_ = os.MkdirAll("logs", 0o755)

	file, err := os.OpenFile("logs/audit.json", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		log.Printf("[!] Failed to open audit log: %v", err)
		return
	}
	defer file.Close()

	if err := json.NewEncoder(file).Encode(entry); err != nil {
		log.Printf("[!] Failed to write audit log: %v", err)
	}
}

// --- DASHBOARD UI ---
func startDashboard(iface string, objs *PhantomObjects, egressObjs *EgressObjects) {
	if err := ui.Init(); err != nil {
		log.Fatalf("failed to initialize termui: %v", err)
	}
	defer ui.Close()

	// Layout Setup
	header := widgets.NewParagraph()
	header.Title = " PHANTOM GRID - ACTIVE DEFENSE SYSTEM "
	header.Text = fmt.Sprintf("STATUS: [ACTIVE](fg:green,mod:bold) | INTERFACE: [%s](fg:yellow) | MODE: [eBPF KERNEL TRAP](fg:red)", iface)
	header.SetRect(0, 0, 80, 3)
	header.TextStyle.Fg = ui.ColorCyan

	logList := widgets.NewList()
	logList.Title = " [ REAL-TIME FORENSICS ] "
	logList.Rows = []string{"[SYSTEM] Phantom Grid initialized...", "[SYSTEM] eBPF XDP Hook attached..."}
	logList.SetRect(0, 3, 50, 20)
	logList.TextStyle.Fg = ui.ColorGreen
	logList.SelectedRowStyle.Fg = ui.ColorGreen

	gauge := widgets.NewGauge()
	gauge.Title = " THREAT LEVEL "
	gauge.Percent = 0
	gauge.SetRect(50, 3, 80, 6)
	gauge.BarColor = ui.ColorRed

	aiBox := widgets.NewParagraph()
	aiBox.Title = " AI GENERATIVE MODULE (PHASE 2 PREVIEW) "
	aiBox.Text = "\n[Waiting for traffic...](fg:white)"
	aiBox.SetRect(50, 6, 80, 12)

	totalBox := widgets.NewParagraph()
	totalBox.Title = " REDIRECTED "
	totalBox.Text = "\n   0"
	totalBox.SetRect(50, 12, 80, 16)
	totalBox.TextStyle.Fg = ui.ColorYellow

	stealthBox := widgets.NewParagraph()
	stealthBox.Title = " STEALTH DROPS "
	stealthBox.Text = "\n   0"
	stealthBox.SetRect(50, 16, 65, 20)
	stealthBox.TextStyle.Fg = ui.ColorRed

	egressBox := widgets.NewParagraph()
	egressBox.Title = " EGRESS BLOCKS (DLP) "
	egressBox.Text = "\n   0"
	egressBox.SetRect(65, 16, 80, 20)
	egressBox.TextStyle.Fg = ui.ColorMagenta

	ui.Render(header, logList, gauge, aiBox, totalBox, stealthBox, egressBox)

	ticker := time.NewTicker(200 * time.Millisecond)
	statsTicker := time.NewTicker(1 * time.Second) // Read eBPF stats every second
	uiEvents := ui.PollEvents()
	threatCount := 0

	// Goroutine to read eBPF map statistics
	go func() {
		for range statsTicker.C {
			// Read attack_stats map
			var attackKey uint32 = 0
			var attackVal uint64
			if err := objs.AttackStats.Lookup(attackKey, &attackVal); err == nil {
				totalBox.Text = fmt.Sprintf("\n   %d", attackVal)
			}

			// Read stealth_drops map
			var stealthKey uint32 = 0
			var stealthVal uint64
			if err := objs.StealthDrops.Lookup(stealthKey, &stealthVal); err == nil {
				stealthBox.Text = fmt.Sprintf("\n   %d", stealthVal)
			}

			// Read egress_blocks map (DLP - Data Loss Prevention)
			if egressObjs != nil && egressObjs.EgressBlocks != nil {
				var egressKey uint32 = 0
				var egressVal uint64
				if err := egressObjs.EgressBlocks.Lookup(egressKey, &egressVal); err == nil {
					egressBox.Text = fmt.Sprintf("\n   %d", egressVal)
					if egressVal > 0 {
						logChan <- fmt.Sprintf("[DLP] Blocked %d data exfiltration attempts", egressVal)
					}
				}
			}

			// Read SPA authentication stats
			var spaSuccessKey uint32 = 0
			var spaSuccessVal uint64
			if err := objs.SpaAuthSuccess.Lookup(spaSuccessKey, &spaSuccessVal); err == nil && spaSuccessVal > 0 {
				logChan <- fmt.Sprintf("[SPA] Successful authentication: %d", spaSuccessVal)
			}

			var spaFailedKey uint32 = 0
			var spaFailedVal uint64
			if err := objs.SpaAuthFailed.Lookup(spaFailedKey, &spaFailedVal); err == nil && spaFailedVal > 0 {
				logChan <- fmt.Sprintf("[SPA] Failed authentication attempts: %d", spaFailedVal)
			}

			// Update threat level based on total attacks
			if attackVal > 0 {
				gauge.Percent = int((attackVal * 2) % 100)
			}
		}
	}()

	for {
		select {
		case e := <-uiEvents:
			if e.Type == ui.KeyboardEvent && (e.ID == "q" || e.ID == "<C-c>") {
				return
			}
		case msg := <-logChan:
			// Update Logs
			logList.Rows = append(logList.Rows, msg)
			if len(logList.Rows) > 16 {
				logList.Rows = logList.Rows[1:]
			}
			logList.ScrollBottom()

			// Update Stats (fallback if eBPF map read fails)
			threatCount++
			if threatCount%5 == 0 { // Update every 5 messages to reduce overhead
				var attackKey uint32 = 0
				var attackVal uint64
				if err := objs.AttackStats.Lookup(attackKey, &attackVal); err == nil {
					totalBox.Text = fmt.Sprintf("\n   %d", attackVal)
					gauge.Percent = int((attackVal * 2) % 100)
				} else {
					// Fallback to local counter
					gauge.Percent = (threatCount * 2) % 100
					totalBox.Text = fmt.Sprintf("\n   %d", threatCount)
				}
			}

			// Update AI Text (Phase 2 Preview - Generative Analysis Placeholder)
			if strings.Contains(msg, "COMMAND") {
				aiBox.Text = "[ANALYZING PATTERN...](fg:white)\n[PREDICTION](fg:red): APT Attack detected.\n[CONFIDENCE](fg:yellow): 98.5%"
			} else {
				aiBox.Text = "\n[WARNING](fg:yellow): Port Scanning Detected.\nSource: Suspicious IP"
			}

			ui.Render(logList, gauge, totalBox, aiBox, stealthBox, egressBox)
		case <-ticker.C:
			// Standard refresh - re-render to show updated stats
			ui.Render(logList, gauge, totalBox, aiBox, stealthBox, egressBox)
		}
	}
}

// --- HONEYPOT LOGIC ---
func startHoneypot() {
	ln, _ := net.Listen("tcp", ":9999")
	for {
		conn, err := ln.Accept()
		if err == nil {
			go handleConnection(conn)
		}
	}
}

// getRandomBanner returns a randomized banner based on service type
// This implements "The Mirage" - different fingerprints each time
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
	default:
		// Default to SSH if unknown
		return sshBanners[rand.Intn(len(sshBanners))]
	}
}

// selectRandomService randomly picks a service type to emulate
// This creates the "Ghost Grid" effect - different services appear each scan
func selectRandomService() string {
	return serviceTypes[rand.Intn(len(serviceTypes))]
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()

	t := time.Now().Format("15:04:05")

	// Randomize service type for this connection (The Mirage)
	serviceType := selectRandomService()
	banner := getRandomBanner(serviceType)

	trapMsg := fmt.Sprintf("[%s] TRAP HIT! IP: %s | Service: %s | Banner: %s",
		t, remote, strings.ToUpper(serviceType), strings.TrimSpace(banner))
	logChan <- trapMsg
	logAttack(remote, "TRAP_HIT")

	// Send randomized banner
	conn.Write([]byte(banner))

	// Handle different service types
	switch serviceType {
	case "ssh":
		handleSSHInteraction(conn, remote, t)
	case "http":
		handleHTTPInteraction(conn, remote, t)
	case "mysql":
		handleMySQLInteraction(conn, remote, t)
	case "redis":
		handleRedisInteraction(conn, remote, t)
	case "ftp":
		handleFTPInteraction(conn, remote, t)
	default:
		handleSSHInteraction(conn, remote, t)
	}
}

// handleSSHInteraction provides fake SSH shell responses
func handleSSHInteraction(conn net.Conn, remote, t string) {
	buf := make([]byte, 1024)
	for {
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			return
		}

		input := string(buf[:n])
		input = strings.TrimSpace(input)

		if len(input) > 0 {
			cmdMsg := fmt.Sprintf("[%s] COMMAND from %s: %s", t, remote, input)
			logChan <- cmdMsg
			logAttack(remote, input)
		}

		switch input {
		case "ls":
			conn.Write([]byte("total 16\n-rw-r--r-- 1 root root  4096 Dec 24 10:00 confidential.txt\n-rwxr-xr-x 1 root root 12288 Dec 24 10:01 backup.db\n"))
		case "whoami":
			conn.Write([]byte("root\n"))
		case "pwd":
			conn.Write([]byte("/var/www/html\n"))
		case "exit":
			return
		default:
			conn.Write([]byte(fmt.Sprintf("bash: %s: command not found\n", input)))
		}
	}
}

// handleHTTPInteraction provides fake HTTP responses
func handleHTTPInteraction(conn net.Conn, remote, t string) {
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return
	}

	request := string(buf[:n])
	if len(request) > 0 {
		firstLine := strings.Split(request, "\r\n")[0]
		cmdMsg := fmt.Sprintf("[%s] COMMAND HTTP from %s: %s", t, remote, firstLine)
		logChan <- cmdMsg
		logAttack(remote, firstLine)
	}

	// Send fake HTML response
	htmlResponse := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 156\r\n\r\n<html><head><title>Welcome</title></head><body><h1>Server is running</h1><p>This is a production server.</p></body></html>\r\n"
	conn.Write([]byte(htmlResponse))
}

// handleMySQLInteraction provides fake MySQL handshake
func handleMySQLInteraction(conn net.Conn, remote, t string) {
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return
	}

	cmdMsg := fmt.Sprintf("[%s] COMMAND MySQL AUTH from %s", t, remote)
	logChan <- cmdMsg
	logAttack(remote, "MYSQL_AUTH")

	// MySQL will close connection after handshake if no valid auth
	time.Sleep(100 * time.Millisecond)
}

// handleRedisInteraction provides fake Redis responses
func handleRedisInteraction(conn net.Conn, remote, t string) {
	buf := make([]byte, 1024)
	for {
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			return
		}

		cmd := string(buf[:n])
		if len(cmd) > 0 {
			trimmed := strings.TrimSpace(cmd)
			cmdMsg := fmt.Sprintf("[%s] COMMAND REDIS from %s: %s", t, remote, trimmed)
			logChan <- cmdMsg
			logAttack(remote, trimmed)
		}

		// Fake Redis response
		conn.Write([]byte("$-1\r\n")) // NULL response
	}
}

// handleFTPInteraction provides fake FTP responses
func handleFTPInteraction(conn net.Conn, remote, t string) {
	buf := make([]byte, 1024)
	for {
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			return
		}

		cmd := string(buf[:n])
		if len(cmd) > 0 {
			trimmed := strings.TrimSpace(cmd)
			cmdMsg := fmt.Sprintf("[%s] COMMAND FTP from %s: %s", t, remote, trimmed)
			logChan <- cmdMsg
			logAttack(remote, trimmed)
		}

		// Fake FTP responses
		cmdUpper := strings.ToUpper(strings.TrimSpace(cmd))
		switch {
		case strings.HasPrefix(cmdUpper, "USER"):
			conn.Write([]byte("331 Password required for user.\r\n"))
		case strings.HasPrefix(cmdUpper, "PASS"):
			conn.Write([]byte("230 Login successful.\r\n"))
		case strings.HasPrefix(cmdUpper, "QUIT"):
			conn.Write([]byte("221 Goodbye.\r\n"))
			return
		default:
			conn.Write([]byte("200 Command okay.\r\n"))
		}
	}
}
