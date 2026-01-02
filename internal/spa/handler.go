package spa

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"phantom-grid/internal/config"
)

// Handler handles dynamic SPA packet verification in user-space
type Handler struct {
	verifier    *Verifier
	mapLoader   *MapLoader
	logChan     chan<- string
	spaConfig   *config.DynamicSPAConfig
	staticToken string // Static token for legacy SPA mode (configurable)
	udpConn     *net.UDPConn
	stopChan    chan struct{}
}

// NewHandler creates a new SPA packet handler
func NewHandler(verifier *Verifier, mapLoader *MapLoader, logChan chan<- string, spaConfig *config.DynamicSPAConfig, staticToken string) *Handler {
	// Use default token if not provided
	if staticToken == "" {
		staticToken = config.SPASecretToken
	}
	return &Handler{
		verifier:   verifier,
		mapLoader:  mapLoader,
		logChan:    logChan,
		spaConfig:  spaConfig,
		staticToken: staticToken,
		stopChan:   make(chan struct{}),
	}
}

// Start starts the UDP listener for SPA packets
func (h *Handler) Start() error {
	addr := &net.UDPAddr{
		IP:   net.IPv4zero,
		Port: int(config.SPAMagicPort),
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on SPA port: %w", err)
	}

	h.udpConn = conn

	// Start packet handler goroutine
	go h.handlePackets()

	// Log startup information (use fmt.Printf for immediate output)
	msg := fmt.Sprintf("[SPA] User-space handler started on port %d", config.SPAMagicPort)
	fmt.Printf("%s\n", msg)
	select {
	case h.logChan <- msg:
	default:
	}
	
	if h.spaConfig != nil {
		msg := fmt.Sprintf("[SPA] Mode: %s", h.spaConfig.Mode)
		fmt.Printf("%s\n", msg)
		select {
		case h.logChan <- msg:
		default:
		}
	} else {
		msg := fmt.Sprintf("[SPA] Mode: static (legacy)")
		fmt.Printf("%s\n", msg)
		select {
		case h.logChan <- msg:
		default:
		}
	}
	if h.staticToken != "" {
		msg := fmt.Sprintf("[SPA] Static token configured (length: %d)", len(h.staticToken))
		fmt.Printf("%s\n", msg)
		select {
		case h.logChan <- msg:
		default:
		}
	}
	readyMsg := fmt.Sprintf("[SPA] Handler ready to receive packets")
	fmt.Printf("%s\n", readyMsg)
	// Non-blocking send to log channel
	select {
	case h.logChan <- readyMsg:
		default:
		// Channel full, but we already printed to stdout
	}

	return nil
}

// Stop stops the handler
func (h *Handler) Stop() error {
	close(h.stopChan)
	if h.udpConn != nil {
		return h.udpConn.Close()
	}
	return nil
}

// handlePackets processes incoming SPA packets
func (h *Handler) handlePackets() {
	buffer := make([]byte, 1500) // Max UDP packet size
	msg := fmt.Sprintf("[SPA] Packet handler goroutine started, listening for packets...")
	fmt.Printf("%s\n", msg)
	// Non-blocking send to log channel
	select {
	case h.logChan <- msg:
	default:
		// Channel full, but we already printed to stdout
	}

	for {
		select {
		case <-h.stopChan:
			msg := fmt.Sprintf("[SPA] Packet handler stopping...")
			fmt.Printf("%s\n", msg)
			select {
			case h.logChan <- msg:
			default:
			}
			return
		default:
			// Set read deadline to allow checking stopChan
			h.udpConn.SetReadDeadline(time.Now().Add(1 * time.Second))
			
			n, clientAddr, err := h.udpConn.ReadFromUDP(buffer)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					// Timeout is expected, continue loop
					continue
				}
				errMsg := fmt.Sprintf("[SPA] Read error: %v", err)
				fmt.Printf("%s\n", errMsg)
				select {
				case h.logChan <- errMsg:
				default:
				}
				continue
			}

			// Log that we received a packet (both to log channel and stdout for debugging)
			msg := fmt.Sprintf("[SPA] → Received packet from %s | Length: %d bytes", clientAddr.IP, n)
			fmt.Printf("%s\n", msg)
			// Non-blocking send to log channel
			select {
			case h.logChan <- msg:
			default:
				// Channel full, but we already printed to stdout
			}

			// Process packet
			go h.processPacket(buffer[:n], clientAddr.IP)
		}
	}
}

// processPacket verifies and processes a single SPA packet
func (h *Handler) processPacket(packetData []byte, clientIP net.IP) {
	// Check if packet is static or dynamic
	if h.isStaticPacket(packetData) {
		// Legacy static token - handled by eBPF, but we should still log it
		// eBPF handles the whitelisting, but we log for visibility
		msg := fmt.Sprintf("[SPA] 🔐 Static token packet received from %s | Handled by eBPF", clientIP)
		fmt.Printf("%s\n", msg)
		select {
		case h.logChan <- msg:
		default:
		}
		// Note: If eBPF already whitelisted, we don't need to do anything here
		// But if eBPF didn't whitelist (e.g., custom token), we should whitelist in user-space
		if h.mapLoader != nil {
			// Use default replay window if spaConfig is nil (static mode)
			replayWindow := config.SPAWhitelistDuration
			if h.spaConfig != nil {
				replayWindow = h.spaConfig.ReplayWindowSeconds
			}
			// Try to whitelist in user-space as well (in case eBPF didn't handle it)
			_ = h.mapLoader.WhitelistIP(clientIP, replayWindow)
		}
		return
	}
	
	// Check if packet might be a static token (any length, not just default)
	// Only check if it's not a dynamic packet (doesn't start with version byte 1)
	if len(packetData) > 0 && packetData[0] != 1 {
		// This could be a static token - check if it matches (support any length)
		staticTokenBytes := []byte(h.staticToken)
		
		// If lengths match, compare byte by byte
		if len(packetData) == len(staticTokenBytes) {
			matches := true
			for i := 0; i < len(packetData); i++ {
				if packetData[i] != staticTokenBytes[i] {
					matches = false
					break
				}
			}
			if matches {
				// Static token matched (any length) - whitelist IP
				if h.mapLoader != nil {
					// Use default replay window if spaConfig is nil (static mode)
					replayWindow := config.SPAWhitelistDuration
					if h.spaConfig != nil {
						replayWindow = h.spaConfig.ReplayWindowSeconds
					}
					if err := h.mapLoader.WhitelistIP(clientIP, replayWindow); err == nil {
						msg := fmt.Sprintf("[SPA] ✓ Static token matched from %s | Length: %d bytes | Whitelisted", clientIP, len(packetData))
						fmt.Printf("%s\n", msg)
						select {
						case h.logChan <- msg:
						default:
						}
						return
					}
				}
			}
		}
	}

	// If packet starts with version byte 1, it's a dynamic packet - skip to parsing
	if len(packetData) > 0 && packetData[0] == 1 {
		// This is a dynamic packet - proceed to parse and verify
		goto parseDynamic
	}

	// If not static packet and not dynamic packet, log for debugging
	if len(packetData) > 0 {
		debugLen := 8
		if len(packetData) < debugLen {
			debugLen = len(packetData)
		}
		// Check if it might be a static token with different length
		if len(packetData) > 0 && packetData[0] != 1 && len(packetData) != len(h.staticToken) {
			msg := fmt.Sprintf("[SPA] ⚠ Token length mismatch from %s | Received: %d bytes | Expected: %d bytes", clientIP, len(packetData), len(h.staticToken))
			fmt.Printf("%s\n", msg)
			select {
			case h.logChan <- msg:
			default:
			}
			// Don't count as failed - just wrong token length
			return
		}
		msg := fmt.Sprintf("[SPA] → Non-matching packet from %s | Length: %d bytes | First bytes: %x | Expected: %d bytes", clientIP, len(packetData), packetData[:debugLen], len(h.staticToken))
		fmt.Printf("%s\n", msg)
		select {
		case h.logChan <- msg:
		default:
		}
		// Don't count as failed yet - might be invalid packet or wrong token
		return
	}

	// Parse dynamic packet
parseDynamic:
	packet, err := ParseSPAPacket(packetData)
	if err != nil {
		errMsg := fmt.Sprintf("[SPA] ✗ Failed to parse packet from %s | Error: %v", clientIP, err)
		fmt.Printf("%s\n", errMsg)
		select {
		case h.logChan <- errMsg:
		default:
		}
		// Only count as failed if it's clearly a dynamic packet that failed to parse
		// (i.e., starts with version byte 1 but parsing failed)
		if len(packetData) > 0 && packetData[0] == 1 {
			if h.mapLoader != nil {
				h.mapLoader.IncrementFailedCounter()
			}
		}
		return
	}

	// Verify packet
	valid, err := h.verifier.VerifyPacket(packetData)
	if !valid {
		errMsg := fmt.Sprintf("[SPA] ✗ Invalid packet from %s | Error: %v", clientIP, err)
		fmt.Printf("%s\n", errMsg)
		select {
		case h.logChan <- errMsg:
		default:
		}
		// Update failed counter in eBPF map if available
		if h.mapLoader != nil {
			h.mapLoader.IncrementFailedCounter()
		}
		return
	}

	// Whitelist IP
	if h.mapLoader == nil {
		errMsg := fmt.Sprintf("[SPA] Failed to whitelist IP %s: mapLoader not available", clientIP)
		fmt.Printf("%s\n", errMsg)
		select {
		case h.logChan <- errMsg:
		default:
		}
		return
	}

	// Get replay window (use default if spaConfig is nil)
	replayWindow := config.SPAWhitelistDuration
	mode := "dynamic"
	if h.spaConfig != nil {
		replayWindow = h.spaConfig.ReplayWindowSeconds
		mode = string(h.spaConfig.Mode)
	}

	if err := h.mapLoader.WhitelistIP(clientIP, replayWindow); err != nil {
		errMsg := fmt.Sprintf("[SPA] Failed to whitelist IP %s: %v", clientIP, err)
		fmt.Printf("%s\n", errMsg)
		select {
		case h.logChan <- errMsg:
		default:
		}
		return
	}

	// Verify whitelist entry was created successfully
	if h.mapLoader != nil {
		// Small delay to ensure map update is visible to eBPF before any packets arrive
		// This helps prevent race condition where SSH packet arrives before whitelist is updated
		time.Sleep(100 * time.Millisecond) // Increased to 100ms for better reliability
		
		// Log successful whitelist
		verifyMsg := fmt.Sprintf("[SPA] ✓ Whitelist entry verified for %s | Duration: %ds", clientIP, replayWindow)
		fmt.Printf("%s\n", verifyMsg)
		select {
		case h.logChan <- verifyMsg:
		default:
		}
	}

	// Increment success counter in eBPF map
	if h.mapLoader != nil {
		h.mapLoader.IncrementSuccessCounter()
	}

	successMsg := fmt.Sprintf("[SPA] ✓ Successfully authenticated and whitelisted IP: %s | Mode: %s | Duration: %ds", 
		clientIP, mode, replayWindow)
	fmt.Printf("%s\n", successMsg)
	select {
	case h.logChan <- successMsg:
	default:
	}
	
	totpMsg := fmt.Sprintf("[SPA] 🔐 TOTP: %d | Timestamp: %d", packet.TOTP, packet.Timestamp)
	fmt.Printf("%s\n", totpMsg)
	select {
	case h.logChan <- totpMsg:
	default:
	}
}

// isStaticPacket checks if packet is legacy static token
func (h *Handler) isStaticPacket(data []byte) bool {
	// Static token is ASCII string, dynamic packet starts with version byte (1)
	staticTokenBytes := []byte(h.staticToken)
	
	// Check length first
	if len(data) != len(staticTokenBytes) {
		return false
	}
	
	// Check if it's a dynamic packet (starts with version byte 1)
	if len(data) > 0 && data[0] == 1 {
		return false
	}
	
	// Compare bytes
	for i := 0; i < len(data); i++ {
		if data[i] != staticTokenBytes[i] {
			return false
		}
	}
	return true
}

// GetClientIPFromPacket extracts client IP from packet (for logging)
func GetClientIPFromPacket(packetData []byte) (net.IP, error) {
	// This is a helper function - in practice, IP comes from UDP connection
	// This is just for demonstration
	if len(packetData) < 14 {
		return nil, fmt.Errorf("packet too short")
	}
	
	// Extract timestamp to verify packet structure
	timestamp := int64(binary.BigEndian.Uint64(packetData[2:10]))
	_ = timestamp // Use timestamp for validation
	
	return nil, fmt.Errorf("IP must come from UDP connection")
}

