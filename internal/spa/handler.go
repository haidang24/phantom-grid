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

	h.logChan <- fmt.Sprintf("[SPA] User-space handler started on port %d", config.SPAMagicPort)
	h.logChan <- fmt.Sprintf("[SPA] Mode: %s", h.spaConfig.Mode)

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

	for {
		select {
		case <-h.stopChan:
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
				h.logChan <- fmt.Sprintf("[SPA] Read error: %v", err)
				continue
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
		// Legacy static token - whitelist IP in user-space
		if h.mapLoader == nil {
			h.logChan <- fmt.Sprintf("[SPA] Static packet received but mapLoader not available")
			return
		}
		
		// Whitelist IP for static SPA (use default duration)
		duration := config.SPAWhitelistDuration
		if h.spaConfig != nil && h.spaConfig.ReplayWindowSeconds > 0 {
			duration = h.spaConfig.ReplayWindowSeconds
		}
		
		if err := h.mapLoader.WhitelistIP(clientIP, duration); err != nil {
			h.logChan <- fmt.Sprintf("[SPA] Failed to whitelist IP %s for static SPA: %v", clientIP, err)
			return
		}
		
		h.logChan <- fmt.Sprintf("[SPA] Successfully authenticated and whitelisted IP: %s (static token, length: %d)", clientIP, len(packetData))
		return
	}
	
	// If not static packet and not dynamic packet, log for debugging
	if len(packetData) > 0 {
		debugLen := 8
		if len(packetData) < debugLen {
			debugLen = len(packetData)
		}
		h.logChan <- fmt.Sprintf("[SPA] Received non-matching packet from %s (length: %d, first bytes: %x)", clientIP, len(packetData), packetData[:debugLen])
	}

	// Parse dynamic packet
	packet, err := ParseSPAPacket(packetData)
	if err != nil {
		h.logChan <- fmt.Sprintf("[SPA] Failed to parse packet from %s: %v", clientIP, err)
		return
	}

	// Verify packet
	valid, err := h.verifier.VerifyPacket(packetData)
	if !valid {
		h.logChan <- fmt.Sprintf("[SPA] Invalid packet from %s: %v", clientIP, err)
		return
	}

	// Whitelist IP
	if err := h.mapLoader.WhitelistIP(clientIP, h.spaConfig.ReplayWindowSeconds); err != nil {
		h.logChan <- fmt.Sprintf("[SPA] Failed to whitelist IP %s: %v", clientIP, err)
		return
	}

	h.logChan <- fmt.Sprintf("[SPA] Successfully authenticated and whitelisted IP: %s", clientIP)
	h.logChan <- fmt.Sprintf("[SPA] TOTP: %d, Timestamp: %d", packet.TOTP, packet.Timestamp)
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

