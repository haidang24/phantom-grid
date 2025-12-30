package spa

import (
	"fmt"
	"net"
	"time"

	"phantom-grid/internal/config"
)

// Client represents an SPA client
type Client struct {
	ServerIP string
}

// NewClient creates a new SPA client
func NewClient(serverIP string) *Client {
	return &Client{
		ServerIP: serverIP,
	}
}

// SendMagicPacket sends the SPA Magic Packet to whitelist the client's IP
func (c *Client) SendMagicPacket() error {
	addr := net.JoinHostPort(c.ServerIP, fmt.Sprintf("%d", config.SPAMagicPort))
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to create UDP connection: %w", err)
	}
	defer conn.Close()

	tokenBytes := []byte(config.SPASecretToken)
	if len(tokenBytes) != config.SPATokenLen {
		return fmt.Errorf("token length mismatch (expected %d, got %d)", config.SPATokenLen, len(tokenBytes))
	}

	_, err = conn.Write(tokenBytes)
	if err != nil {
		return fmt.Errorf("failed to send Magic Packet: %w", err)
	}

	time.Sleep(100 * time.Millisecond)
	return nil
}
