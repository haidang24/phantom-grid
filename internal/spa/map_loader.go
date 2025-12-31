package spa

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/cilium/ebpf"

	"phantom-grid/internal/config"
)

// MapLoader loads SPA configuration into BPF maps
type MapLoader struct {
	whitelistMap    *ebpf.Map
	replayMap       *ebpf.Map
	totpSecretMap   *ebpf.Map
	hmacSecretMap   *ebpf.Map
	configMap       *ebpf.Map
}

// NewMapLoader creates a new SPA map loader
// Note: Maps must be from the dynamic SPA eBPF program
func NewMapLoader(whitelistMap, replayMap, totpSecretMap, hmacSecretMap, configMap *ebpf.Map) *MapLoader {
	return &MapLoader{
		whitelistMap:  whitelistMap,
		replayMap:     replayMap,
		totpSecretMap: totpSecretMap,
		hmacSecretMap: hmacSecretMap,
		configMap:     configMap,
	}
}

// LoadConfiguration loads SPA configuration into BPF maps
func (ml *MapLoader) LoadConfiguration(spaConfig *config.DynamicSPAConfig) error {
	if ml.configMap == nil {
		return fmt.Errorf("config map not available")
	}

	// Load TOTP secret
	if ml.totpSecretMap != nil && len(spaConfig.TOTPSecret) > 0 {
		if err := ml.loadTOTPSecret(spaConfig.TOTPSecret); err != nil {
			return fmt.Errorf("failed to load TOTP secret: %w", err)
		}
	}

	// Load HMAC secret (for dynamic mode)
	if ml.hmacSecretMap != nil && len(spaConfig.HMACSecret) > 0 {
		if err := ml.loadHMACSecret(spaConfig.HMACSecret); err != nil {
			return fmt.Errorf("failed to load HMAC secret: %w", err)
		}
	}

	// Load configuration values
	configValues := map[uint32]uint32{
		0: uint32(spaConfig.TOTPTimeStep),    // TOTP time step
		1: uint32(spaConfig.TOTPTolerance),  // TOTP tolerance
		2: uint32(spaConfig.ReplayWindowSeconds), // Replay window
		3: uint32(ml.getSPAModeValue(spaConfig.Mode)), // SPA mode
	}

	for key, value := range configValues {
		if err := ml.configMap.Put(key, value); err != nil {
			return fmt.Errorf("failed to set config key %d: %w", key, err)
		}
	}

	return nil
}

// WhitelistIP adds an IP address to the whitelist
func (ml *MapLoader) WhitelistIP(ip net.IP, durationSeconds int) error {
	if ml.whitelistMap == nil {
		return fmt.Errorf("whitelist map not available")
	}

	// Convert IP to network byte order
	ipv4 := ip.To4()
	if ipv4 == nil {
		return fmt.Errorf("invalid IPv4 address: %s", ip.String())
	}

	ipUint32 := binary.BigEndian.Uint32(ipv4)

	// Calculate expiry (nanoseconds)
	// Note: This is a simplified calculation. In production, use bpf_ktime_get_ns() equivalent
	// For now, we'll use a relative duration that the eBPF program will handle
	expiry := uint64(durationSeconds) * 1000000000 // Convert to nanoseconds

	return ml.whitelistMap.Put(ipUint32, expiry)
}

// RemoveWhitelistIP removes an IP from the whitelist
func (ml *MapLoader) RemoveWhitelistIP(ip net.IP) error {
	if ml.whitelistMap == nil {
		return fmt.Errorf("whitelist map not available")
	}

	ipv4 := ip.To4()
	if ipv4 == nil {
		return fmt.Errorf("invalid IPv4 address: %s", ip.String())
	}

	ipUint32 := binary.BigEndian.Uint32(ipv4)
	return ml.whitelistMap.Delete(ipUint32)
}

// loadTOTPSecret loads TOTP secret into BPF map
func (ml *MapLoader) loadTOTPSecret(secret []byte) error {
	if len(secret) > 32 {
		return fmt.Errorf("TOTP secret too long: %d bytes (max 32)", len(secret))
	}

	// Load secret byte by byte into array map
	for i := 0; i < len(secret) && i < 32; i++ {
		key := uint32(i)
		value := secret[i]
		if err := ml.totpSecretMap.Put(key, value); err != nil {
			return fmt.Errorf("failed to set TOTP secret byte %d: %w", i, err)
		}
	}

	return nil
}

// loadHMACSecret loads HMAC secret into BPF map
func (ml *MapLoader) loadHMACSecret(secret []byte) error {
	if len(secret) > 32 {
		return fmt.Errorf("HMAC secret too long: %d bytes (max 32)", len(secret))
	}

	// Load secret byte by byte into array map
	for i := 0; i < len(secret) && i < 32; i++ {
		key := uint32(i)
		value := secret[i]
		if err := ml.hmacSecretMap.Put(key, value); err != nil {
			return fmt.Errorf("failed to set HMAC secret byte %d: %w", i, err)
		}
	}

	return nil
}

// getSPAModeValue converts SPAMode to uint32 for BPF map
func (ml *MapLoader) getSPAModeValue(mode config.SPAMode) uint32 {
	switch mode {
	case config.SPAModeStatic:
		return 0
	case config.SPAModeDynamic:
		return 1
	case config.SPAModeAsymmetric:
		return 2
	default:
		return 0 // Default to static
	}
}

