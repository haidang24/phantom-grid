package dashboard

import (
	"fmt"
	"strings"
	"time"
)

// FormatLogMessage formats a log message with timestamp and emoji prefix
func FormatLogMessage(msg string) string {
	timestamp := time.Now().Format("15:04:05")
	
	// Determine emoji prefix based on message type
	var prefix string
	
	msgUpper := strings.ToUpper(msg)
	
	switch {
	case strings.Contains(msgUpper, "[SPA]") && (strings.Contains(msgUpper, "SUCCESS") || strings.Contains(msgUpper, "WHITELISTED")):
		prefix = "✓"
	case strings.Contains(msgUpper, "[SPA]") && (strings.Contains(msgUpper, "FAILED") || strings.Contains(msgUpper, "INVALID") || strings.Contains(msgUpper, "ERROR")):
		prefix = "✗"
	case strings.Contains(msgUpper, "[SPA]") && strings.Contains(msgUpper, "RECEIVED"):
		prefix = "→"
	case strings.Contains(msgUpper, "[SPA]"):
		prefix = "🔐"
	case strings.Contains(msgUpper, "[TRAP]"):
		prefix = "🎣"
	case strings.Contains(msgUpper, "[STEALTH]"):
		prefix = "👻"
	case strings.Contains(msgUpper, "[OS-MUTATION]"):
		prefix = "🔄"
	case strings.Contains(msgUpper, "[SYSTEM]"):
		prefix = "⚙"
	case strings.Contains(msgUpper, "[WARN]"):
		prefix = "⚠"
	case strings.Contains(msgUpper, "[ERROR]"):
		prefix = "❌"
	default:
		prefix = "•"
	}
	
	// Format: [HH:MM:SS] prefix message
	formatted := fmt.Sprintf("[%s] %s %s", timestamp, prefix, msg)
	return formatted
}

