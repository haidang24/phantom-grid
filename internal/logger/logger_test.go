package logger

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLogAttackWritesAuditEntry(t *testing.T) {
	const baseDir = "test-logger-tmp"

	// Ensure a clean base directory
	_ = os.RemoveAll(baseDir)
	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		t.Fatalf("failed to create base dir: %v", err)
	}

	// Change working directory to an isolated location and restore afterwards.
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	if err := os.Chdir(baseDir); err != nil {
		t.Fatalf("failed to chdir to base dir: %v", err)
	}
	defer func() {
		_ = os.Chdir(oldWD)
		_ = os.RemoveAll(baseDir)
	}()

	ip := "1.2.3.4"
	cmd := "whoami"

	LogAttack(ip, cmd)

	logFile := filepath.Join("logs", "audit.json")
	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("expected log file to be written, got error: %v", err)
	}

	var entry AttackLog
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatalf("failed to unmarshal log entry: %v", err)
	}

	if entry.AttackerIP != ip {
		t.Fatalf("AttackerIP = %q, want %q", entry.AttackerIP, ip)
	}
	if entry.Command != cmd {
		t.Fatalf("Command = %q, want %q", entry.Command, cmd)
	}
	if entry.RiskLevel == "" {
		t.Fatalf("RiskLevel should not be empty")
	}
	if entry.Timestamp == "" {
		t.Fatalf("Timestamp should not be empty")
	}
}
