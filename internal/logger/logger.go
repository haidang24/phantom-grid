package logger

import (
	"encoding/json"
	"os"
	"time"
)

// AttackLog is the structured format for attack logging
type AttackLog struct {
	Timestamp  string `json:"timestamp"`
	AttackerIP string `json:"src_ip"`
	Command    string `json:"command"`
	RiskLevel  string `json:"risk_level"`
}

// LogChannel is a channel for sending log messages
var LogChannel = make(chan string, 100)

// LogAttack writes a structured AttackLog entry to disk
func LogAttack(ip string, cmd string) {
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
		_ = err
	}
}

