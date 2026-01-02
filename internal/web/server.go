package web

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"phantom-grid/internal/ebpf"
)

// Server manages the web interface
type Server struct {
	phantomObjs  *ebpf.PhantomObjects
	egressObjs   *ebpf.EgressObjects
	iface        string
	port         int
	startTime    time.Time
	logChan      <-chan string
	logs         []LogEntry
	logsMutex    sync.RWMutex
	maxLogs      int
	stats        *Statistics
	statsMutex   sync.RWMutex
}

// LogEntry represents a single log entry
type LogEntry struct {
	Timestamp string `json:"timestamp"`
	Message   string `json:"message"`
}

// Statistics holds current system statistics
type Statistics struct {
	Redirected     uint64 `json:"redirected"`
	Stealth        uint64 `json:"stealth"`
	OSMutations    uint64 `json:"os_mutations"`
	SPASuccess     uint64 `json:"spa_success"`
	SPAFailed      uint64 `json:"spa_failed"`
	EgressBlocks   uint64 `json:"egress_blocks"`
	HoneypotConns  uint64 `json:"honeypot_conns"`
	ActiveSessions uint64 `json:"active_sessions"`
	TotalCommands  uint64 `json:"total_commands"`
	Uptime         string `json:"uptime"`
	Interface      string `json:"interface"`
}

// NewServer creates a new web server instance
func NewServer(iface string, port int, phantomObjs *ebpf.PhantomObjects, egressObjs *ebpf.EgressObjects, logChan <-chan string) *Server {
	return &Server{
		phantomObjs: phantomObjs,
		egressObjs:  egressObjs,
		iface:       iface,
		port:        port,
		startTime:   time.Now(),
		logChan:     logChan,
		logs:        make([]LogEntry, 0),
		maxLogs:     1000,
		stats:       &Statistics{Interface: iface},
	}
}

// Start starts the web server
func (s *Server) Start() error {
	// Start log collector
	go s.collectLogs()

	// Start statistics updater
	go s.updateStatistics()

	// Setup routes
	http.HandleFunc("/", s.handleIndex)
	http.HandleFunc("/api/stats", s.handleStats)
	http.HandleFunc("/api/logs", s.handleLogs)
	http.HandleFunc("/api/events", s.handleEvents)
	http.HandleFunc("/api/logs-stream", s.handleLogsStream)

	// Serve static files
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("web/static"))))

	addr := fmt.Sprintf(":%d", s.port)
	log.Printf("[WEB] Starting web interface on http://localhost%s", addr)
	log.Printf("[WEB] Open http://localhost%s in your browser", addr)

	return http.ListenAndServe(addr, nil)
}

// collectLogs collects log messages from the channel
func (s *Server) collectLogs() {
	for msg := range s.logChan {
		entry := LogEntry{
			Timestamp: time.Now().Format("2006-01-02 15:04:05"),
			Message:   msg,
		}

		s.logsMutex.Lock()
		s.logs = append(s.logs, entry)
		if len(s.logs) > s.maxLogs {
			s.logs = s.logs[len(s.logs)-s.maxLogs:]
		}
		s.logsMutex.Unlock()
		
		// Log to stdout for debugging
		log.Printf("[WEB] Received log: %s", msg)
	}
}

// updateStatistics periodically updates statistics from eBPF maps
func (s *Server) updateStatistics() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		stats := &Statistics{
			Interface: s.iface,
			Uptime:    formatUptime(time.Since(s.startTime)),
		}

		// Read from eBPF maps
		var key uint32 = 0

		if s.phantomObjs != nil {
			if s.phantomObjs.AttackStats != nil {
				var val uint64
				if err := s.phantomObjs.AttackStats.Lookup(key, &val); err == nil {
					stats.Redirected = val
				}
			}

			if s.phantomObjs.StealthDrops != nil {
				var val uint64
				if err := s.phantomObjs.StealthDrops.Lookup(key, &val); err == nil {
					stats.Stealth = val
				}
			}

			if s.phantomObjs.OsMutations != nil {
				var val uint64
				if err := s.phantomObjs.OsMutations.Lookup(key, &val); err == nil {
					stats.OSMutations = val
				}
			}

			if s.phantomObjs.SpaAuthSuccess != nil {
				var val uint64
				if err := s.phantomObjs.SpaAuthSuccess.Lookup(key, &val); err == nil {
					stats.SPASuccess = val
				}
			}

			if s.phantomObjs.SpaAuthFailed != nil {
				var val uint64
				if err := s.phantomObjs.SpaAuthFailed.Lookup(key, &val); err == nil {
					stats.SPAFailed = val
				}
			}
		}

		if s.egressObjs != nil && s.egressObjs.EgressBlocks != nil {
			var val uint64
			if err := s.egressObjs.EgressBlocks.Lookup(key, &val); err == nil {
				stats.EgressBlocks = val
			}
		}

		s.statsMutex.Lock()
		s.stats = stats
		s.statsMutex.Unlock()
	}
}

// formatUptime formats duration as HH:MM:SS
func formatUptime(d time.Duration) string {
	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60
	return fmt.Sprintf("%02d:%02d:%02d", hours, minutes, seconds)
}

// handleIndex serves the main HTML page
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, getHTMLTemplate())
}

// handleStats returns current statistics as JSON
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	s.statsMutex.RLock()
	stats := *s.stats
	s.statsMutex.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// handleLogs returns recent logs as JSON
func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	s.logsMutex.RLock()
	logs := make([]LogEntry, len(s.logs))
	copy(logs, s.logs)
	s.logsMutex.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(logs)
}

// handleEvents handles Server-Sent Events (SSE) for real-time updates
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			s.statsMutex.RLock()
			stats := *s.stats
			s.statsMutex.RUnlock()

			data, _ := json.Marshal(stats)
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}

// handleLogsStream handles Server-Sent Events for real-time log streaming
func (s *Server) handleLogsStream(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	// Send initial logs
	s.logsMutex.RLock()
	logs := make([]LogEntry, len(s.logs))
	copy(logs, s.logs)
	lastLogCount := len(s.logs)
	s.logsMutex.RUnlock()

	initialData, _ := json.Marshal(logs)
	fmt.Fprintf(w, "data: %s\n\n", initialData)
	flusher.Flush()

	// Poll for new logs
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			s.logsMutex.RLock()
			currentLogCount := len(s.logs)
			if currentLogCount > lastLogCount {
				// Send only new logs
				newLogs := s.logs[lastLogCount:]
				lastLogCount = currentLogCount
				s.logsMutex.RUnlock()

				data, _ := json.Marshal(newLogs)
				fmt.Fprintf(w, "data: %s\n\n", data)
				flusher.Flush()
			} else {
				s.logsMutex.RUnlock()
			}
		}
	}
}

