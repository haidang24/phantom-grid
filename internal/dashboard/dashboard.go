package dashboard

import (
	"fmt"
	"strings"
	"sync"
	"time"

	ui "github.com/gizak/termui/v3"

	"phantom-grid/internal/ebpf"
)

// Dashboard manages the TUI dashboard
type Dashboard struct {
	phantomObjs  *ebpf.PhantomObjects
	egressObjs   *ebpf.EgressObjects
	iface        string
	startTime    time.Time
	statsMutex   sync.RWMutex
	honeypotConns uint64
	activeSessions uint64
	totalCommands  uint64
	logChan       <-chan string
}

// New creates a new Dashboard instance
func New(iface string, phantomObjs *ebpf.PhantomObjects, egressObjs *ebpf.EgressObjects, logChan <-chan string) *Dashboard {
	return &Dashboard{
		phantomObjs: phantomObjs,
		egressObjs:  egressObjs,
		iface:       iface,
		startTime:   time.Now(),
		logChan:     logChan,
	}
}

// Start initializes and runs the dashboard
func (d *Dashboard) Start() {
	if err := ui.Init(); err != nil {
		panic(fmt.Sprintf("failed to initialize termui: %v", err))
	}
	defer ui.Close()

	termWidth, termHeight := ui.TerminalDimensions()
	if termWidth < 100 {
		termWidth = 100
	}
	if termHeight < 30 {
		termHeight = 30
	}

	widgets := d.createWidgets(termWidth, termHeight)
	d.runEventLoop(widgets)
}

// ProcessLogMessage processes a log message and updates statistics
func (d *Dashboard) ProcessLogMessage(msg string) {
	d.statsMutex.Lock()
	if strings.Contains(msg, "TRAP HIT") {
		d.honeypotConns++
		d.activeSessions++
	}
	if strings.Contains(msg, "COMMAND") {
		d.totalCommands++
	}
	if strings.Contains(msg, "exit") {
		if d.activeSessions > 0 {
			d.activeSessions--
		}
	}
	d.statsMutex.Unlock()
}

