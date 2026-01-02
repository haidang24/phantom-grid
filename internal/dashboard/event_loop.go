package dashboard

import (
	"fmt"
	"time"

	ui 	"github.com/gizak/termui/v3"
)

// runEventLoop runs the main dashboard event loop
func (d *Dashboard) runEventLoop(w *DashboardWidgets) {
	// Initial render
	ui.Render(w.header, w.logList, w.gauge, w.redirectedBox, w.stealthBox, w.egressBox,
		w.osMutationsBox, w.spaSuccessBox, w.spaFailedBox, w.systemInfoBox, w.connStatsBox, w.footer)

	ticker := time.NewTicker(200 * time.Millisecond)
	statsTicker := time.NewTicker(1 * time.Second)
	uptimeTicker := time.NewTicker(1 * time.Second)
	uiEvents := ui.PollEvents()
	paused := false
	autoScroll := true
	var lastAttackCount uint64 = 0

	// Update uptime
	go func() {
		for range uptimeTicker.C {
			uptime := time.Since(d.startTime)
			hours := int(uptime.Hours())
			minutes := int(uptime.Minutes()) % 60
			seconds := int(uptime.Seconds()) % 60
			w.header.Text = fmt.Sprintf("STATUS: [ACTIVE](fg:green,mod:bold) | INTERFACE: [%s](fg:yellow) | MODE: [eBPF KERNEL TRAP](fg:red) | UPTIME: [%02d:%02d:%02d](fg:cyan)",
				d.iface, hours, minutes, seconds)
			ui.Render(w.header)
		}
	}()

	// Update statistics
	go func() {
		for range statsTicker.C {
			d.updateStatistics(w, &lastAttackCount)
		}
	}()

	// Main event loop
	for {
		select {
		case e := <-uiEvents:
			if e.Type == ui.KeyboardEvent {
				switch e.ID {
				case "q", "<C-c>":
					return
				case " ":
					paused = !paused
					msg := "[SYSTEM] Log scrolling paused"
					if !paused {
						msg = "[SYSTEM] Log scrolling resumed"
					}
					d.handleLogMessage(msg, w, paused, &autoScroll)
				case "j", "<Down>":
					w.logList.ScrollDown()
					autoScroll = false
					ui.Render(w.logList, w.connStatsBox)
				case "k", "<Up>":
					w.logList.ScrollUp()
					autoScroll = false
					ui.Render(w.logList, w.connStatsBox)
				case "g", "<Home>":
					w.logList.ScrollTop()
					autoScroll = false
					ui.Render(w.logList, w.connStatsBox)
				case "G", "<End>":
					w.logList.ScrollBottom()
					autoScroll = true
					ui.Render(w.logList, w.connStatsBox)
				case "a":
					autoScroll = !autoScroll
					msg := "[SYSTEM] Auto-scroll disabled (press 'a' to enable, 'G' to go to bottom)"
					if autoScroll {
						w.logList.ScrollBottom()
						msg = "[SYSTEM] Auto-scroll enabled (press 'a' to disable)"
					}
					d.handleLogMessage(msg, w, paused, &autoScroll)
					ui.Render(w.logList, w.connStatsBox)
				}
			}
		case msg := <-d.logChan:
			d.handleLogMessage(msg, w, paused, &autoScroll)
		case <-ticker.C:
			ui.Render(w.logList, w.connStatsBox)
		}
	}
}

// updateStatistics updates all dashboard statistics
func (d *Dashboard) updateStatistics(w *DashboardWidgets, lastAttackCount *uint64) {
	var attackKey uint32 = 0
	var attackVal uint64
	if err := d.phantomObjs.AttackStats.Lookup(attackKey, &attackVal); err == nil {
		w.redirectedBox.Text = fmt.Sprintf("\n\n   %d\n\n   Total Attacks", attackVal)

		if attackVal > *lastAttackCount {
			*lastAttackCount = attackVal
		}
	} else {
		w.redirectedBox.Text = "\n\n   0\n\n   Total Attacks"
	}

	var stealthKey uint32 = 0
	var stealthVal uint64
	if err := d.phantomObjs.StealthDrops.Lookup(stealthKey, &stealthVal); err == nil {
		w.stealthBox.Text = fmt.Sprintf("\n\n   %d\n\n   Stealth Scans", stealthVal)
	} else {
		w.stealthBox.Text = "\n\n   0\n\n   Stealth Scans"
	}

	var osKey uint32 = 0
	var osVal uint64
	if err := d.phantomObjs.OsMutations.Lookup(osKey, &osVal); err == nil {
		w.osMutationsBox.Text = fmt.Sprintf("\n\n   %d\n\n   OS Mutations", osVal)
	} else {
		w.osMutationsBox.Text = "\n\n   0\n\n   OS Mutations"
	}

	var spaSuccessKey uint32 = 0
	var spaSuccessVal uint64
	if err := d.phantomObjs.SpaAuthSuccess.Lookup(spaSuccessKey, &spaSuccessVal); err == nil {
		w.spaSuccessBox.Text = fmt.Sprintf("\n\n   %d\n\n   Successful", spaSuccessVal)
	} else {
		w.spaSuccessBox.Text = "\n\n   0\n\n   Successful"
	}

	var spaFailedKey uint32 = 0
	var spaFailedVal uint64
	if err := d.phantomObjs.SpaAuthFailed.Lookup(spaFailedKey, &spaFailedVal); err == nil {
		w.spaFailedBox.Text = fmt.Sprintf("\n\n   %d\n\n   Failed", spaFailedVal)
	} else {
		w.spaFailedBox.Text = "\n\n   0\n\n   Failed"
	}

	if d.egressObjs != nil && d.egressObjs.EgressBlocks != nil {
		var egressKey uint32 = 0
		var egressVal uint64
		if err := d.egressObjs.EgressBlocks.Lookup(egressKey, &egressVal); err == nil {
			w.egressBox.Text = fmt.Sprintf("\n\n   %d", egressVal)
		}
	}

	// Update connection statistics
	d.statsMutex.RLock()
	connCount := d.honeypotConns
	sessionCount := d.activeSessions
	cmdCount := d.totalCommands
	d.statsMutex.RUnlock()

	w.connStatsBox.Text = fmt.Sprintf("\n\nHoneypot Connections: %d\nActive Sessions: %d\nTotal Commands: %d",
		connCount, sessionCount, cmdCount)

	// Calculate threat level
	totalThreats := attackVal + stealthVal
	if totalThreats > 0 {
		threatLevel := int((totalThreats * 10) % 100)
		if threatLevel > 100 {
			threatLevel = 100
		}
		w.gauge.Percent = threatLevel
		if threatLevel < 30 {
			w.gauge.BarColor = ui.ColorGreen
			w.gauge.Label = fmt.Sprintf("%d%% - LOW", threatLevel)
		} else if threatLevel < 70 {
			w.gauge.BarColor = ui.ColorYellow
			w.gauge.Label = fmt.Sprintf("%d%% - MEDIUM", threatLevel)
		} else {
			w.gauge.BarColor = ui.ColorRed
			w.gauge.Label = fmt.Sprintf("%d%% - HIGH", threatLevel)
		}
	}

	ui.Render(w.redirectedBox, w.stealthBox, w.egressBox, w.osMutationsBox,
		w.spaSuccessBox, w.spaFailedBox, w.gauge, w.connStatsBox)
}

// handleLogMessage processes log messages and updates UI
func (d *Dashboard) handleLogMessage(msg string, w *DashboardWidgets, paused bool, autoScroll *bool) {
	if !paused {
		// Format message with timestamp and colors
		formattedMsg := FormatLogMessage(msg)
		w.logList.Rows = append(w.logList.Rows, formattedMsg)
		maxLogs := 1000 // Keep more history for detailed logs
		if len(w.logList.Rows) > maxLogs {
			w.logList.Rows = w.logList.Rows[len(w.logList.Rows)-maxLogs:]
		}
		if *autoScroll {
			w.logList.ScrollBottom()
		}
	}

	// Update statistics
	d.ProcessLogMessage(msg)

	ui.Render(w.logList, w.connStatsBox)
}

