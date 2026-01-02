package dashboard

import (
	"fmt"

	ui "github.com/gizak/termui/v3"
	"github.com/gizak/termui/v3/widgets"

	"phantom-grid/internal/config"
)

// DashboardWidgets holds all UI widgets
type DashboardWidgets struct {
	header        *widgets.Paragraph
	logList       *widgets.List
	gauge         *widgets.Gauge
	redirectedBox *widgets.Paragraph
	stealthBox    *widgets.Paragraph
	egressBox     *widgets.Paragraph
	osMutationsBox *widgets.Paragraph
	spaSuccessBox *widgets.Paragraph
	spaFailedBox  *widgets.Paragraph
	systemInfoBox *widgets.Paragraph
	connStatsBox  *widgets.Paragraph
	footer        *widgets.Paragraph
}

// createWidgets creates and configures all dashboard widgets
func (d *Dashboard) createWidgets(termWidth, termHeight int) *DashboardWidgets {
	w := &DashboardWidgets{}

	// Header
	w.header = widgets.NewParagraph()
	w.header.Title = " ═══ PHANTOM GRID - ACTIVE DEFENSE SYSTEM ═══ "
	w.header.Text = fmt.Sprintf("STATUS: [ACTIVE](fg:green,mod:bold) | INTERFACE: [%s](fg:yellow) | MODE: [eBPF KERNEL TRAP](fg:red) | UPTIME: [00:00:00](fg:cyan)", d.iface)
	w.header.SetRect(0, 0, termWidth, 3)
	w.header.TextStyle.Fg = ui.ColorCyan
	w.header.BorderStyle.Fg = ui.ColorCyan

	// Calculate responsive layout
	// Left panel (logs): 50% of width, minimum 50 chars
	logPanelWidth := termWidth * 50 / 100
	if logPanelWidth < 50 {
		logPanelWidth = 50
	}
	rightPanelStart := logPanelWidth
	rightPanelWidth := termWidth - rightPanelStart

	// Statistics boxes: divide right panel into 3 equal columns
	boxWidth := rightPanelWidth / 3
	if boxWidth < 20 {
		boxWidth = 20
	}

	// Log list
	w.logList = widgets.NewList()
	w.logList.Title = " ═══ REAL-TIME FORENSICS & EVENT LOG (j/k: scroll, a: auto-scroll, G: bottom) ═══ "
	w.logList.Rows = []string{
		"[SYSTEM] Phantom Grid initialized...",
		"[SYSTEM] eBPF XDP Hook attached...",
		"[SYSTEM] TC Egress Hook attached (DLP Active)...",
		"[SYSTEM] Honeypot service listening on port 9999...",
		"[SYSTEM] Dashboard ready. Monitoring traffic...",
		"[HELP] Use 'j'/'k' to scroll, 'G' to go to bottom, 'a' to toggle auto-scroll",
	}
	w.logList.SetRect(0, 3, logPanelWidth, termHeight-8)
	w.logList.TextStyle.Fg = ui.ColorGreen
	w.logList.SelectedRowStyle.Fg = ui.ColorWhite
	w.logList.SelectedRowStyle.Bg = ui.ColorBlue
	w.logList.BorderStyle.Fg = ui.ColorGreen

	// Threat gauge
	w.gauge = widgets.NewGauge()
	w.gauge.Title = " ═══ THREAT LEVEL ═══ "
	w.gauge.Percent = 0
	w.gauge.SetRect(rightPanelStart, 3, termWidth, 6)
	w.gauge.BarColor = ui.ColorGreen
	w.gauge.Label = "0%"
	w.gauge.BorderStyle.Fg = ui.ColorYellow

	// Statistics boxes - Row 1
	w.redirectedBox = widgets.NewParagraph()
	w.redirectedBox.Title = " ═══ REDIRECTED TO HONEYPOT ═══ "
	w.redirectedBox.Text = "\n\n   0\n\n   Total Attacks"
	w.redirectedBox.SetRect(rightPanelStart, 6, rightPanelStart+boxWidth, 11)
	w.redirectedBox.TextStyle.Fg = ui.ColorYellow
	w.redirectedBox.BorderStyle.Fg = ui.ColorYellow

	w.stealthBox = widgets.NewParagraph()
	w.stealthBox.Title = " ═══ STEALTH SCAN DROPS ═══ "
	w.stealthBox.Text = "\n\n   0\n\n   Stealth Scans"
	w.stealthBox.SetRect(rightPanelStart+boxWidth, 6, rightPanelStart+boxWidth*2, 11)
	w.stealthBox.TextStyle.Fg = ui.ColorRed
	w.stealthBox.BorderStyle.Fg = ui.ColorRed

	w.egressBox = widgets.NewParagraph()
	w.egressBox.Title = " ═══ EGRESS BLOCKS (DLP) ═══ "
	w.egressBox.Text = "\n\n       0"
	w.egressBox.SetRect(rightPanelStart+boxWidth*2, 6, termWidth, 11)
	w.egressBox.TextStyle.Fg = ui.ColorMagenta
	w.egressBox.BorderStyle.Fg = ui.ColorMagenta

	// Statistics boxes - Row 2
	w.osMutationsBox = widgets.NewParagraph()
	w.osMutationsBox.Title = " ═══ OS PERSONALITY MUTATIONS ═══ "
	w.osMutationsBox.Text = "\n\n   0\n\n   OS Mutations"
	w.osMutationsBox.SetRect(rightPanelStart, 11, rightPanelStart+boxWidth, 16)
	w.osMutationsBox.TextStyle.Fg = ui.ColorCyan
	w.osMutationsBox.BorderStyle.Fg = ui.ColorCyan

	w.spaSuccessBox = widgets.NewParagraph()
	w.spaSuccessBox.Title = " ═══ SPA AUTH SUCCESS ═══ "
	w.spaSuccessBox.Text = "\n\n   0\n\n   Successful"
	w.spaSuccessBox.SetRect(rightPanelStart+boxWidth, 11, rightPanelStart+boxWidth*2, 16)
	w.spaSuccessBox.TextStyle.Fg = ui.ColorGreen
	w.spaSuccessBox.BorderStyle.Fg = ui.ColorGreen

	w.spaFailedBox = widgets.NewParagraph()
	w.spaFailedBox.Title = " ═══ SPA AUTH FAILED ═══ "
	w.spaFailedBox.Text = "\n\n   0\n\n   Failed"
	w.spaFailedBox.SetRect(rightPanelStart+boxWidth*2, 11, termWidth, 16)
	w.spaFailedBox.TextStyle.Fg = ui.ColorRed
	w.spaFailedBox.BorderStyle.Fg = ui.ColorRed

	// System info
	w.systemInfoBox = widgets.NewParagraph()
	w.systemInfoBox.Title = " ═══ SYSTEM INFORMATION ═══ "
	egressStatus := "INACTIVE"
	egressColor := "red"
	if d.egressObjs != nil {
		egressStatus = "ACTIVE"
		egressColor = "green"
	}
	w.systemInfoBox.Text = fmt.Sprintf("\nInterface: %s\nXDP Hook: [ACTIVE](fg:green)\nTC Egress: [%s](fg:%s)\nHoneypot: [LISTENING](fg:green)\nPort: %d\nSPA Port: %d\nSSH Port: %d (Protected)",
		d.iface, egressStatus, egressColor, config.HoneypotPort, config.SPAMagicPort, config.SSHPort)
	w.systemInfoBox.SetRect(rightPanelStart, 16, termWidth, termHeight-8)
	w.systemInfoBox.BorderStyle.Fg = ui.ColorBlue

	// Connection stats
	w.connStatsBox = widgets.NewParagraph()
	w.connStatsBox.Title = " ═══ CONNECTION STATISTICS ═══ "
	w.connStatsBox.Text = "\n\nHoneypot Connections: 0\nActive Sessions: 0\nTotal Commands: 0"
	w.connStatsBox.SetRect(0, termHeight-8, logPanelWidth, termHeight-3)
	w.connStatsBox.BorderStyle.Fg = ui.ColorMagenta

	// Footer
	w.footer = widgets.NewParagraph()
	w.footer.Title = " CONTROLS "
	w.footer.Text = "Press [q](fg:yellow) or [Ctrl+C](fg:yellow) to exit | [SPACE](fg:yellow) to pause/resume logs"
	w.footer.SetRect(0, termHeight-3, termWidth, termHeight)
	w.footer.BorderStyle.Fg = ui.ColorWhite

	return w
}

