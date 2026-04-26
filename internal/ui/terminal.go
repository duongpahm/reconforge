// Package ui provides terminal UI components using bubbletea and lipgloss.
package ui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Colors defines the ReconForge color palette.
var (
	ColorPrimary   = lipgloss.Color("#7C3AED") // purple
	ColorSecondary = lipgloss.Color("#06B6D4") // cyan
	ColorSuccess   = lipgloss.Color("#22C55E") // green
	ColorWarning   = lipgloss.Color("#F59E0B") // amber
	ColorDanger    = lipgloss.Color("#EF4444") // red
	ColorMuted     = lipgloss.Color("#6B7280") // gray
	ColorText      = lipgloss.Color("#F9FAFB") // white
)

// Styles provides pre-configured lipgloss styles.
var (
	StyleTitle     lipgloss.Style
	StyleSubtitle  lipgloss.Style
	StyleSuccess   lipgloss.Style
	StyleWarning   lipgloss.Style
	StyleDanger    lipgloss.Style
	StyleMuted     lipgloss.Style
	StyleBox       lipgloss.Style
	StyleStatusBar lipgloss.Style
)

func init() {
	refreshStyles()
}

func refreshStyles() {
	StyleTitle = lipgloss.NewStyle().
		Bold(true).
		MarginBottom(1)
	StyleSubtitle = lipgloss.NewStyle()
	StyleSuccess = lipgloss.NewStyle()
	StyleWarning = lipgloss.NewStyle()
	StyleDanger = lipgloss.NewStyle()
	StyleMuted = lipgloss.NewStyle()
	StyleBox = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		Padding(1, 2)
	StyleStatusBar = lipgloss.NewStyle().
		Padding(0, 1).
		Width(80)

	if !ColorEnabled() {
		return
	}

	StyleTitle = StyleTitle.Foreground(ColorPrimary)
	StyleSubtitle = StyleSubtitle.Foreground(ColorSecondary)
	StyleSuccess = StyleSuccess.Foreground(ColorSuccess)
	StyleWarning = StyleWarning.Foreground(ColorWarning)
	StyleDanger = StyleDanger.Foreground(ColorDanger)
	StyleMuted = StyleMuted.Foreground(ColorMuted)
	StyleBox = StyleBox.BorderForeground(ColorPrimary)
	StyleStatusBar = StyleStatusBar.
		Background(lipgloss.Color("#1F2937")).
		Foreground(ColorText)
}

// ProgressBar renders a progress bar.
type ProgressBar struct {
	Total   int
	Current int
	Width   int
	Label   string
	ShowPct bool
}

// Render returns the progress bar as a string.
func (pb ProgressBar) Render() string {
	if pb.Width == 0 {
		pb.Width = 40
	}

	pct := float64(0)
	if pb.Total > 0 {
		pct = float64(pb.Current) / float64(pb.Total)
	}

	filled := int(pct * float64(pb.Width))
	if filled > pb.Width {
		filled = pb.Width
	}

	bar := strings.Repeat("█", filled) + strings.Repeat("░", pb.Width-filled)

	coloredBar := bar
	if ColorEnabled() {
		coloredBar = lipgloss.NewStyle().Foreground(ColorPrimary).Render(bar[:filled]) +
			lipgloss.NewStyle().Foreground(ColorMuted).Render(bar[filled:])
	}

	result := fmt.Sprintf("%s [%s]", pb.Label, coloredBar)
	if pb.ShowPct {
		result += fmt.Sprintf(" %.0f%%", pct*100)
	}

	return result
}

// ModuleStatus represents a module's status for display.
type ModuleStatus struct {
	Name     string
	Status   string // running, complete, failed, pending
	Duration time.Duration
	Findings int
}

// StatusIcon returns a colored icon for the status.
func (ms ModuleStatus) StatusIcon() string {
	switch ms.Status {
	case "running":
		return StyleWarning.Render("⟳")
	case "complete":
		return StyleSuccess.Render("✓")
	case "failed":
		return StyleDanger.Render("✗")
	case "pending":
		return StyleMuted.Render("○")
	default:
		return "?"
	}
}

// Render returns the module status as a formatted string.
func (ms ModuleStatus) Render() string {
	duration := ""
	if ms.Duration > 0 {
		duration = StyleMuted.Render(fmt.Sprintf(" (%s)", ms.Duration.Round(time.Millisecond)))
	}

	findings := ""
	if ms.Findings > 0 {
		findings = StyleSubtitle.Render(fmt.Sprintf(" [%d found]", ms.Findings))
	}

	return fmt.Sprintf("  %s %s%s%s", ms.StatusIcon(), ms.Name, duration, findings)
}

// Dashboard is the main bubbletea model for the scan dashboard.
type Dashboard struct {
	Target       string
	Mode         string
	ScanID       string
	StartTime    time.Time
	Stages       []StageDisplay
	TotalModules int
	Completed    int
	Failed       int
	Findings     int

	width  int
	height int
	done   bool
}

// StageDisplay represents a stage for the dashboard.
type StageDisplay struct {
	Name    string
	Status  string
	Modules []ModuleStatus
}

// NewDashboard creates a new scan dashboard.
func NewDashboard(target, mode, scanID string) Dashboard {
	refreshStyles()
	return Dashboard{
		Target:    target,
		Mode:      mode,
		ScanID:    scanID,
		StartTime: time.Now(),
	}
}

// TickMsg triggers a dashboard update.
type TickMsg time.Time

// Custom TUI Messages
type StageStartMsg struct {
	Stage string
}
type StageCompleteMsg struct {
	Stage  string
	Status string // "complete" or "failed"
}
type ModuleStartMsg struct {
	Stage  string
	Module string
}
type ModuleCompleteMsg struct {
	Stage    string
	Module   string
	Status   string
	Findings int
	Duration time.Duration
}

// Init initializes the dashboard.
func (d Dashboard) Init() tea.Cmd {
	return tea.Tick(100*time.Millisecond, func(t time.Time) tea.Msg {
		return TickMsg(t)
	})
}

// Update handles messages.
func (d Dashboard) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return d, tea.Quit
		}
	case tea.WindowSizeMsg:
		d.width = msg.Width
		d.height = msg.Height
	case StageStartMsg:
		for i, s := range d.Stages {
			if s.Name == msg.Stage {
				d.Stages[i].Status = "running"
				break
			}
		}
	case StageCompleteMsg:
		for i, s := range d.Stages {
			if s.Name == msg.Stage {
				d.Stages[i].Status = msg.Status
				break
			}
		}
	case ModuleStartMsg:
		for i, s := range d.Stages {
			if s.Name == msg.Stage {
				for j, m := range s.Modules {
					if m.Name == msg.Module {
						d.Stages[i].Modules[j].Status = "running"
						break
					}
				}
				break
			}
		}
	case ModuleCompleteMsg:
		for i, s := range d.Stages {
			if s.Name == msg.Stage {
				for j, m := range s.Modules {
					if m.Name == msg.Module {
						d.Stages[i].Modules[j].Status = msg.Status
						d.Stages[i].Modules[j].Findings = msg.Findings
						d.Stages[i].Modules[j].Duration = msg.Duration
						if msg.Findings > d.Findings {
							d.Findings = msg.Findings
						}
						if msg.Status == "complete" {
							d.Completed++
						} else {
							d.Failed++
						}
						// Global findings update can be tracked elsewhere, or we sum them here
						break
					}
				}
				break
			}
		}
	case TickMsg:
		if d.done {
			return d, tea.Quit
		}
		return d, tea.Tick(100*time.Millisecond, func(t time.Time) tea.Msg {
			return TickMsg(t)
		})
	}
	return d, nil
}

// View renders the dashboard.
func (d Dashboard) View() string {
	var b strings.Builder

	// Header
	b.WriteString(StyleTitle.Render("[*] ReconForge"))
	b.WriteString("\n")
	b.WriteString(StyleSubtitle.Render(fmt.Sprintf("Target: %s | Mode: %s | Scan: %s",
		d.Target, d.Mode, d.ScanID[:min(12, len(d.ScanID))])))
	b.WriteString("\n\n")

	// Overall progress
	pb := ProgressBar{
		Total:   d.TotalModules,
		Current: d.Completed + d.Failed,
		Width:   50,
		Label:   "Progress",
		ShowPct: true,
	}
	b.WriteString(pb.Render())
	b.WriteString("\n")

	// Stats line
	elapsed := time.Since(d.StartTime).Round(time.Second)
	stats := fmt.Sprintf("  Elapsed: %s | Completed: %d | Failed: %d | Findings: %d",
		elapsed, d.Completed, d.Failed, d.Findings)
	b.WriteString(StyleMuted.Render(stats))
	b.WriteString("\n\n")

	// Stages
	for _, stage := range d.Stages {
		stageIcon := "▸"
		stageStyle := StyleMuted
		switch stage.Status {
		case "running":
			stageIcon = "▶"
			stageStyle = StyleWarning
		case "complete":
			stageIcon = "✓"
			stageStyle = StyleSuccess
		case "failed":
			stageIcon = "✗"
			stageStyle = StyleDanger
		}

		b.WriteString(stageStyle.Render(fmt.Sprintf("%s %s", stageIcon, stage.Name)))
		b.WriteString("\n")

		for _, mod := range stage.Modules {
			b.WriteString(mod.Render())
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}

	// Footer
	b.WriteString(StyleMuted.Render("Press 'q' to abort"))

	return b.String()
}

// SetDone marks the dashboard as done, causing it to quit on next tick.
func (d *Dashboard) SetDone() {
	d.done = true
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
