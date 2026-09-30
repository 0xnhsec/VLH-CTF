package ui

import "github.com/charmbracelet/lipgloss"

// Semantic colors (PRD FR-9): green = normal/success, red = error/alert.
// No other color carries semantic meaning — dim/gray is neutral chrome only.
// (Green #22C55E / red #EF4444 per CONTRACT §9.)
var (
	green = lipgloss.Color("#22C55E")
	red   = lipgloss.Color("#EF4444")

	// Normal renders success / normal-state text (green).
	Normal = lipgloss.NewStyle().Foreground(green)
	// Alert renders errors and alerts (red).
	Alert = lipgloss.NewStyle().Foreground(red)
	// Dim renders neutral, de-emphasized chrome (gray).
	Dim = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	// Title renders view titles (green, bold).
	Title = lipgloss.NewStyle().Bold(true).Foreground(green)
	// TableHeader renders table column headers (bold, neutral).
	TableHeader = lipgloss.NewStyle().Bold(true)
	// HelpStyle renders key hints (gray).
	HelpStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
)
