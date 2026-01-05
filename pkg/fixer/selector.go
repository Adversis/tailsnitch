package fixer

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/Adversis/tailsnitch/pkg/types"
)

var baseStyle = lipgloss.NewStyle().
	BorderStyle(lipgloss.NormalBorder()).
	BorderForeground(lipgloss.Color("240"))

// SelectorConfig configures the generic selector TUI
type SelectorConfig struct {
	Title      string // Title shown above the table
	IDColumn   string // Name of the ID column (e.g., "Key ID", "Name")
	DescColumn string // Name of the description column
	IDWidth    int    // Width of ID column
	DescWidth  int    // Width of description column
}

type selectorModel struct {
	config   SelectorConfig
	table    table.Model
	items    []types.FixableItem
	selected map[int]bool
	quitting bool
	done     bool
}

func newSelectorModel(items []types.FixableItem, autoSelect bool, config SelectorConfig) selectorModel {
	columns := []table.Column{
		{Title: " ", Width: 3},
		{Title: config.IDColumn, Width: config.IDWidth},
		{Title: config.DescColumn, Width: config.DescWidth},
	}

	rows := make([]table.Row, len(items))
	selected := make(map[int]bool)

	for i, item := range items {
		checkbox := "[ ]"
		if item.Selected || autoSelect {
			checkbox = "[x]"
			selected[i] = true
		}
		// Use Name if available, otherwise ID
		displayID := item.Name
		if displayID == "" {
			displayID = item.ID
		}
		rows[i] = table.Row{checkbox, displayID, item.Description}
	}

	t := table.New(
		table.WithColumns(columns),
		table.WithRows(rows),
		table.WithFocused(true),
		table.WithHeight(min(len(items)+1, 15)),
	)

	s := table.DefaultStyles()
	s.Header = s.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("240")).
		BorderBottom(true).
		Bold(false)
	s.Selected = s.Selected.
		Foreground(lipgloss.Color("229")).
		Background(lipgloss.Color("57")).
		Bold(false)
	t.SetStyles(s)

	return selectorModel{
		config:   config,
		table:    t,
		items:    items,
		selected: selected,
	}
}

func (m selectorModel) Init() tea.Cmd {
	return nil
}

func (m selectorModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "esc":
			m.quitting = true
			return m, tea.Quit
		case "enter":
			m.done = true
			return m, tea.Quit
		case " ":
			cursor := m.table.Cursor()
			if m.selected[cursor] {
				delete(m.selected, cursor)
			} else {
				m.selected[cursor] = true
			}
			m.updateRows()
		case "a":
			for i := range m.items {
				m.selected[i] = true
			}
			m.updateRows()
		case "n":
			m.selected = make(map[int]bool)
			m.updateRows()
		}
	}

	m.table, cmd = m.table.Update(msg)
	return m, cmd
}

func (m *selectorModel) updateRows() {
	rows := make([]table.Row, len(m.items))
	for i, item := range m.items {
		checkbox := "[ ]"
		if m.selected[i] {
			checkbox = "[x]"
		}
		displayID := item.Name
		if displayID == "" {
			displayID = item.ID
		}
		rows[i] = table.Row{checkbox, displayID, item.Description}
	}
	m.table.SetRows(rows)
}

func (m selectorModel) View() string {
	if m.quitting {
		return ""
	}

	var b strings.Builder
	b.WriteString("  " + m.config.Title + "\n\n")
	b.WriteString(baseStyle.Render(m.table.View()))
	b.WriteString("\n\n")
	b.WriteString("  Space: toggle | a: all | n: none | Enter: confirm | q: cancel\n")
	b.WriteString(fmt.Sprintf("  Selected: %d\n", len(m.selected)))
	return b.String()
}

func (m selectorModel) getSelected() []types.FixableItem {
	var result []types.FixableItem
	for i, item := range m.items {
		if m.selected[i] {
			result = append(result, item)
		}
	}
	return result
}

// RunSelector runs the interactive selection TUI with the given configuration
func RunSelector(items []types.FixableItem, autoSelect bool, config SelectorConfig) ([]types.FixableItem, error) {
	if len(items) == 0 {
		return nil, nil
	}

	m := newSelectorModel(items, autoSelect, config)
	p := tea.NewProgram(m)

	finalModel, err := p.Run()
	if err != nil {
		return nil, err
	}

	final, ok := finalModel.(selectorModel)
	if !ok {
		return nil, fmt.Errorf("unexpected TUI state: expected selectorModel")
	}
	if final.quitting {
		return nil, nil
	}

	return final.getSelected(), nil
}

// Convenience functions for common selector types

// RunKeySelector runs the interactive key selection TUI
func RunKeySelector(items []types.FixableItem, autoSelect bool) ([]types.FixableItem, error) {
	return RunSelector(items, autoSelect, SelectorConfig{
		Title:      "Auth Keys - Select keys to delete",
		IDColumn:   "Key ID",
		DescColumn: "Description",
		IDWidth:    20,
		DescWidth:  40,
	})
}

// RunDeviceSelector runs the interactive device selection TUI
func RunDeviceSelector(items []types.FixableItem, autoSelect bool) ([]types.FixableItem, error) {
	return RunSelector(items, autoSelect, SelectorConfig{
		Title:      "Devices - Select devices to delete",
		IDColumn:   "Name",
		DescColumn: "Details",
		IDWidth:    30,
		DescWidth:  40,
	})
}

// RunAuthorizationSelector runs the interactive device authorization TUI
func RunAuthorizationSelector(items []types.FixableItem, autoSelect bool) ([]types.FixableItem, error) {
	return RunSelector(items, autoSelect, SelectorConfig{
		Title:      "Authorize Devices - Select devices to approve",
		IDColumn:   "Device Name",
		DescColumn: "Details",
		IDWidth:    25,
		DescWidth:  45,
	})
}

// RunTagRemovalSelector runs the interactive tag removal TUI
func RunTagRemovalSelector(items []types.FixableItem, autoSelect bool) ([]types.FixableItem, error) {
	return RunSelector(items, autoSelect, SelectorConfig{
		Title:      "Remove Tags - Select devices to untag",
		IDColumn:   "Device Name",
		DescColumn: "Details (tags to remove)",
		IDWidth:    25,
		DescWidth:  45,
	})
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
