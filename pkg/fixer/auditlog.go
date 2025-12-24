package fixer

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// AuditAction represents a single action taken during fix mode
type AuditAction struct {
	Timestamp    time.Time `json:"timestamp"`
	Action       string    `json:"action"`
	ResourceType string    `json:"resource_type"`
	ResourceID   string    `json:"resource_id"`
	ResourceName string    `json:"resource_name,omitempty"`
	Details      string    `json:"details,omitempty"`
	Success      bool      `json:"success"`
	Error        string    `json:"error,omitempty"`
	DryRun       bool      `json:"dry_run"`
}

// AuditLog records all fix actions for accountability
type AuditLog struct {
	StartTime time.Time     `json:"start_time"`
	Tailnet   string        `json:"tailnet"`
	DryRun    bool          `json:"dry_run"`
	Actions   []AuditAction `json:"actions"`
	file      *os.File
	encoder   *json.Encoder
	writer    io.Writer
}

// NewAuditLog creates a new audit log
func NewAuditLog(tailnet string, dryRun bool, logDir string) (*AuditLog, error) {
	al := &AuditLog{
		StartTime: time.Now(),
		Tailnet:   tailnet,
		DryRun:    dryRun,
		Actions:   []AuditAction{},
	}

	// Create log directory if it doesn't exist
	if logDir == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home directory: %w", err)
		}
		logDir = filepath.Join(homeDir, ".tailsnitch", "logs")
	}

	if err := os.MkdirAll(logDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	// Create log file with timestamp
	logFileName := fmt.Sprintf("audit-%s.json", al.StartTime.Format("2006-01-02T15-04-05"))
	logPath := filepath.Join(logDir, logFileName)

	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to create audit log file: %w", err)
	}

	al.file = file
	al.writer = file

	// Write header
	header := struct {
		StartTime time.Time `json:"start_time"`
		Tailnet   string    `json:"tailnet"`
		DryRun    bool      `json:"dry_run"`
		Version   string    `json:"version"`
	}{
		StartTime: al.StartTime,
		Tailnet:   tailnet,
		DryRun:    dryRun,
		Version:   "1.0",
	}

	headerBytes, _ := json.MarshalIndent(header, "", "  ")
	fmt.Fprintf(file, "// Tailsnitch Fix Log\n")
	fmt.Fprintf(file, "// %s\n", headerBytes)
	fmt.Fprintf(file, "// Actions:\n")

	return al, nil
}

// LogAction records an action to the audit log
func (al *AuditLog) LogAction(action, resourceType, resourceID, resourceName, details string, success bool, err error) {
	a := AuditAction{
		Timestamp:    time.Now(),
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		ResourceName: resourceName,
		Details:      details,
		Success:      success,
		DryRun:       al.DryRun,
	}

	if err != nil {
		a.Error = err.Error()
	}

	al.Actions = append(al.Actions, a)

	// Write to file immediately
	if al.writer != nil {
		actionBytes, _ := json.Marshal(a)
		fmt.Fprintf(al.writer, "%s\n", actionBytes)
	}
}

// LogPath returns the path to the audit log file
func (al *AuditLog) LogPath() string {
	if al.file != nil {
		return al.file.Name()
	}
	return ""
}

// Close closes the audit log file
func (al *AuditLog) Close() error {
	if al.file != nil {
		// Write summary
		summary := struct {
			EndTime      time.Time `json:"end_time"`
			TotalActions int       `json:"total_actions"`
			Successful   int       `json:"successful"`
			Failed       int       `json:"failed"`
		}{
			EndTime:      time.Now(),
			TotalActions: len(al.Actions),
		}

		for _, a := range al.Actions {
			if a.Success {
				summary.Successful++
			} else {
				summary.Failed++
			}
		}

		summaryBytes, _ := json.MarshalIndent(summary, "", "  ")
		fmt.Fprintf(al.file, "// Summary:\n")
		fmt.Fprintf(al.file, "// %s\n", summaryBytes)

		return al.file.Close()
	}
	return nil
}

// Summary returns a summary of actions taken
func (al *AuditLog) Summary() (total, successful, failed int) {
	total = len(al.Actions)
	for _, a := range al.Actions {
		if a.Success {
			successful++
		} else {
			failed++
		}
	}
	return
}
