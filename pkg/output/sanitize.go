package output

import "strings"

// Sanitize makes a string from the Tailscale API safe to write to a terminal.
//
// Device names, hostnames, client versions and key descriptions are set by
// whoever owns the device or the key, not by the tailnet administrator reading
// the report. Left alone, an escape sequence in one of those fields can repaint
// or erase the lines around it, so a member could hide a finding from the
// person auditing them.
//
// Tab, newline and carriage return become a space, because the report is laid
// out line by line. Every other C0 control, DEL, and the C1 controls are
// dropped, which leaves the rest of an escape sequence on screen as ordinary
// text rather than letting the terminal act on it.
func Sanitize(s string) string {
	if s == "" {
		return s
	}

	s = strings.ToValidUTF8(s, "�")

	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\t' || r == '\n' || r == '\r':
			b.WriteRune(' ')
		case r < 0x20 || r == 0x7F:
			// C0 controls and DEL, including ESC.
		case r >= 0x80 && r <= 0x9F:
			// C1 controls, which some terminals honour directly.
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// sanitizeAll applies Sanitize to every element of a slice.
func sanitizeAll(items []string) []string {
	out := make([]string, len(items))
	for i, item := range items {
		out[i] = Sanitize(item)
	}
	return out
}

// csvField makes a value safe to write into the SOC 2 evidence CSV.
//
// encoding/csv quotes a field correctly, but quoting is not what stops a
// spreadsheet from treating a leading =, +, - or @ as the start of a formula.
// Values here include device names and reported client versions, so the cell
// is prefixed with an apostrophe, which spreadsheets read as "this is text".
func csvField(s string) string {
	s = Sanitize(s)
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@':
		return "'" + s
	}
	return s
}
