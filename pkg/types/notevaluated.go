package types

// NotEvaluated builds the finding for a check that could not run, because the
// input it needs was unreadable or unparseable.
//
// It reports Pass false deliberately. A check that did not run has not passed,
// and a passing finding would be dropped from the default output by
// FilterFailed and counted in Summary.Passed, which would present a skipped
// control as a satisfied one.
func NotEvaluated(id, reason string) Suggestion {
	s := Suggestion{
		ID:          id,
		Title:       id + " could not be evaluated",
		Severity:    Informational,
		Description: reason,
		Remediation: "Resolve the underlying error, then re-run the audit to evaluate this check.",
		Pass:        false,
	}
	if info, ok := DefaultRegistry.Lookup(id); ok {
		s.Title = info.Title + " (not evaluated)"
		s.Category = info.Category
	}
	return s
}
