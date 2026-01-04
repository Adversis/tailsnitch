# Contributing to Tailsnitch

Thank you for your interest in contributing to Tailsnitch! This document provides guidelines for contributing.

## Development Setup

### Prerequisites

- Go 1.21 or later
- A Tailscale account with API access
- `tailscale` CLI installed (for Tailnet Lock checks DEV-010, DEV-012)

### Getting Started

```bash
# Clone the repository
git clone https://github.com/Adversis/tailsnitch.git
cd tailsnitch

# Install dependencies
go mod download

# Build
go build -o tailsnitch .

# Run tests
go test -v ./...

# Run linters
go vet ./...
```

### Environment Setup

```bash
# Set your Tailscale API key
export TSKEY="tskey-api-..."

# Run the auditor
./tailsnitch
```

## Project Structure

```
tailsnitch/
├── main.go              # CLI entry point
├── pkg/
│   ├── client/          # Tailscale API client wrapper
│   │   └── client.go
│   ├── auditor/         # Security check implementations
│   │   ├── auditor.go   # Main orchestrator
│   │   ├── acl.go       # ACL checks (ACL-001 to ACL-010)
│   │   ├── auth.go      # Auth key checks (AUTH-001 to AUTH-004)
│   │   ├── devices.go   # Device checks (DEV-001 to DEV-012)
│   │   ├── network.go   # Network checks (NET-001 to NET-007)
│   │   ├── ssh.go       # SSH checks (SSH-001 to SSH-004)
│   │   ├── logging.go   # Logging checks (LOG-001 to LOG-012, USER-001, DEV-013)
│   │   └── dns.go       # DNS checks (DNS-001)
│   └── types/           # Shared types
│       └── findings.go
├── docs/
│   ├── API.md           # API reference
│   └── CHECKS.md        # Check reference
└── .github/
    └── workflows/       # CI/CD
```

## Adding a New Security Check

### 1. Choose an ID and Category

Check IDs follow the pattern `CATEGORY-NNN`:
- `ACL-*` - Access control policy
- `AUTH-*` - Authentication and keys
- `DEV-*` - Device security
- `NET-*` - Network exposure
- `SSH-*` - SSH security
- `LOG-*` - Logging and admin
- `DNS-*` - DNS configuration
- `USER-*` - User management

### 2. Implement the Check

Add your check function to the appropriate auditor file:

```go
func (a *ACLAuditor) checkNewThing(policy ACLPolicy) types.Suggestion {
    finding := types.Suggestion{
        ID:          "ACL-011",
        Title:       "New security check",
        Severity:    types.Medium,
        Category:    types.AccessControl,
        Description: "Description of what this checks for.",
        Remediation: "How to fix the issue.",
        Source:      "https://tailscale.com/kb/relevant-doc",
        Pass:        true,
    }

    // Check logic here
    var issues []string
    // ... populate issues ...

    if len(issues) > 0 {
        finding.Pass = false
        finding.Details = issues
        finding.Description = fmt.Sprintf("Found %d issue(s).", len(issues))
        finding.Fix = &types.FixInfo{
            Type:        types.FixTypeManual,
            Description: "Detailed fix instructions",
            AdminURL:    "https://login.tailscale.com/admin/...",
            DocURL:      "https://tailscale.com/kb/...",
        }
    }

    return finding
}
```

### 3. Register the Check

Add your check to the `Audit()` method:

```go
func (a *ACLAuditor) Audit(ctx context.Context) ([]types.Suggestion, error) {
    var findings []types.Suggestion

    // ... existing checks ...

    // ACL-011: New security check
    findings = append(findings, a.checkNewThing(policy))

    return findings, nil
}
```

### 4. Document the Check

Add an entry to `docs/CHECKS.md` following the existing format.

### 5. Update the README

Update the check count in `README.md` if adding a new check.

## Check Design Guidelines

### Severity Levels

- **CRITICAL**: Immediate security risk, actively exploitable
- **HIGH**: Significant security concern, should be addressed soon
- **MEDIUM**: Security consideration, review recommended
- **LOW**: Minor concern or informational with action
- **INFO**: For awareness, no action typically required

### Pass/Fail Logic

- `Pass: true` - Check passed, no issues found
- `Pass: false` - Check failed, issues found OR manual verification needed

For informational checks that just report status:
- Use `Pass: true` with descriptive text
- Use `Pass: false` only if there's an actual concern

### Fix Types

- `FixTypeAPI` - Can be fixed programmatically via Tailscale API
- `FixTypeManual` - Requires action in admin console
- `FixTypeExternal` - Requires external system (IdP, CLI, etc.)
- `FixTypeNone` - Informational, no fix needed

### Details Field

Use `Details` to provide:
- List of affected items
- Specific configuration values
- Manual check instructions

```go
finding.Details = []string{
    "Device A: issue description",
    "Device B: issue description",
}
```

## Code Style

- Follow standard Go conventions (`gofmt`, `go vet`)
- Keep functions focused and under 100 lines where possible
- Document exported functions and types
- Use meaningful variable names

## Security Guidelines

When contributing code that interacts with external systems:

### External Binary Execution

- Never use `exec.LookPath` directly without additional validation
- Use `findTailscaleBinary()` pattern: check known safe paths first, reject current directory
- Always resolve to absolute paths before execution

### HTTP Requests

- Always use `httpClientWithTimeout` (10-second timeout) for external API calls
- Never use `http.DefaultClient` which has no timeout

### Sensitive Data

- Never log API keys, tokens, or credentials
- Be cautious with device names and user identifiers in output

## Testing

```bash
# Run all tests
go test -v ./...

# Run tests for a specific package
go test -v ./pkg/auditor/...

# Run with race detection
go test -race ./...
```

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-check`)
3. Make your changes
4. Ensure tests pass (`go test ./...`)
5. Ensure code passes vet (`go vet ./...`)
6. Commit with a descriptive message
7. Push to your fork
8. Open a Pull Request

### PR Guidelines

- Keep PRs focused on a single change
- Update documentation if adding features
- Add tests for new functionality where applicable
- Reference any related issues

## Reporting Issues

Please include:
- Tailsnitch version
- Go version
- Steps to reproduce
- Expected vs actual behavior
- Relevant error messages

## Security Issues

For security vulnerabilities, please report privately rather than opening a public issue.

## License

By contributing, you agree that your contributions will be licensed under the same license as the project.
