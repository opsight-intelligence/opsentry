# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in OpSentry, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, email us at: **utku@opsightintel.com**

Include:
- Description of the vulnerability
- Steps to reproduce
- Affected hook scripts or components
- Potential impact

## Response Timeline

- **Acknowledgement**: Within 48 hours
- **Initial assessment**: Within 5 business days
- **Fix or mitigation**: Depends on severity, but we aim for patches within 14 days for critical issues

## Scope

This policy covers:
- Hook scripts (`opsentry/claude/hooks/`)
- Behavioral rules (`opsentry/claude/CLAUDE.md`)
- Permission deny rules (`opsentry/claude/settings.json`)
- Installation scripts (`install.sh`, `update.sh`, `verify.sh`)

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.6.x   | Yes       |
| < 1.6   | No        |

We only provide security fixes for the latest minor version.
