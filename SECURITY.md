# Security Policy

## Supported Versions

Only the latest active minor release receives security fixes and vulnerability updates.

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0.0 | :x:                |

## Reporting a Vulnerability

We take the security of VibeSec and the safety of user environments seriously. If you discover a vulnerability in VibeSec, please disclose it responsibly.

### How to Report

- **Email**: Send vulnerability reports directly to `mysocialmedia456@gmail.com`.
- **Subject**: Prefix your email subject with `[SECURITY VULNERABILITY] VibeSec`.
- **Content**: Please include:
  1. A clear description of the vulnerability and its potential impact.
  2. Step-by-step reproduction instructions or a minimal proof-of-concept archive.
  3. The affected component, file, or endpoint.
  4. Any proposed remediations or patches.

### Response Timelines

- **Initial Acknowledgment**: Within 48 hours of receipt.
- **Triage & Assessment**: Within 5 business days.
- **Remediation & Advisory**: We coordinate coordinated public disclosure once a verified patch is released.

## Security Architecture & Guarantees

VibeSec is designed with a defense-in-depth model for scanning untrusted codebases:
1. **Zero Untrusted Execution Invariant**: VibeSec never executes the target code under analysis. Parsing is performed strictly via static AST, regex, and lockfile inspection.
2. **Subprocess Isolation**: External scanners (Semgrep, Gitleaks, Bandit, Trivy) run with explicit `argv` argument lists (`shell=False`), scrubbed environment variables (telemetry disabled, cloud tokens stripped), hard 60–90 second timeouts, and 25 MB stdout/stderr memory caps.
3. **Ingestion Hardening**: Archive extraction enforces Zip Slip prevention, decompression byte caps (`MAX_UNCOMPRESSED_BYTES`), and symlink skipping. Git cloning strictly enforces HTTPS URL patterns.
4. **Offline Isolation**: In offline mode (`--offline`), all network sockets are blocked; external vulnerability databases rely strictly on local caches.

## Out of Scope

The following are considered out of scope for security bounties or vulnerability reports:
- Denial-of-service attempts by uploading files exceeding the documented maximum upload limits (e.g., > 1 GB or > 50,000 files).
- Vulnerabilities in optional external scanner binaries (e.g., Trivy or Semgrep engine bugs) that do not enable sandbox escape or command injection in VibeSec.
- Theoretical attacks requiring existing root/administrator access on the host system running VibeSec.

