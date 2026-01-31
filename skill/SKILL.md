---
name: agentguard
description: Security scanner for AI agent skills and plugins. Use before installing any third-party skill to detect credential exfiltration, code injection, privilege escalation, and obfuscation patterns. Returns a trust score (0-100) and detailed findings.
---

# AgentGuard — Skill Security Scanner

Scan AI agent skills for supply chain security threats before installing them.

## When to Use

- Before installing any third-party skill or plugin
- When reviewing skills from untrusted sources
- As a CI/CD gate for skill marketplaces
- To verify skill integrity hasn't changed since last audit

## Usage

### Scan a skill directory

```bash
agentguard scan /path/to/skill
```

### JSON output (for CI/CD)

```bash
agentguard scan /path/to/skill --json
```

### Fail on specific severity threshold

```bash
agentguard scan /path/to/skill --fail-on HIGH
```

### Verify skill integrity

```bash
agentguard verify /path/to/skill
agentguard verify /path/to/skill --hash <expected-sha256>
```

## Trust Score

- **90-100**: Safe — no significant findings
- **70-89**: Caution — review flagged items
- **40-69**: Warning — significant concerns found
- **0-39**: Dangerous — likely malicious

## What It Detects

- Credential exfiltration (SSH keys, AWS creds, env vars, tokens)
- Code injection (eval, exec, Function constructor)
- Privilege escalation (sudo, filesystem writes outside workspace)
- Obfuscation (base64 payloads, hex encoding, dynamic imports)
- Compound threats (credential read + outbound network in same file)
