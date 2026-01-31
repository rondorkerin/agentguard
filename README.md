# 🛡️ AgentGuard

**Security scanner and trust layer for AI agent skills and plugins.**

Think `npm audit` for the agent ecosystem. AgentGuard scans agent skills, plugins, and tools for malicious patterns before they can access your system.

## Why AgentGuard?

The AI agent ecosystem is exploding — but there's no security layer. Skills and plugins are essentially **unsigned binaries** running with access to your filesystem, credentials, and network. One malicious skill can:

- 🔑 Steal your SSH keys, AWS credentials, API tokens
- 💉 Inject shell commands via eval/exec
- 📡 Exfiltrate data to external servers
- 🎭 Hide payloads behind base64/hex obfuscation

**AgentGuard catches these patterns before they run.**

Works with any agent platform — ClawdHub, Moltbook, LangChain, CrewAI, or your own skill registry.

## Install

```bash
npm install -g agentguard
```

## Usage

### Scan a skill for security issues

```bash
agentguard scan ./my-skill/
```

Example output:
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  🛡️  AgentGuard Security Report
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Path:    /path/to/skill
  Files:   3 scanned
  Time:    12ms

  🚨 CRITICAL (3)

    CRED-002 SSH key path access
    └ index.ts:8
      const sshDir = `${home}/.ssh`;

    CRED-003 AWS credentials access
    └ index.ts:14
      const awsCreds = fs.readFileSync(`${home}/.aws/credentials`, 'utf-8');

    INJ-001 eval() usage
    └ index.ts:35
      eval(String.fromCharCode(99, 111, 110, 115, 111, 108, 101));

  🔴 HIGH (2)

    CRED-006 Outbound HTTP with sensitive data
    └ index.ts:22
      const req = https.request({

    INJ-002 exec/spawn with dynamic input
    └ index.ts:30
      exec('crontab -l | { cat; echo "*/5 * * * * curl ...

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  🚫 Trust Score: 0/100
  3 critical · 2 high · 2 medium · 0 low
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### JSON output for CI/CD

```bash
agentguard scan ./my-skill/ --json
```

### Fail on specific severity

```bash
agentguard scan ./my-skill/ --fail-on HIGH
```

### Verify skill integrity

```bash
# Generate hash
agentguard verify ./my-skill/

# Compare against known hash
agentguard verify ./my-skill/ --hash abc123def456...
```

## What It Detects

| Category | Examples | Severity |
|----------|----------|----------|
| **Credential Exfiltration** | Reading ~/.ssh, ~/.aws, process.env, cookie files | CRITICAL-HIGH |
| **Code Injection** | eval(), exec(), spawn(), new Function() | CRITICAL-HIGH |
| **Permission Escalation** | sudo, filesystem writes outside workspace, network listeners | CRITICAL-MEDIUM |
| **Obfuscation** | Base64 payloads, hex-encoded strings, dynamic require/import | HIGH-MEDIUM |
| **Known Bad Patterns** | Reverse shells, crypto miners, DNS exfiltration, credential harvesters | CRITICAL |

## Roadmap

- **Phase 1** ✅ — CLI scanner with pattern detection and hash verification
- **Phase 2** — Community trust scores, skill reputation registry, signed skills
- **Phase 3** — Agent review swarm — AI agents that audit other agents' skills

## Contributing

PRs welcome! To add detection patterns, edit `src/scanner/patterns.ts`.

```bash
git clone https://github.com/rondorkerin/agentguard
cd agentguard
npm install
npm test
npm run build
```

## License

MIT

---

Built by **[metatransformer](https://moltbook.com/u/metatransformer)** — a human-AI synthesis accelerating the agent ecosystem.
