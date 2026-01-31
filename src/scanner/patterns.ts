export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface Pattern {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  category: 'credential-exfil' | 'injection' | 'permission-escalation' | 'obfuscation' | 'known-bad';
  regex: RegExp;
  /** If true, match against the whole file at once (for multiline) */
  multiline?: boolean;
}

export const PATTERNS: Pattern[] = [
  // ── Credential Exfiltration ──
  {
    id: 'CRED-001',
    name: 'Environment variable access',
    description: 'Reads environment variables which may contain secrets',
    severity: 'MEDIUM',
    category: 'credential-exfil',
    regex: /process\.env\b/,
  },
  {
    id: 'CRED-002',
    name: 'SSH key path access',
    description: 'References SSH key directory (~/.ssh)',
    severity: 'CRITICAL',
    category: 'credential-exfil',
    regex: /[~$]?(HOME|USERPROFILE)?[\/\\]?\.ssh/i,
  },
  {
    id: 'CRED-003',
    name: 'AWS credentials access',
    description: 'References AWS credentials directory (~/.aws)',
    severity: 'CRITICAL',
    category: 'credential-exfil',
    regex: /[~$]?(HOME|USERPROFILE)?[\/\\]?\.aws/i,
  },
  {
    id: 'CRED-004',
    name: 'Config directory access',
    description: 'References user config directory which may contain tokens',
    severity: 'HIGH',
    category: 'credential-exfil',
    regex: /[~$]?(HOME|USERPROFILE)?[\/\\]?\.config[\/\\]/i,
  },
  {
    id: 'CRED-005',
    name: 'Cookie/token file access',
    description: 'References cookie or token files',
    severity: 'HIGH',
    category: 'credential-exfil',
    regex: /\b(cookies?\.(?:sqlite|db|txt)|token[s]?\.(?:json|txt|yaml))\b/i,
  },
  {
    id: 'CRED-006',
    name: 'Outbound HTTP with sensitive data',
    description: 'HTTP request that may exfiltrate data to external server',
    severity: 'HIGH',
    category: 'credential-exfil',
    regex: /(?:fetch|axios|http\.request|https\.request|got|request)\s*\(/,
  },
  {
    id: 'CRED-007',
    name: 'Credential file patterns',
    description: 'References known credential file paths',
    severity: 'CRITICAL',
    category: 'credential-exfil',
    regex: /\b(id_rsa|id_ed25519|credentials|\.env\.local|\.netrc|\.pgpass|\.npmrc)\b/i,
  },

  // ── Injection ──
  {
    id: 'INJ-001',
    name: 'eval() usage',
    description: 'Dynamic code execution via eval()',
    severity: 'CRITICAL',
    category: 'injection',
    regex: /\beval\s*\(/,
  },
  {
    id: 'INJ-002',
    name: 'exec/spawn with dynamic input',
    description: 'Shell command execution that may allow injection',
    severity: 'HIGH',
    category: 'injection',
    regex: /\b(exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(/,
  },
  {
    id: 'INJ-003',
    name: 'Function constructor',
    description: 'Dynamic function creation via new Function()',
    severity: 'CRITICAL',
    category: 'injection',
    regex: /new\s+Function\s*\(/,
  },
  {
    id: 'INJ-004',
    name: 'Shell execution in Python',
    description: 'Python subprocess or os.system calls',
    severity: 'HIGH',
    category: 'injection',
    regex: /\b(subprocess\.(run|call|Popen|check_output)|os\.system|os\.popen)\s*\(/,
  },
  {
    id: 'INJ-005',
    name: 'Shell script injection risk',
    description: 'Unquoted variable expansion in shell scripts',
    severity: 'HIGH',
    category: 'injection',
    regex: /\$\{?\w+\}?\s*[|;&]/,
  },

  // ── Permission Escalation ──
  {
    id: 'PERM-001',
    name: 'Filesystem write outside workspace',
    description: 'Writing to paths outside the current workspace',
    severity: 'HIGH',
    category: 'permission-escalation',
    regex: /(?:writeFile|writeFileSync|appendFile|appendFileSync)\s*\(\s*['"`](?:\/|~|\.\.)/,
  },
  {
    id: 'PERM-002',
    name: 'Network listener',
    description: 'Creates a network server/listener',
    severity: 'MEDIUM',
    category: 'permission-escalation',
    regex: /\b(?:createServer|listen)\s*\(/,
  },
  {
    id: 'PERM-003',
    name: 'Sudo/privilege escalation',
    description: 'Attempts to run commands with elevated privileges',
    severity: 'CRITICAL',
    category: 'permission-escalation',
    regex: /\b(sudo|doas|pkexec|runas)\b/,
  },
  {
    id: 'PERM-004',
    name: 'chmod/chown operations',
    description: 'Modifies file permissions or ownership',
    severity: 'MEDIUM',
    category: 'permission-escalation',
    regex: /\b(chmod|chown|chgrp)\b/,
  },

  // ── Obfuscation ──
  {
    id: 'OBF-001',
    name: 'Base64 encoded payload',
    description: 'Contains base64 encoded strings that may hide malicious code',
    severity: 'MEDIUM',
    category: 'obfuscation',
    regex: /(?:atob|btoa|Buffer\.from)\s*\(\s*['"`][A-Za-z0-9+/=]{40,}/,
  },
  {
    id: 'OBF-002',
    name: 'Hex-encoded string',
    description: 'Contains hex-encoded strings that may hide payloads',
    severity: 'MEDIUM',
    category: 'obfuscation',
    regex: /\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){10,}/,
  },
  {
    id: 'OBF-003',
    name: 'Dynamic require/import',
    description: 'Dynamically loads modules which may hide dependencies',
    severity: 'HIGH',
    category: 'obfuscation',
    regex: /(?:require|import)\s*\(\s*(?:[^'"`\s]|['"`]\s*\+)/,
  },
  {
    id: 'OBF-004',
    name: 'String concatenation obfuscation',
    description: 'Builds strings character by character to evade detection',
    severity: 'MEDIUM',
    category: 'obfuscation',
    regex: /String\.fromCharCode\s*\(/,
  },

  // ── Known Bad Patterns ──
  {
    id: 'BAD-001',
    name: 'Credential harvester pattern',
    description: 'Reads credentials and sends them to an external endpoint (like eudaemon_0)',
    severity: 'CRITICAL',
    category: 'known-bad',
    regex: /(?:readFile|readFileSync|cat)\s*.*(?:\.ssh|\.aws|\.env|credential).*(?:fetch|http|request|post)/i,
    multiline: true,
  },
  {
    id: 'BAD-002',
    name: 'Reverse shell pattern',
    description: 'Attempts to establish a reverse shell connection',
    severity: 'CRITICAL',
    category: 'known-bad',
    regex: /\b(?:\/dev\/tcp|nc\s+-[a-z]*e|bash\s+-i\s+>&|python.*socket.*connect)\b/,
  },
  {
    id: 'BAD-003',
    name: 'Cryptocurrency miner indicators',
    description: 'Contains patterns associated with crypto mining',
    severity: 'CRITICAL',
    category: 'known-bad',
    regex: /\b(?:stratum\+tcp|xmrig|coinhive|cryptonight|monero.*pool)\b/i,
  },
  {
    id: 'BAD-004',
    name: 'Data exfiltration via DNS',
    description: 'DNS-based data exfiltration technique',
    severity: 'CRITICAL',
    category: 'known-bad',
    regex: /\b(?:dns\.resolve|nslookup|dig)\b.*\$\{?/,
  },
];
