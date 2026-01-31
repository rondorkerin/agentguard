import * as path from 'path';
import { Pattern, PATTERNS, Severity } from './patterns';
import { readFileSafe, getAllFiles, SCAN_EXTENSIONS } from '../utils';

export interface Finding {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  category: string;
  file: string;
  line: number;
  snippet: string;
}

export interface ScanResult {
  path: string;
  files: number;
  findings: Finding[];
  score: number;
  duration: number;
}

const EXECUTABLE_EXTENSIONS = ['.ts', '.js', '.mjs', '.cjs', '.py', '.sh', '.bash'];
const DOC_EXTENSIONS = ['.md'];

const SEVERITY_ORDER: Severity[] = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

function lowerSeverity(sev: Severity): Severity | null {
  const idx = SEVERITY_ORDER.indexOf(sev);
  if (idx <= 0) return null; // LOW drops off entirely
  return SEVERITY_ORDER[idx - 1];
}

function isExecutable(filePath: string): boolean {
  return EXECUTABLE_EXTENSIONS.some(ext => filePath.endsWith(ext));
}

function isDoc(filePath: string): boolean {
  return DOC_EXTENSIONS.some(ext => filePath.endsWith(ext));
}

/** Extract content from fenced code blocks in markdown */
function extractCodeBlocks(content: string): { text: string; startLine: number }[] {
  const blocks: { text: string; startLine: number }[] = [];
  const lines = content.split('\n');
  let inBlock = false;
  let blockLines: string[] = [];
  let blockStart = 0;

  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trim();
    if (!inBlock && trimmed.startsWith('```')) {
      inBlock = true;
      blockStart = i + 1; // content starts next line
      blockLines = [];
    } else if (inBlock && trimmed.startsWith('```')) {
      inBlock = false;
      blocks.push({ text: blockLines.join('\n'), startLine: blockStart });
    } else if (inBlock) {
      blockLines.push(lines[i]);
    }
  }
  return blocks;
}

/** Check if file has credential-reading patterns */
function hasCredentialAccess(content: string): boolean {
  const credPatterns = [
    /\.ssh/i,
    /\.aws/i,
    /\.env\b/i,
    /credential/i,
    /\.npmrc/i,
    /\.netrc/i,
    /\.pgpass/i,
    /id_rsa/i,
    /id_ed25519/i,
    /process\.env\b/,
    /readFile.*(?:secret|token|key|password|cred)/i,
  ];
  return credPatterns.some(p => p.test(content));
}

/** Check if file has outbound network patterns */
function hasOutboundNetwork(content: string): boolean {
  return /(?:fetch|axios|http\.request|https\.request|got|request)\s*\(/.test(content);
}

function scanFileContent(
  content: string,
  lines: string[],
  relFile: string,
  fileType: 'executable' | 'doc' | 'data',
  lineOffset: number = 0,
): Finding[] {
  const findings: Finding[] = [];

  for (const pattern of PATTERNS) {
    // Skip compound patterns here — handled separately
    if (pattern.id === 'COMPOUND-001') continue;

    if (pattern.multiline) {
      if (pattern.regex.test(content)) {
        let severity = pattern.severity;
        if (fileType === 'doc') {
          const reduced = lowerSeverity(severity);
          if (!reduced) continue;
          severity = reduced;
        }
        findings.push({
          id: pattern.id,
          name: pattern.name,
          description: pattern.description,
          severity,
          category: pattern.category,
          file: relFile,
          line: lineOffset + 1,
          snippet: content.substring(0, 120).replace(/\n/g, ' '),
        });
      }
    } else {
      for (let i = 0; i < lines.length; i++) {
        if (pattern.regex.test(lines[i])) {
          let severity = pattern.severity;
          if (fileType === 'doc') {
            const reduced = lowerSeverity(severity);
            if (!reduced) continue;
            severity = reduced;
          }
          findings.push({
            id: pattern.id,
            name: pattern.name,
            description: pattern.description,
            severity,
            category: pattern.category,
            file: relFile,
            line: lineOffset + i + 1,
            snippet: lines[i].trim().substring(0, 120),
          });
        }
      }
    }
  }

  return findings;
}

function computeScore(findings: Finding[]): number {
  let score = 100;
  const penalties: Record<Severity, number> = {
    CRITICAL: 25,
    HIGH: 15,
    MEDIUM: 5,
    LOW: 2,
  };
  for (const f of findings) {
    score -= penalties[f.severity];
  }
  return Math.max(0, Math.min(100, score));
}

export function scanDirectory(targetPath: string): ScanResult {
  const start = Date.now();
  const files = getAllFiles(targetPath, SCAN_EXTENSIONS);
  const findings: Finding[] = [];

  for (const file of files) {
    const content = readFileSafe(file);
    if (!content) continue;
    const relFile = path.relative(targetPath, file);

    if (isDoc(file)) {
      // For documentation files, only scan inside code blocks
      const codeBlocks = extractCodeBlocks(content);
      for (const block of codeBlocks) {
        const blockLines = block.text.split('\n');
        findings.push(...scanFileContent(block.text, blockLines, relFile, 'doc', block.startLine));
      }
    } else if (isExecutable(file)) {
      const lines = content.split('\n');
      const fileFindings = scanFileContent(content, lines, relFile, 'executable');
      findings.push(...fileFindings);

      // Compound pattern: credential access + outbound network in same file = CRITICAL
      if (hasCredentialAccess(content) && hasOutboundNetwork(content)) {
        findings.push({
          id: 'COMPOUND-001',
          name: 'Credential access with outbound network',
          description: 'File reads credentials/secrets AND makes outbound HTTP requests — likely exfiltration',
          severity: 'CRITICAL',
          category: 'known-bad',
          file: relFile,
          line: 1,
          snippet: 'Compound pattern: credential read + network send in same file',
        });
      }
    } else {
      // Data files (json, yaml, toml) — scan with reduced severity
      const lines = content.split('\n');
      findings.push(...scanFileContent(content, lines, relFile, 'doc'));
    }
  }

  return {
    path: targetPath,
    files: files.length,
    findings,
    score: computeScore(findings),
    duration: Date.now() - start,
  };
}
