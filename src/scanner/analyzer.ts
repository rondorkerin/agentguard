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
    const lines = content.split('\n');

    for (const pattern of PATTERNS) {
      if (pattern.multiline) {
        // Match against full content
        if (pattern.regex.test(content)) {
          findings.push({
            id: pattern.id,
            name: pattern.name,
            description: pattern.description,
            severity: pattern.severity,
            category: pattern.category,
            file: relFile,
            line: 1,
            snippet: content.substring(0, 120).replace(/\n/g, ' '),
          });
        }
      } else {
        for (let i = 0; i < lines.length; i++) {
          if (pattern.regex.test(lines[i])) {
            findings.push({
              id: pattern.id,
              name: pattern.name,
              description: pattern.description,
              severity: pattern.severity,
              category: pattern.category,
              file: relFile,
              line: i + 1,
              snippet: lines[i].trim().substring(0, 120),
            });
          }
        }
      }
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
