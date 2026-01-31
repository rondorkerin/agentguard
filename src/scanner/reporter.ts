import chalk from 'chalk';
import { ScanResult, Finding } from './analyzer';
import { Severity } from './patterns';

const SEVERITY_COLORS: Record<Severity, (s: string) => string> = {
  CRITICAL: chalk.bgRed.white.bold,
  HIGH: chalk.red.bold,
  MEDIUM: chalk.yellow.bold,
  LOW: chalk.blue,
};

const SEVERITY_ICONS: Record<Severity, string> = {
  CRITICAL: '🚨',
  HIGH: '🔴',
  MEDIUM: '🟡',
  LOW: '🔵',
};

function scoreColor(score: number): (s: string) => string {
  if (score >= 80) return chalk.green.bold;
  if (score >= 50) return chalk.yellow.bold;
  return chalk.red.bold;
}

function scoreEmoji(score: number): string {
  if (score >= 90) return '✅';
  if (score >= 70) return '⚠️';
  if (score >= 40) return '🔶';
  return '🚫';
}

export function formatReport(result: ScanResult): string {
  const lines: string[] = [];

  lines.push('');
  lines.push(chalk.cyan.bold('━'.repeat(60)));
  lines.push(chalk.cyan.bold('  🛡️  AgentGuard Security Report'));
  lines.push(chalk.cyan.bold('━'.repeat(60)));
  lines.push('');
  lines.push(`  ${chalk.dim('Path:')}    ${result.path}`);
  lines.push(`  ${chalk.dim('Files:')}   ${result.files} scanned`);
  lines.push(`  ${chalk.dim('Time:')}    ${result.duration}ms`);
  lines.push('');

  if (result.findings.length === 0) {
    lines.push(chalk.green.bold('  ✅ No security issues found!'));
  } else {
    // Group by severity
    const grouped: Record<string, Finding[]> = {};
    for (const f of result.findings) {
      (grouped[f.severity] ||= []).push(f);
    }

    const order: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
    for (const sev of order) {
      const items = grouped[sev];
      if (!items || items.length === 0) continue;

      lines.push(`  ${SEVERITY_ICONS[sev]} ${SEVERITY_COLORS[sev](sev)} (${items.length})`);
      lines.push('');
      for (const f of items) {
        lines.push(`    ${chalk.dim(f.id)} ${chalk.white.bold(f.name)}`);
        lines.push(`    ${chalk.dim('└')} ${f.file}:${f.line}`);
        lines.push(`      ${chalk.dim(f.snippet)}`);
        lines.push('');
      }
    }
  }

  // Summary
  const counts = {
    CRITICAL: result.findings.filter(f => f.severity === 'CRITICAL').length,
    HIGH: result.findings.filter(f => f.severity === 'HIGH').length,
    MEDIUM: result.findings.filter(f => f.severity === 'MEDIUM').length,
    LOW: result.findings.filter(f => f.severity === 'LOW').length,
  };

  lines.push(chalk.cyan.bold('━'.repeat(60)));
  lines.push(`  ${scoreEmoji(result.score)} Trust Score: ${scoreColor(result.score)(String(result.score))}/100`);
  lines.push(`  ${chalk.dim(`${counts.CRITICAL} critical · ${counts.HIGH} high · ${counts.MEDIUM} medium · ${counts.LOW} low`)}`);
  lines.push(chalk.cyan.bold('━'.repeat(60)));
  lines.push('');

  return lines.join('\n');
}

export function formatJSON(result: ScanResult): string {
  return JSON.stringify({
    path: result.path,
    files: result.files,
    score: result.score,
    duration: result.duration,
    summary: {
      critical: result.findings.filter(f => f.severity === 'CRITICAL').length,
      high: result.findings.filter(f => f.severity === 'HIGH').length,
      medium: result.findings.filter(f => f.severity === 'MEDIUM').length,
      low: result.findings.filter(f => f.severity === 'LOW').length,
      total: result.findings.length,
    },
    findings: result.findings,
  }, null, 2);
}
