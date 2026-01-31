import * as fs from 'fs';
import * as path from 'path';
import chalk from 'chalk';
import { hashDirectory, hashFile } from '../utils';

export interface VerifyResult {
  path: string;
  hash: string;
  expected?: string;
  match: boolean | null; // null = no expected hash to compare
}

export function verifyPath(targetPath: string, expectedHash?: string): VerifyResult {
  const stat = fs.statSync(targetPath);
  const hash = stat.isDirectory() ? hashDirectory(targetPath) : hashFile(targetPath);

  return {
    path: targetPath,
    hash,
    expected: expectedHash,
    match: expectedHash ? hash === expectedHash : null,
  };
}

export function formatVerifyReport(result: VerifyResult): string {
  const lines: string[] = [];
  lines.push('');
  lines.push(chalk.cyan.bold('━'.repeat(60)));
  lines.push(chalk.cyan.bold('  🔐 AgentGuard Hash Verification'));
  lines.push(chalk.cyan.bold('━'.repeat(60)));
  lines.push('');
  lines.push(`  ${chalk.dim('Path:')} ${result.path}`);
  lines.push(`  ${chalk.dim('SHA-256:')} ${chalk.white(result.hash)}`);

  if (result.match === null) {
    lines.push('');
    lines.push(`  ${chalk.yellow('ℹ')} No expected hash provided. Use --hash to compare.`);
  } else if (result.match) {
    lines.push(`  ${chalk.dim('Expected:')} ${chalk.white(result.expected!)}`);
    lines.push('');
    lines.push(chalk.green.bold('  ✅ Hash matches — integrity verified'));
  } else {
    lines.push(`  ${chalk.dim('Expected:')} ${chalk.red(result.expected!)}`);
    lines.push('');
    lines.push(chalk.red.bold('  ❌ Hash mismatch — contents have been modified!'));
  }

  lines.push('');
  lines.push(chalk.cyan.bold('━'.repeat(60)));
  lines.push('');
  return lines.join('\n');
}

export function formatVerifyJSON(result: VerifyResult): string {
  return JSON.stringify(result, null, 2);
}
