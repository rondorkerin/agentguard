#!/usr/bin/env node

import { Command } from 'commander';
import * as fs from 'fs';
import chalk from 'chalk';
import { scanDirectory, formatReport, formatJSON } from './scanner';
import { verifyPath, formatVerifyReport, formatVerifyJSON } from './verify';

const pkg = JSON.parse(fs.readFileSync(require.resolve('../package.json'), 'utf-8'));

const program = new Command();

program
  .name('agentguard')
  .description('🛡️  Security scanner for AI agent skills and plugins')
  .version(pkg.version);

program
  .command('scan <path>')
  .description('Scan a skill directory for security issues')
  .option('--json', 'Output results as JSON')
  .option('--fail-on <severity>', 'Exit with code 1 if findings at this severity or above', 'CRITICAL')
  .action((targetPath: string, opts: { json?: boolean; failOn?: string }) => {
    const resolved = require('path').resolve(targetPath);
    if (!fs.existsSync(resolved)) {
      console.error(chalk.red(`Error: Path not found: ${resolved}`));
      process.exit(1);
    }

    const result = scanDirectory(resolved);

    if (opts.json) {
      console.log(formatJSON(result));
    } else {
      console.log(formatReport(result));
    }

    // Exit code based on findings
    const severityOrder = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
    const threshold = severityOrder.indexOf(opts.failOn?.toUpperCase() || 'CRITICAL');
    const hasFailing = result.findings.some(
      f => severityOrder.indexOf(f.severity) >= threshold
    );
    if (hasFailing) process.exit(1);
  });

program
  .command('verify <path>')
  .description('Verify integrity of a skill via SHA-256 hash')
  .option('--hash <hash>', 'Expected hash to compare against')
  .option('--json', 'Output results as JSON')
  .action((targetPath: string, opts: { hash?: string; json?: boolean }) => {
    const resolved = require('path').resolve(targetPath);
    if (!fs.existsSync(resolved)) {
      console.error(chalk.red(`Error: Path not found: ${resolved}`));
      process.exit(1);
    }

    const result = verifyPath(resolved, opts.hash);

    if (opts.json) {
      console.log(formatVerifyJSON(result));
    } else {
      console.log(formatVerifyReport(result));
    }

    if (result.match === false) process.exit(1);
  });

program.parse();
