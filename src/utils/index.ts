import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';

export function readFileSafe(filePath: string): string | null {
  try {
    return fs.readFileSync(filePath, 'utf-8');
  } catch {
    return null;
  }
}

export function getAllFiles(dir: string, extensions: string[] = []): string[] {
  const results: string[] = [];
  if (!fs.existsSync(dir)) return results;

  const stat = fs.statSync(dir);
  if (stat.isFile()) {
    if (extensions.length === 0 || extensions.some(ext => dir.endsWith(ext))) {
      results.push(dir);
    }
    return results;
  }

  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.name.startsWith('.') || entry.name === 'node_modules') continue;
    if (entry.isDirectory()) {
      results.push(...getAllFiles(fullPath, extensions));
    } else if (entry.isFile()) {
      if (extensions.length === 0 || extensions.some(ext => entry.name.endsWith(ext))) {
        results.push(fullPath);
      }
    }
  }
  return results;
}

export function hashFile(filePath: string): string {
  const content = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(content).digest('hex');
}

export function hashDirectory(dir: string): string {
  const files = getAllFiles(dir).sort();
  const hash = crypto.createHash('sha256');
  for (const file of files) {
    const rel = path.relative(dir, file);
    hash.update(rel);
    hash.update(fs.readFileSync(file));
  }
  return hash.digest('hex');
}

export const SCAN_EXTENSIONS = [
  '.ts', '.js', '.mjs', '.cjs', '.py', '.sh', '.bash',
  '.md', '.json', '.yaml', '.yml', '.toml',
];
