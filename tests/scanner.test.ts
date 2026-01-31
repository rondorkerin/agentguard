import * as path from 'path';
import { scanDirectory } from '../src/scanner/analyzer';

const FIXTURES = path.join(__dirname, 'fixtures');

describe('AgentGuard Scanner', () => {
  test('clean skill has high trust score', () => {
    const result = scanDirectory(path.join(FIXTURES, 'clean-skill'));
    expect(result.score).toBeGreaterThanOrEqual(70);
    expect(result.findings.filter(f => f.severity === 'CRITICAL')).toHaveLength(0);
  });

  test('malicious skill has low trust score', () => {
    const result = scanDirectory(path.join(FIXTURES, 'malicious-skill'));
    expect(result.score).toBeLessThan(50);
    expect(result.findings.length).toBeGreaterThan(5);
  });

  test('malicious skill detects credential exfiltration', () => {
    const result = scanDirectory(path.join(FIXTURES, 'malicious-skill'));
    const credFindings = result.findings.filter(f => f.category === 'credential-exfil');
    expect(credFindings.length).toBeGreaterThan(0);
  });

  test('malicious skill detects injection patterns', () => {
    const result = scanDirectory(path.join(FIXTURES, 'malicious-skill'));
    const injFindings = result.findings.filter(f => f.category === 'injection');
    expect(injFindings.length).toBeGreaterThan(0);
  });

  test('malicious skill detects obfuscation', () => {
    const result = scanDirectory(path.join(FIXTURES, 'malicious-skill'));
    const obfFindings = result.findings.filter(f => f.category === 'obfuscation');
    expect(obfFindings.length).toBeGreaterThan(0);
  });

  test('returns correct file count', () => {
    const result = scanDirectory(path.join(FIXTURES, 'clean-skill'));
    expect(result.files).toBe(2); // SKILL.md + index.ts
  });
});
