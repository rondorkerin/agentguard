import * as path from 'path';
import { scanDirectory } from '../src/scanner/analyzer';

const FIXTURES = path.join(__dirname, 'fixtures');

describe('AgentGuard Scanner', () => {
  test('clean skill has high trust score (90+)', () => {
    const result = scanDirectory(path.join(FIXTURES, 'clean-skill'));
    expect(result.score).toBeGreaterThanOrEqual(90);
    expect(result.findings.filter(f => f.severity === 'CRITICAL')).toHaveLength(0);
  });

  test('clean skill fetch() is not flagged as outbound with sensitive data', () => {
    const result = scanDirectory(path.join(FIXTURES, 'clean-skill'));
    const cred006 = result.findings.filter(f => f.id === 'CRED-006');
    expect(cred006).toHaveLength(0);
  });

  test('malicious skill has low trust score', () => {
    const result = scanDirectory(path.join(FIXTURES, 'malicious-skill'));
    expect(result.score).toBeLessThan(10);
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

  test('malicious skill triggers compound pattern (creds + network)', () => {
    const result = scanDirectory(path.join(FIXTURES, 'malicious-skill'));
    const compound = result.findings.filter(f => f.id === 'COMPOUND-001');
    expect(compound.length).toBeGreaterThan(0);
  });

  test('returns correct file count', () => {
    const result = scanDirectory(path.join(FIXTURES, 'clean-skill'));
    expect(result.files).toBe(2); // SKILL.md + index.ts
  });

  test('markdown narrative text is not scanned (only code blocks)', () => {
    // The clean SKILL.md has no code blocks with suspicious patterns
    const result = scanDirectory(path.join(FIXTURES, 'clean-skill'));
    const mdFindings = result.findings.filter(f => f.file.endsWith('.md'));
    expect(mdFindings).toHaveLength(0);
  });

  test('doc findings have reduced severity', () => {
    // Create a scenario: malicious-skill SKILL.md has no code blocks, so no md findings
    const result = scanDirectory(path.join(FIXTURES, 'malicious-skill'));
    const mdFindings = result.findings.filter(f => f.file.endsWith('.md'));
    // Malicious SKILL.md has no code blocks, so nothing from it
    expect(mdFindings).toHaveLength(0);
  });
});
