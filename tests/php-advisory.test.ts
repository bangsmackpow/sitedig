import { describe, expect, it } from 'vitest';
import { evaluatePhpAdvisory, parseRuntimeVersion, PHP2SHELL } from '../src/shared/advisories';
import { detectPhpRuntime } from '../src/worker/php-runtime';

function evaluate(version: string | null) {
  return evaluatePhpAdvisory(PHP2SHELL, parseRuntimeVersion(version));
}

describe('PHP2Shell advisory', () => {
  it('flags vulnerable supported branches below the fixed release', () => {
    expect(evaluate('8.2.34').state).toBe('vulnerable');
    expect(evaluate('8.3.35').state).toBe('vulnerable');
    expect(evaluate('8.4.26').state).toBe('vulnerable');
    expect(evaluate('8.5.11').state).toBe('vulnerable');
  });

  it('accepts fixed releases and later patches', () => {
    expect(evaluate('8.2.35').state).toBe('fixed');
    expect(evaluate('8.3.36').state).toBe('fixed');
    expect(evaluate('8.4.27').state).toBe('fixed');
    expect(evaluate('8.5.12').state).toBe('fixed');
    expect(evaluate('8.4.28').state).toBe('fixed');
  });

  it('flags end-of-life branches', () => {
    expect(evaluate('8.1.99').state).toBe('vulnerable');
    expect(evaluate('7.4.33').state).toBe('vulnerable');
    expect(evaluate('5.6.40').state).toBe('vulnerable');
  });

  it('parses distro and banner version strings', () => {
    expect(parseRuntimeVersion('PHP/8.4.26')).toMatchObject({ major: 8, minor: 4, patch: 26 });
    expect(parseRuntimeVersion('8.2.35-1.el9')).toMatchObject({ major: 8, minor: 2, patch: 35 });
    expect(parseRuntimeVersion('Apache/2.4.62 PHP/8.3.35')).toMatchObject({ major: 8, minor: 3, patch: 35 });
    expect(parseRuntimeVersion('PHP 8.5.11 +deb13u1')).toMatchObject({ major: 8, minor: 5, patch: 11 });
  });

  it('returns unknown without a version', () => {
    expect(evaluate(null).state).toBe('unknown');
  });
});

describe('PHP runtime detection', () => {
  it('extracts a version from X-Powered-By', () => {
    const detection = detectPhpRuntime({
      technologies: [],
      http: { status: 200, finalUrl: null, server: null, poweredBy: 'PHP/8.4.26', headers: {}, redirects: [], error: null },
    });
    expect(detection.present).toBe(true);
    expect(detection.version).toBe('8.4.26');
    expect(detection.confidence).toBe('high');
  });

  it('extracts a version from the whatweb PHP plugin', () => {
    const detection = detectPhpRuntime({
      technologies: [{ name: 'PHP', version: '8.3.35' }],
      http: null,
    });
    expect(detection.present).toBe(true);
    expect(detection.version).toBe('8.3.35');
    expect(detection.sources).toContain('whatweb');
  });

  it('extracts a version from httpx tech strings', () => {
    const detection = detectPhpRuntime({
      technologies: [],
      http: null,
      httpx: {
        url: 'https://example.com',
        status: 200,
        finalUrl: null,
        server: null,
        headers: {},
        cookies: [],
        tlsVersion: null,
        certExpiry: null,
        technologies: ['PHP:8.5.11'],
        error: null,
      },
    });
    expect(detection.present).toBe(true);
    expect(detection.version).toBe('8.5.11');
    expect(detection.sources).toContain('httpx');
  });

  it('detects PHP without a version from a session cookie', () => {
    const detection = detectPhpRuntime({
      technologies: [],
      http: null,
      httpx: {
        url: 'https://example.com',
        status: 200,
        finalUrl: null,
        server: null,
        headers: {},
        cookies: [{ name: 'PHPSESSID', secure: true, httpOnly: true }],
        tlsVersion: null,
        certExpiry: null,
        technologies: [],
        error: null,
      },
    });
    expect(detection.present).toBe(true);
    expect(detection.version).toBeNull();
  });

  it('does not treat unrelated technologies as PHP', () => {
    const detection = detectPhpRuntime({
      technologies: [{ name: 'phpMyAdmin', version: '5.2.1' }],
      http: null,
    });
    expect(detection.present).toBe(false);
  });
});
