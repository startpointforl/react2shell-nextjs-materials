#!/usr/bin/env node
import { existsSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { scan } from './scan.js';
import { renderText } from './report/text.js';
import { renderJson } from './report/json.js';
const HELP = `
server-action-audit — static analysis of Server Action code (React Server Components / Next.js)

Flags patterns related to React2Shell (CVE-2025-55182/55183/55184) and Server Action hygiene
issues. It points at code worth reviewing — not proof of a vulnerability.

Usage:
  npx server-action-audit [path...] [options]

Arguments:
  path                 file or directory to scan (default: app, src, ./)

Options:
  --format <fmt>       text | json                    (default: text)
  -o, --output <file>  write the report to a file instead of stdout
  --no-heuristics      CVE rules only (skip the "Hygiene" section)
  --fail-on <sev>      non-zero exit on findings >= severity: high|medium|low (default: high)
  --audit              also run \`npm audit\` (version check) and print the summary
  --no-color           disable ANSI color
  -h, --help           show this help
  -v, --version        show the version

Rule reference (what each type means and how to fix it) lives in the README.
Exit codes: 0 — clean (below threshold); 1 — findings >= --fail-on; 2 — startup error.
`;
function parseArgs(argv) {
    const o = {
        targets: [],
        format: 'text',
        heuristics: true,
        failOn: 'high',
        audit: false,
        color: process.stdout.isTTY ?? false,
    };
    for (let i = 0; i < argv.length; i++) {
        const a = argv[i];
        switch (a) {
            case '-h':
            case '--help':
                return { help: true };
            case '-v':
            case '--version':
                return { version: true };
            case '--format':
                o.format = expectEnum(argv[++i], ['text', 'json'], '--format');
                break;
            case '-o':
            case '--output':
                o.output = expect(argv[++i], '--output');
                break;
            case '--no-heuristics':
                o.heuristics = false;
                break;
            case '--heuristics':
                o.heuristics = true;
                break;
            case '--fail-on':
                o.failOn = expectEnum(argv[++i], ['high', 'medium', 'low'], '--fail-on');
                break;
            case '--audit':
                o.audit = true;
                break;
            case '--no-color':
                o.color = false;
                break;
            case '--color':
                o.color = true;
                break;
            default:
                if (a.startsWith('-'))
                    fail(`unknown option: ${a}`);
                o.targets.push(a);
        }
    }
    if (o.targets.length === 0)
        o.targets = defaultTargets();
    if (o.format !== 'text')
        o.color = false;
    return o;
}
function defaultTargets() {
    const found = ['app', 'src'].filter((d) => existsSync(d));
    return found.length ? found : ['.'];
}
function expect(v, name) {
    if (v === undefined)
        fail(`option ${name} requires a value`);
    return v;
}
function expectEnum(v, allowed, name) {
    const val = expect(v, name);
    if (!allowed.includes(val))
        fail(`${name}: expected ${allowed.join('|')}, got "${val}"`);
    return val;
}
function fail(msg) {
    process.stderr.write(`server-action-audit: ${msg}\n`);
    process.exit(2);
}
function mergeResults(results) {
    if (results.length === 1)
        return results[0];
    return {
        root: results[0]?.root ?? process.cwd(),
        filesScanned: sum(results, (r) => r.filesScanned),
        filesWithActions: sum(results, (r) => r.filesWithActions),
        findings: results.flatMap((r) => r.findings),
        actions: results.flatMap((r) => r.actions),
        parseErrors: results.flatMap((r) => r.parseErrors),
        suppressed: sum(results, (r) => r.suppressed),
    };
}
const sum = (arr, f) => arr.reduce((n, t) => n + f(t), 0);
const SEV_RANK = { high: 3, medium: 2, low: 1 };
function runAudit() {
    const res = spawnSync('npm', ['audit', '--omit=dev'], { encoding: 'utf8' });
    if (res.error)
        return `npm audit did not run: ${res.error.message}`;
    const text = (res.stdout || '') + (res.stderr || '');
    const vulnLine = text.split(/\r?\n/).find((l) => /vulnerabilit/i.test(l) && /found|\d/.test(l));
    return vulnLine?.trim() || text.trim().split(/\r?\n/).slice(-3).join('\n') || 'npm audit: no output';
}
function main() {
    const parsed = parseArgs(process.argv.slice(2));
    if ('help' in parsed) {
        process.stdout.write(HELP);
        return;
    }
    if ('version' in parsed) {
        process.stdout.write('0.1.0\n');
        return;
    }
    const opts = parsed;
    const results = opts.targets.map((t) => scan(t, { heuristics: opts.heuristics }));
    const result = mergeResults(results);
    const report = opts.format === 'json' ? renderJson(result) : renderText(result, { color: opts.color });
    if (opts.output) {
        writeFileSync(opts.output, report.endsWith('\n') ? report : report + '\n');
        process.stderr.write(`Report written: ${opts.output}\n`);
    }
    else {
        process.stdout.write(report + '\n');
    }
    if (opts.audit && opts.format === 'text') {
        process.stdout.write('\n── npm audit (version check) ──\n');
        process.stdout.write(runAudit() + '\n');
    }
    const worst = result.findings.reduce((acc, f) => (acc === null || SEV_RANK[f.severity] > SEV_RANK[acc] ? f.severity : acc), null);
    const shouldFail = worst !== null && SEV_RANK[worst] >= SEV_RANK[opts.failOn];
    process.exit(shouldFail ? 1 : 0);
}
main();
