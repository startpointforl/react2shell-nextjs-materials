import type { Finding, ScanResult, Severity } from '../types.js'
import { ALL_RULES } from '../rules/index.js'

const META = new Map(ALL_RULES.map((r) => [r.meta.id, r.meta]))

interface Style {
  bold: (s: string) => string
  dim: (s: string) => string
  red: (s: string) => string
  yellow: (s: string) => string
  blue: (s: string) => string
  green: (s: string) => string
  cyan: (s: string) => string
}

function makeStyle(color: boolean): Style {
  const wrap = (code: string) => (s: string) => (color ? `\x1b[${code}m${s}\x1b[0m` : s)
  return {
    bold: wrap('1'),
    dim: wrap('2'),
    red: wrap('31'),
    yellow: wrap('33'),
    blue: wrap('34'),
    green: wrap('32'),
    cyan: wrap('36'),
  }
}

const SEV_LABEL: Record<Severity, string> = { high: 'high', medium: 'medium', low: 'low' }

function sevColor(s: Style, sev: Severity): (t: string) => string {
  return sev === 'high' ? s.red : sev === 'medium' ? s.yellow : s.blue
}

export function renderText(result: ScanResult, opts: { color: boolean }): string {
  const s = makeStyle(opts.color)
  const lines: string[] = []
  const { findings } = result

  const counts: Record<Severity, number> = { high: 0, medium: 0, low: 0 }
  for (const f of findings) counts[f.severity]++

  const summary =
    [
      counts.high ? s.red(`${counts.high} high`) : null,
      counts.medium ? s.yellow(`${counts.medium} medium`) : null,
      counts.low ? s.blue(`${counts.low} low`) : null,
    ]
      .filter(Boolean)
      .join(s.dim(' · ')) || s.green('no findings')

  lines.push('')
  lines.push(`${s.bold('server-action-audit')}${s.dim('  ')}${summary}`)
  const sub = `${result.actions.length} server action(s) in ${result.filesWithActions} file(s) · ${result.filesScanned} file(s) scanned`
  lines.push(s.dim(result.suppressed ? `${sub} · ${result.suppressed} suppressed` : sub))

  const cve = findings.filter((f) => META.get(f.ruleId)?.category === 'cve')
  const hygiene = findings.filter((f) => META.get(f.ruleId)?.category === 'hygiene')

  if (cve.length) {
    lines.push('')
    lines.push(s.bold('React2Shell (CVE)'))
    for (const f of cve) lines.push(...renderFinding(f, s))
  }
  if (hygiene.length) {
    lines.push('')
    lines.push(`${s.bold('Hygiene')} ${s.dim('(heuristics — expect false positives)')}`)
    for (const f of hygiene) lines.push(...renderFinding(f, s))
  }

  lines.push('')
  lines.push(...renderEndpointMap(result, s))

  if (result.parseErrors.length) {
    lines.push('')
    lines.push(s.dim(`${result.parseErrors.length} file(s)/rule(s) failed to parse (see --json for details)`))
  }

  lines.push('')
  lines.push(s.dim('─'.repeat(78)))
  lines.push(
    s.dim('This points at code worth reviewing — not proof of a vulnerability. Heuristics are noisy.'),
  )
  lines.push(s.dim('See the rule reference in the README for what each type means and how to fix it.'))
  lines.push(
    s.dim(
      'Real CVE fix = upgrade React: 55182 → 19.0.1/19.1.2/19.2.1 · 55183/55184 → 19.0.4/19.1.5/19.2.4 · ' +
        '2026-23864 → 19.2.4, then run npm audit.',
    ),
  )
  lines.push('')

  return lines.join('\n')
}

function renderFinding(f: Finding, s: Style): string[] {
  const sev = sevColor(s, f.severity)
  const head = `${sev(s.bold(SEV_LABEL[f.severity].padEnd(6)))} ${s.bold(f.type)}${s.dim('  ' + f.file + ':' + f.line)}`
  const meta = [f.cve?.join(', '), `rule: ${f.ruleId}`, `confidence: ${f.confidence}`].filter(Boolean).join(' · ')
  return ['', head, `       ${f.message}`, `       ${s.dim(meta)}`]
}

function renderEndpointMap(result: ScanResult, s: Style): string[] {
  const mutating = result.actions.filter((a) => a.mutates).length
  const lines = [
    `${s.bold(`Server actions (${result.actions.length})`)} ${s.dim(`— public endpoints; ${mutating} perform mutations`)}`,
  ]
  if (result.actions.length === 0) {
    lines.push(s.dim('  none found'))
    return lines
  }
  for (const a of result.actions) {
    const flags = [
      a.mutates ? s.yellow('mutation') : null,
      a.mutates && !a.authCheck ? s.red('no-auth') : null,
      a.wrapper ? s.dim(`wrapped: ${a.wrapper}`) : null,
      a.kind === 'inline' ? s.dim('inline') : null,
    ]
      .filter(Boolean)
      .join('  ')
    const name = `${a.name}/${a.params}`
    lines.push(`  ${s.cyan((a.file + ':' + a.line).padEnd(38))} ${name.padEnd(22)} ${flags}`)
  }
  return lines
}
