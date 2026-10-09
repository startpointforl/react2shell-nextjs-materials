import { statSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { buildParents } from './ast.js'
import { parseFile } from './ast.js'
import { findActions } from './actions.js'
import { callsIn } from './taint.js'
import { isAuthCall, isAuthWrapper, isMutationCall } from './patterns.js'
import { discoverFiles, mightHaveServerCode, readCode, toRel } from './discover.js'
import { collectSuppressions, filterSuppressed } from './suppress.js'
import { rulesFor } from './rules/index.js'
import type {
  ActionSummary,
  FileContext,
  Finding,
  ProjectContext,
  Rule,
  ScanResult,
  Severity,
} from './types.js'

export interface ScanOptions {
  heuristics: boolean
  rules?: Rule[]
}

const SEVERITY_ORDER: Record<Severity, number> = { high: 0, medium: 1, low: 2 }
const CONFIDENCE_ORDER = { high: 0, medium: 1, heuristic: 2 }

export function scan(target: string, opts: ScanOptions): ScanResult {
  const rules = opts.rules ?? rulesFor({ heuristics: opts.heuristics })
  const abs = resolve(target)
  const files = discoverFiles(abs)
  const root = isFile(abs) ? dirname(abs) : abs

  // Проход 1: разбор файлов с server-кодом, сбор контекстов и имён экшенов
  const contexts: FileContext[] = []
  const parseErrors: { file: string; message: string }[] = []
  const project: ProjectContext = { root, actionNames: new Set() }

  for (const abs of files) {
    const code = readCode(abs)
    if (!mightHaveServerCode(code)) continue
    const rel = toRel(root, abs)
    try {
      const ast = parseFile(code, abs)
      const { moduleDirective, actions } = findActions(ast, rel)
      const hasBind = /\.bind\s*\(/.test(code)
      // файл без экшенов держим в контексте только если там есть .bind() — для bound-secret
      if (actions.length === 0 && !hasBind) continue
      const parents = buildParents(ast)
      for (const a of actions) project.actionNames.add(a.name)
      contexts.push({ file: rel, absPath: abs, code, ast, parents, moduleDirective, actions })
    } catch (err) {
      parseErrors.push({ file: rel, message: (err as Error).message })
    }
  }

  // Проход 2: правила + сбор карты экшенов
  const findings: Finding[] = []
  const actionSummaries: ActionSummary[] = []
  let suppressed = 0

  for (const ctx of contexts) {
    const raw: Finding[] = []
    for (const rule of rules) {
      try {
        raw.push(...rule.check(ctx, project))
      } catch (err) {
        parseErrors.push({ file: ctx.file, message: `rule ${rule.meta.id}: ${(err as Error).message}` })
      }
    }
    const { kept, suppressed: n } = filterSuppressed(raw, collectSuppressions(ctx.code))
    suppressed += n
    findings.push(...kept)

    for (const a of ctx.actions) {
      const calls = callsIn(a.fn)
      actionSummaries.push({
        name: a.name,
        file: ctx.file,
        line: a.line,
        kind: a.kind,
        params: a.params,
        wrapper: a.wrapper,
        mutates: calls.some((c) => c.type === 'CallExpression' && isMutationCall(c)),
        authCheck: isAuthWrapper(a.wrapper) || calls.some((c) => isAuthCall(c)),
      })
    }
  }

  findings.sort(
    (a, b) =>
      SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] ||
      CONFIDENCE_ORDER[a.confidence] - CONFIDENCE_ORDER[b.confidence] ||
      a.file.localeCompare(b.file) ||
      a.line - b.line,
  )

  return {
    root,
    filesScanned: files.length,
    filesWithActions: contexts.filter((c) => c.actions.length > 0).length,
    findings,
    actions: actionSummaries.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line),
    parseErrors,
    suppressed,
  }
}

function isFile(target: string): boolean {
  try {
    return statSync(target).isFile()
  } catch {
    return false
  }
}
