import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { parseFile, buildParents } from '../src/ast.js'
import { findActions } from '../src/actions.js'
import { ALL_RULES } from '../src/rules/index.js'
import { scan } from '../src/scan.js'
import type { Finding, FileContext, ProjectContext, Rule } from '../src/types.js'

const here = dirname(fileURLToPath(import.meta.url))
const fixtures = join(here, 'fixtures')

function run(file: string, rules: Rule[] = ALL_RULES): Finding[] {
  const abs = join(fixtures, file)
  const code = readFileSync(abs, 'utf8')
  const ast = parseFile(code, abs)
  const { moduleDirective, actions } = findActions(ast, file)
  const ctx: FileContext = { file, absPath: abs, code, ast, parents: buildParents(ast), moduleDirective, actions }
  const project: ProjectContext = { root: fixtures, actionNames: new Set(actions.map((a) => a.name)) }
  return rules.flatMap((r) => r.check(ctx, project))
}

const ruleById = (id: string) => ALL_RULES.filter((r) => r.meta.id === id)

describe('stringify-arg (55183)', () => {
  it('ловит все три формы приведения к строке с возвратом', () => {
    const f = run('bad/stringify.ts', ruleById('stringify-arg'))
    expect(f.map((x) => x.action).sort()).toEqual(['echo', 'greet', 'stamp'])
    expect(f.every((x) => x.severity === 'high' && x.confidence === 'high')).toBe(true)
    expect(f.every((x) => x.cve?.includes('CVE-2025-55183'))).toBe(true)
  })

  it('ловит реальный leakyAction из демо', () => {
    const f = run('../../../../vulnerable-target/app/actions.ts', ruleById('stringify-arg'))
    expect(f).toHaveLength(1)
    expect(f[0].action).toBe('leakyAction')
    expect(f[0].severity).toBe('high')
  })

  it('не срабатывает, когда тип проверен до использования', () => {
    const f = run('good/clean.ts', ruleById('stringify-arg'))
    expect(f).toHaveLength(0)
  })
})

describe('hardcoded-secret (55183)', () => {
  it('ловит литералы-ключи внутри экшена', () => {
    const f = run('bad/secrets.ts', ruleById('hardcoded-secret'))
    expect(f.length).toBeGreaterThanOrEqual(2)
    expect(f.every((x) => x.severity === 'high')).toBe(true)
    // отчёт маскирует значение
    expect(f.every((x) => !x.message.includes('sk_live_51H9xQ2eZvKYlo2C8kR3nD4pXmT7wY6aB'))).toBe(true)
  })

  it('не срабатывает на process.env', () => {
    const f = run('good/clean.ts', ruleById('hardcoded-secret'))
    expect(f).toHaveLength(0)
  })
})

describe('bound-secret (55183)', () => {
  it('ловит секрет в .bind()', () => {
    const f = run('bad/bind.tsx', ruleById('bound-secret'))
    expect(f).toHaveLength(1)
    expect(f[0].ruleId).toBe('bound-secret')
    expect(f[0].action).toBe('updateUser')
  })
})

describe('hygiene', () => {
  it('missing-auth: мутация без проверки прав', () => {
    const f = run('bad/hygiene.ts', ruleById('missing-auth'))
    expect(f.map((x) => x.action)).toContain('deletePost')
  })

  it('dangerous-sink: redirect и exec', () => {
    const f = run('bad/hygiene.ts', ruleById('dangerous-sink'))
    const types = f.map((x) => x.type)
    expect(types).toContain('Open redirect')
    expect(types).toContain('Command injection')
  })

  it('mass-assignment: весь вход в data', () => {
    const f = run('bad/hygiene.ts', ruleById('mass-assignment'))
    expect(f.map((x) => x.action)).toContain('updateProfile')
  })

  it('return-leak: сырая запись и детали ошибки', () => {
    const f = run('bad/hygiene.ts', ruleById('return-leak'))
    expect(f.map((x) => x.action)).toContain('getUser')
    expect(f.map((x) => x.action)).toContain('risky')
  })

  it('чистый файл не даёт находок гигиены', () => {
    const hygiene = ALL_RULES.filter((r) => r.meta.category === 'hygiene')
    const f = run('good/clean.ts', hygiene)
    expect(f).toHaveLength(0)
  })
})

describe('общие свойства', () => {
  it('файл без use server не даёт находок', () => {
    const f = run('good/not-actions.ts')
    expect(f).toHaveLength(0)
  })

  it('scan() игнорирует подавленную комментарием находку', () => {
    const result = scan(join(fixtures, 'good/suppressed.ts'), { heuristics: true })
    expect(result.findings).toHaveLength(0)
    expect(result.suppressed).toBe(1)
  })

  it('--no-heuristics оставляет только CVE-правила', () => {
    const result = scan(join(fixtures, 'bad/hygiene.ts'), { heuristics: false })
    expect(result.findings.every((x) => x.cve && x.cve.length > 0)).toBe(true)
  })

  it('scan() строит карту экшенов с флагом мутации', () => {
    const result = scan(join(fixtures, 'bad/hygiene.ts'), { heuristics: true })
    const del = result.actions.find((a) => a.name === 'deletePost')
    expect(del?.mutates).toBe(true)
    expect(del?.authCheck).toBe(false)
  })
})
