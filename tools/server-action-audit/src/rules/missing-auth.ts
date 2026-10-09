import type { TSESTree } from '@typescript-eslint/typescript-estree'
import { snippet } from '../ast.js'
import type { Finding, Rule, ServerAction } from '../types.js'
import { callsIn } from '../taint.js'
import { isAuthCall, isAuthWrapper, mutationsIn } from '../patterns.js'

/** Есть ли вызов авторизации до первой мутации (по позиции в исходнике) */
function authBeforeMutation(action: ServerAction, mutations: TSESTree.CallExpression[]): boolean {
  if (isAuthWrapper(action.wrapper)) return true
  const firstMutation = Math.min(...mutations.map((m) => m.range[0]))
  for (const call of callsIn(action.fn)) {
    if (isAuthCall(call) && call.range[0] < firstMutation) return true
  }
  return false
}

export const missingAuthRule: Rule = {
  meta: {
    id: 'missing-auth',
    title: 'Missing authorization',
    category: 'hygiene',
    description:
      'An exported Server Action performs a mutation (db create/update/delete, fetch POST) without a visible ' +
      'auth/getSession/permission check before it. A Server Action is a public endpoint, not an internal function.',
  },
  check(ctx) {
    const out: Finding[] = []
    for (const action of ctx.actions) {
      const mutations = mutationsIn(action.fn)
      if (mutations.length === 0) continue
      if (authBeforeMutation(action, mutations)) continue
      const m = mutations.sort((a, b) => a.range[0] - b.range[0])[0]
      out.push({
        ruleId: 'missing-auth',
        type: 'Missing authorization',
        severity: 'medium',
        confidence: 'heuristic',
        file: ctx.file,
        line: m.loc.start.line,
        column: m.loc.start.column + 1,
        endLine: m.loc.end.line,
        endColumn: m.loc.end.column + 1,
        action: action.name,
        message: `${action.name}: mutation without a visible auth check — \`${snippet(ctx.code, m)}\``,
        why:
          'A Server Action is a public endpoint — anyone can POST to it by id. Without a permission check ' +
          'before the mutation it is effectively an unprotected write endpoint.',
        fix: 'Check the session/permissions at the start of the action (auth(), getSession(), requireUser()) or wrap it in auth middleware.',
      })
    }
    return out
  },
}
