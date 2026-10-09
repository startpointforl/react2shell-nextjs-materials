
import { memberChain, ownReturns, propertyName, snippet, unwrap, walk } from '../ast.js'
import type { Finding, FileContext, Node, Rule, ServerAction } from '../types.js'
import { Taint } from '../taint.js'
import { isDbReadCall } from '../patterns.js'

/** return возвращает сырую запись из БД (findFirst/findUnique без select) */
function returnsRawDbRow(returnArg: Node, taint: Taint): Node | undefined {
  const r = unwrap(returnArg)
  if (isDbReadCall(r)) return r
  if (r.type === 'Identifier' && taint.dbRows.has(r.name)) return r
  if (r.type === 'ObjectExpression') {
    for (const p of r.properties) {
      if (p.type === 'Property') {
        const v = unwrap(p.value as Node)
        if (isDbReadCall(v)) return v
        if (v.type === 'Identifier' && taint.dbRows.has(v.name)) return v
      }
      if (p.type === 'SpreadElement') {
        const a = unwrap(p.argument)
        if (a.type === 'Identifier' && taint.dbRows.has(a.name)) return a
      }
    }
  }
  return undefined
}

/** return { error: e.message } / return String(e) — внутри catch */
function returnsErrorDetail(returnArg: Node, catchParams: Set<string>): Node | undefined {
  const check = (node: Node): Node | undefined => {
    const n = unwrap(node)
    if (n.type === 'MemberExpression') {
      const root = memberChain(n)[0]
      if (catchParams.has(root) && ['message', 'stack'].includes(propertyName(n) ?? '')) return n
    }
    if (n.type === 'CallExpression') {
      const callee = unwrap(n.callee)
      if (callee.type === 'Identifier' && callee.name === 'String' && n.arguments[0]) {
        const a = unwrap(n.arguments[0] as Node)
        if (a.type === 'Identifier' && catchParams.has(a.name)) return n
      }
      if (callee.type === 'MemberExpression' && propertyName(callee) === 'toString') {
        const o = unwrap(callee.object)
        if (o.type === 'Identifier' && catchParams.has(o.name)) return n
      }
    }
    return undefined
  }
  const r = unwrap(returnArg)
  const direct = check(r)
  if (direct) return direct
  if (r.type === 'ObjectExpression') {
    for (const p of r.properties) {
      if (p.type === 'Property') {
        const hit = check(p.value as Node)
        if (hit) return hit
      }
    }
  }
  return undefined
}

function analyze(action: ServerAction, ctx: FileContext): Finding[] {
  const out: Finding[] = []
  const taint = new Taint(action.fn)
  const returns = ownReturns(action.fn, ctx.parents)

  for (const ret of returns) {
    const raw = returnsRawDbRow(ret, taint)
    if (raw) {
      out.push({
        ruleId: 'return-leak',
        type: 'Over-returning',
        severity: 'low',
        confidence: 'heuristic',
        file: ctx.file,
        line: ret.loc.start.line,
        column: ret.loc.start.column + 1,
        endLine: ret.loc.end.line,
        endColumn: ret.loc.end.column + 1,
        action: action.name,
        message: `Raw database row returned to the client — \`${snippet(ctx.code, ret)}\``,
        why:
          'A DB row without an explicit select is returned whole — including fields like passwordHash, ' +
          'tokenVersion and internal flags.',
        fix: 'Return a DTO with explicit fields (select/omit), not the raw row.',
      })
    }
  }

  // ошибки: ищем return внутри catch-блоков
  walk(action.fn.body, (node) => {
    if (node !== action.fn && (node.type === 'FunctionDeclaration' || node.type === 'FunctionExpression' || node.type === 'ArrowFunctionExpression')) return false
    if (node.type !== 'CatchClause') return
    const catchParams = new Set<string>()
    if (node.param && node.param.type === 'Identifier') catchParams.add(node.param.name)
    if (catchParams.size === 0) return
    walk(node.body, (inner) => {
      if (inner.type === 'ReturnStatement' && inner.argument) {
        const hit = returnsErrorDetail(inner.argument, catchParams)
        if (hit) {
          out.push({
            ruleId: 'return-leak',
            type: 'Over-returning',
            severity: 'low',
            confidence: 'heuristic',
            file: ctx.file,
            line: hit.loc.start.line,
            column: hit.loc.start.column + 1,
            endLine: hit.loc.end.line,
            endColumn: hit.loc.end.column + 1,
            action: action.name,
            message: `Error details returned to the client — \`${snippet(ctx.code, hit)}\``,
            why:
              'Next.js masks thrown errors but not returned values. e.message/e.stack in a return reach the ' +
              'client together with the stack trace and internal details.',
            fix: 'Log the error server-side and return a generic message without message/stack.',
          })
        }
      }
    })
  })

  return out
}

export const returnLeakRule: Rule = {
  meta: {
    id: 'return-leak',
    title: 'Over-returning',
    category: 'hygiene',
    description:
      'Returning a raw DB row (no select) or a value with e.message/e.stack. Unlike thrown errors, ' +
      'returned values are not masked by Next.js.',
  },
  check(ctx) {
    return ctx.actions.flatMap((a) => analyze(a, ctx))
  },
}
