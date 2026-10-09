import type { TSESTree } from '@typescript-eslint/typescript-estree'
import { calleeName, memberChain, snippet, unwrap } from '../ast.js'
import type { Finding, Node, Rule } from '../types.js'
import { callsIn, Taint } from '../taint.js'
import { isMutationCall } from '../patterns.js'

/** Значение — «весь вход целиком»: input, {...input}, Object.fromEntries(formData) */
function wholeInput(node: Node, taint: Taint): boolean {
  const n = unwrap(node)
  if (n.type === 'Identifier') return taint.direct.has(n.name)
  if (n.type === 'CallExpression') {
    const name = calleeName(n)
    if (name === 'fromEntries' && memberChain(unwrap(n.callee))[0] === 'Object') return taint.isDirect(n.arguments[0] as Node)
  }
  if (n.type === 'ObjectExpression') {
    // { ...input } без явного перечисления полений — расплывчатый перенос
    const spreads = n.properties.filter((p) => p.type === 'SpreadElement' && taint.isDirect(p.argument))
    return spreads.length > 0
  }
  return false
}

/** Ищем { data: <весь вход> } / { set: … } / первый аргумент create/insert */
function dataPayloads(call: TSESTree.CallExpression): Node[] {
  const out: Node[] = []
  const arg0 = call.arguments[0] ? unwrap(call.arguments[0] as Node) : undefined
  if (arg0?.type === 'ObjectExpression') {
    for (const p of arg0.properties) {
      if (p.type === 'Property' && p.key.type === 'Identifier' && ['data', 'set', 'values', 'update', 'create'].includes(p.key.name)) {
        out.push(p.value as Node)
      }
    }
    if (out.length === 0) out.push(arg0)
  } else if (arg0) {
    out.push(arg0)
  }
  return out
}

export const massAssignmentRule: Rule = {
  meta: {
    id: 'mass-assignment',
    title: 'Mass assignment',
    category: 'hygiene',
    description:
      'Object.fromEntries(formData) or the whole input object is passed to db.*.update/create ({ data: input }). ' +
      'The client can add any field — e.g. role: "admin".',
  },
  check(ctx) {
    const out: Finding[] = []
    for (const action of ctx.actions) {
      const taint = new Taint(action.fn)
      if (taint.params.length === 0) continue
      for (const call of callsIn(action.fn)) {
        if (call.type !== 'CallExpression' || !isMutationCall(call)) continue
        for (const payload of dataPayloads(call)) {
          if (!wholeInput(payload, taint)) continue
          out.push({
            ruleId: 'mass-assignment',
            type: 'Mass assignment',
            severity: 'medium',
            confidence: 'heuristic',
            file: ctx.file,
            line: payload.loc.start.line,
            column: payload.loc.start.column + 1,
            endLine: payload.loc.end.line,
            endColumn: payload.loc.end.column + 1,
            action: action.name,
            message: `Whole input object written to the database — \`${snippet(ctx.code, payload)}\``,
            why:
              'Writing the entire input object without picking fields lets the client add extra fields ' +
              '(role, isAdmin, ownerId) and escalate privileges — classic mass assignment.',
            fix: 'Write only explicit allow-listed fields (zod .pick / destructuring), not the whole object.',
          })
          break
        }
      }
    }
    return out
  },
}
