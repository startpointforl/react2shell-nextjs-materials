import type { TSESTree } from '@typescript-eslint/typescript-estree'
import { ownReturns, snippet, unwrap, walk } from '../ast.js'
import type { Finding, FileContext, Rule, ServerAction } from '../types.js'
import { Taint } from '../taint.js'

const TYPE = 'Source disclosure'
const WHY =
  'Matches the CVE-2025-55183 exploit condition: passing a server-function reference instead of a ' +
  'string can leak the function source in the response (only source, not process.env).'
const FIX = 'Upgrade React and validate the argument type before use (typeof / zod).'

/** Выражение приводит значение к строке: String(x), `${x}`, x+'', x.toString() */
function stringifies(node: TSESTree.Node, taint: Taint): TSESTree.Node | undefined {
  const n = unwrap(node)
  if (n.type === 'TemplateLiteral' && n.expressions.some((e) => taint.reaches(e))) return n
  if (n.type === 'BinaryExpression' && n.operator === '+') {
    const l = unwrap(n.left)
    const r = unwrap(n.right)
    const lStr = l.type === 'Literal' && typeof l.value === 'string'
    const rStr = r.type === 'Literal' && typeof r.value === 'string'
    if ((lStr && taint.reaches(r)) || (rStr && taint.reaches(l))) return n
  }
  if (n.type === 'CallExpression') {
    const callee = unwrap(n.callee)
    if (callee.type === 'Identifier' && callee.name === 'String' && n.arguments.some((a) => taint.reaches(a))) return n
    if (callee.type === 'MemberExpression') {
      const prop = !callee.computed && callee.property.type === 'Identifier' ? callee.property.name : undefined
      if (prop === 'toString' && taint.reaches(callee.object)) return n
      if (prop === 'concat' && (taint.reaches(callee.object) || n.arguments.some((a) => taint.reaches(a)))) return n
      if (prop === 'join' && taint.reaches(callee.object)) return n
    }
  }
  return undefined
}

function analyze(action: ServerAction, ctx: FileContext): Finding | undefined {
  const taint = new Taint(action.fn)
  if (taint.params.length === 0) return undefined

  const stringifyNodes: TSESTree.Node[] = []
  walk(action.fn.body, (node) => {
    const hit = stringifies(node, taint)
    // если тип входа проверен (typeof/instanceof) до использования — не эксплуатируемо
    if (hit && !taint.isGuarded(hit) && !stringifyNodes.some((s) => s.range[0] === hit.range[0])) {
      stringifyNodes.push(hit)
    }
  })
  if (stringifyNodes.length === 0) return undefined

  // Результат возвращается клиенту? → high. Иначе medium.
  const returns = ownReturns(action.fn, ctx.parents)
  const returned = stringifyNodes.some((s) => returns.some((r) => within(s, r, taint)))
  const first = stringifyNodes[0]

  return {
    ruleId: 'stringify-arg',
    type: TYPE,
    severity: returned ? 'high' : 'medium',
    confidence: returned ? 'high' : 'medium',
    file: ctx.file,
    line: first.loc.start.line,
    column: first.loc.start.column + 1,
    endLine: first.loc.end.line,
    endColumn: first.loc.end.column + 1,
    action: action.name,
    cve: ['CVE-2025-55183'],
    message: returned
      ? `Argument is stringified and returned to the client — \`${snippet(ctx.code, first)}\``
      : `Argument is stringified — \`${snippet(ctx.code, first)}\``,
    why: WHY,
    fix: FIX,
  }
}

/** Узел-строка лежит внутри return-выражения, либо это та же переменная, что возвращается */
function within(strNode: TSESTree.Node, returnArg: TSESTree.Node, taint: Taint): boolean {
  if (returnArg.range[0] <= strNode.range[0] && strNode.range[1] <= returnArg.range[1]) return true
  const r = unwrap(returnArg)
  if (r.type === 'Identifier') return taint.derived.has(r.name) || taint.direct.has(r.name)
  if (r.type === 'ObjectExpression') {
    return r.properties.some(
      (p) => p.type === 'Property' && taint.reaches(p.value as TSESTree.Node),
    )
  }
  return false
}

export const stringifyArgRule: Rule = {
  meta: {
    id: 'stringify-arg',
    title: TYPE,
    category: 'cve',
    cve: ['CVE-2025-55183'],
    description:
      'A Server Action that stringifies its argument (String(arg), a template literal, concatenation) ' +
      'matches the CVE-2025-55183 exploit condition — source-code disclosure of the server function.',
    helpUri: 'https://react.dev/blog/2025/12/11/denial-of-service-and-source-code-exposure-in-react-server-components',
  },
  check(ctx) {
    const out: Finding[] = []
    for (const action of ctx.actions) {
      const f = analyze(action, ctx)
      if (f) out.push(f)
    }
    return out
  },
}
