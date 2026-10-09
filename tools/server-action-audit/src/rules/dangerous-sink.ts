import type { TSESTree } from '@typescript-eslint/typescript-estree'
import { calleeName, memberChain, snippet, unwrap } from '../ast.js'
import type { Finding, Rule } from '../types.js'
import { callsIn, Taint } from '../taint.js'

interface Sink {
  match(call: TSESTree.CallExpression | TSESTree.NewExpression): number[] | undefined
  /** Short human-readable type shown in the report */
  type: string
  severity: 'high' | 'medium'
  why: string
  fix: string
}

const idName = (c: TSESTree.CallExpression | TSESTree.NewExpression) =>
  unwrap(c.callee).type === 'Identifier' ? (unwrap(c.callee) as TSESTree.Identifier).name : undefined

const SINKS: Sink[] = [
  {
    type: 'Code execution',
    severity: 'high',
    match: (c) => (['eval', 'Function'].includes(idName(c) ?? '') ? c.arguments.map((_, i) => i) : undefined),
    why: 'Action input reaches eval / new Function — arbitrary code execution on the server.',
    fix: 'Never execute input as code. Remove eval / Function.',
  },
  {
    type: 'Command injection',
    severity: 'high',
    match: (c) => {
      const chain = memberChain(unwrap(c.callee))
      const name = calleeName(c)
      if (/^(child_process|cp)$/.test(chain[0] ?? '') || ['exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync'].includes(name ?? '')) {
        return [0, 1]
      }
      return undefined
    },
    why: 'Action input reaches a process launch (child_process.exec/spawn) — command injection.',
    fix: 'Do not build commands from user input. Use execFile with fixed arguments and no shell.',
  },
  {
    type: 'SSRF',
    severity: 'medium',
    match: (c) => (c.type === 'CallExpression' && idName(c) === 'fetch' ? [0] : c.type === 'NewExpression' && idName(c) === 'URL' ? [0] : undefined),
    why: 'A fetch URL is built from action input — server-side request forgery to internal hosts.',
    fix: 'Validate and allow-list the host before the request.',
  },
  {
    type: 'Open redirect',
    severity: 'medium',
    match: (c) => (['redirect', 'permanentRedirect'].includes(calleeName(c) ?? '') ? [0] : undefined),
    why: 'The redirect target comes from action input — open redirect to an arbitrary site.',
    fix: 'Allow only relative paths or an allow-listed host.',
  },
  {
    type: 'Path traversal',
    severity: 'medium',
    match: (c) => {
      const chain = memberChain(unwrap(c.callee))
      const name = calleeName(c) ?? ''
      const fsLike = /^(fs|fsp|fileSystem)$/.test(chain[0] ?? '') || chain.includes('promises')
      const fsMethod = /^(readFile|readFileSync|writeFile|writeFileSync|unlink|unlinkSync|rm|rmSync|readdir|readdirSync|createReadStream|createWriteStream|open|appendFile)$/.test(name)
      return fsLike && fsMethod ? [0] : undefined
    },
    why: 'A file path is built from action input — escaping the intended directory (../../etc/passwd).',
    fix: 'Normalize the path and verify it stays inside an allowed directory (path.resolve + startsWith).',
  },
  {
    type: 'SQL injection',
    severity: 'high',
    match: (c) => {
      const name = calleeName(c) ?? ''
      if (/^(\$queryRawUnsafe|\$executeRawUnsafe|unsafe|raw)$/.test(name)) return c.arguments.map((_, i) => i)
      return undefined
    },
    why: 'Action input reaches raw SQL (queryRawUnsafe / sql.raw) — SQL injection.',
    fix: 'Use parameterized queries ($queryRaw with placeholders), not the Unsafe variants.',
  },
]

export const dangerousSinkRule: Rule = {
  meta: {
    id: 'dangerous-sink',
    title: 'Unsafe sink',
    category: 'hygiene',
    description:
      'Action input reaches, without validation, eval/exec (code/command execution), fetch/URL (SSRF), ' +
      'redirect (open redirect), fs.* (path traversal) or raw SQL (injection).',
  },
  check(ctx) {
    const out: Finding[] = []
    for (const action of ctx.actions) {
      const taint = new Taint(action.fn)
      if (taint.params.length === 0) continue
      for (const call of callsIn(action.fn)) {
        for (const sink of SINKS) {
          const indices = sink.match(call)
          if (!indices) continue
          const tainted = indices.some((i) => {
            const arg = call.arguments[i]
            return arg && taint.reaches(arg.type === 'SpreadElement' ? arg.argument : arg)
          })
          if (!tainted) continue
          out.push({
            ruleId: 'dangerous-sink',
            type: sink.type,
            severity: sink.severity,
            confidence: sink.severity === 'high' ? 'high' : 'medium',
            file: ctx.file,
            line: call.loc.start.line,
            column: call.loc.start.column + 1,
            endLine: call.loc.end.line,
            endColumn: call.loc.end.column + 1,
            action: action.name,
            message: `Untrusted input reaches \`${snippet(ctx.code, call)}\``,
            why: sink.why,
            fix: sink.fix,
          })
          break
        }
      }
    }
    return out
  },
}
