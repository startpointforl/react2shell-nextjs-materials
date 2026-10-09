import type { TSESTree } from '@typescript-eslint/typescript-estree'
import { calleeName, unwrap, walk } from '../ast.js'
import type { Finding, Node, Rule } from '../types.js'
import { Taint } from '../taint.js'
import { secretishExpression } from '../patterns.js'
import { findActions } from '../actions.js'

/**
 * action.bind(null, secret) — bound-аргумент сериализуется и уходит на клиент.
 * Плюс: inline 'use server', захватывающая секрет из замыкания (та же механика).
 */
function collectEnvInits(ast: TSESTree.Program): Map<string, Node> {
  const envInits = new Map<string, Node>()
  walk(ast, (node) => {
    if (node.type === 'VariableDeclarator' && node.id.type === 'Identifier' && node.init) {
      envInits.set(node.id.name, node.init)
    }
  })
  return envInits
}

export const boundSecretRule: Rule = {
  meta: {
    id: 'bound-secret',
    title: 'Secret via .bind()',
    category: 'cve',
    cve: ['CVE-2025-55183'],
    description:
      'action.bind(null, secret) serializes the bound argument and sends it to the client (encrypted with ' +
      'the build key, but off the server). The same holds for a secret captured by an inline action closure.',
  },
  check(ctx) {
    const out: Finding[] = []
    const envInits = collectEnvInits(ctx.ast)
    const { actions } = findActions(ctx.ast, ctx.file)
    const actionNames = new Set(actions.map((a) => a.name))

    // 1) X.bind(null, secret) — идиома привязки Server Action (первый арг = this = null)
    walk(ctx.ast, (node) => {
      if (node.type !== 'CallExpression') return
      const callee = unwrap(node.callee)
      if (callee.type !== 'MemberExpression' || calleeName(node) !== 'bind') return
      const target = unwrap(callee.object)
      const targetName = target.type === 'Identifier' ? target.name : undefined
      // bind-this должен быть null/undefined — иначе это обычный .bind(), не экшен
      const thisArg = node.arguments[0] ? unwrap(node.arguments[0] as Node) : undefined
      const isActionBind =
        !!thisArg &&
        ((thisArg.type === 'Literal' && thisArg.value === null) ||
          (thisArg.type === 'Identifier' && thisArg.name === 'undefined'))
      // уверенность выше, если цель — известный в проекте экшен
      if (!isActionBind && !(targetName && actionNames.has(targetName))) return
      const boundArgs = node.arguments.slice(1)
      boundArgs.forEach((arg, i) => {
        const secret = secretishExpression(arg as Node, envInits)
        if (!secret) return
        out.push({
          ruleId: 'bound-secret',
          type: 'Secret via .bind()',
          severity: 'medium',
          confidence: 'medium',
          file: ctx.file,
          line: arg.loc.start.line,
          column: arg.loc.start.column + 1,
          endLine: arg.loc.end.line,
          endColumn: arg.loc.end.column + 1,
          action: targetName,
          cve: ['CVE-2025-55183'],
          message: `Secret passed to .bind() as bound arg #${i + 1} — ${secret}`,
          why:
            'Bound arguments of a Server Action are serialized and sent to the client. They are encrypted with ' +
            'the build key, but they leave the server — not a place for secrets. A leaked build key exposes them.',
          fix: 'Do not pass secrets via .bind(). Read them from process.env inside the action instead.',
        })
      })
    })

    // 2) inline 'use server' захватывает секрет из внешней области
    for (const action of actions) {
      if (action.kind !== 'inline') continue
      const taint = new Taint(action.fn)
      const localNames = new Set<string>(taint.params)
      walk(action.fn.body, (node) => {
        if (node.type === 'VariableDeclarator' && node.id.type === 'Identifier') localNames.add(node.id.name)
      })
      const reported = new Set<string>()
      walk(action.fn.body, (node) => {
        if (node.type !== 'Identifier') return
        if (localNames.has(node.name) || reported.has(node.name)) return
        // интересуют только внешние переменные, объявленные в этом модуле
        if (!envInits.has(node.name)) return
        const secret = secretishExpression(node, envInits)
        if (secret) {
          reported.add(node.name)
          out.push({
            ruleId: 'bound-secret',
            type: 'Secret via .bind()',
            severity: 'medium',
            confidence: 'heuristic',
            file: ctx.file,
            line: node.loc.start.line,
            column: node.loc.start.column + 1,
            endLine: node.loc.end.line,
            endColumn: node.loc.end.column + 1,
            action: action.name,
            cve: ['CVE-2025-55183'],
            message: `Inline action closes over a secret-like value — ${secret}`,
            why:
              'Variables captured by an inline action are serialized as bound arguments and sent to the client — ' +
              'the same mechanism as .bind(). Secrets do not belong there.',
            fix: 'Read the secret from process.env inside the action instead of capturing it from the outer scope.',
          })
        }
      })
    }

    return out
  },
}
