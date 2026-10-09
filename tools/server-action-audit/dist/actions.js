import { calleeName, isFunction, unwrap, walk } from './ast.js';
export function hasDirective(body, directive) {
    for (const stmt of body) {
        if (stmt.type !== 'ExpressionStatement')
            return false;
        if (stmt.directive === directive)
            return true;
        if (stmt.expression.type === 'Literal' && stmt.expression.value === directive)
            return true;
        if (stmt.expression.type !== 'Literal')
            return false;
    }
    return false;
}
function fnHasDirective(fn) {
    return fn.body.type === 'BlockStatement' && hasDirective(fn.body.body, 'use server');
}
/** async () => ... | function () {} | wrapper(async () => ...) */
function resolveFunction(expr, locals) {
    if (!expr)
        return undefined;
    const n = unwrap(expr);
    if (isFunction(n))
        return { fn: n };
    if (n.type === 'Identifier')
        return locals.get(n.name);
    if (n.type === 'CallExpression') {
        // export const x = withAuth(async () => {...})  /  actionClient.schema(s).action(async () => {...})
        const fnArg = [...n.arguments].reverse().find((a) => isFunction(unwrap(a)));
        if (fnArg)
            return { fn: unwrap(fnArg), wrapper: wrapperName(n) };
    }
    return undefined;
}
function wrapperName(call) {
    const parts = [];
    let cur = call;
    while (cur.type === 'CallExpression') {
        const callee = unwrap(cur.callee);
        if (callee.type === 'Identifier') {
            parts.unshift(callee.name);
            break;
        }
        if (callee.type === 'MemberExpression') {
            parts.unshift(calleeName(cur) ?? '?');
            cur = unwrap(callee.object);
            if (cur.type === 'Identifier') {
                parts.unshift(cur.name);
                break;
            }
            continue;
        }
        break;
    }
    return parts.join('.');
}
function loc(fn, nameNode) {
    const at = nameNode ?? fn;
    return { line: at.loc.start.line, column: at.loc.start.column };
}
export function findActions(ast, file) {
    const moduleDirective = hasDirective(ast.body, 'use server');
    const actions = [];
    const seen = new Set();
    const push = (name, r, kind, nameNode) => {
        if (seen.has(r.fn))
            return;
        seen.add(r.fn);
        actions.push({ name, file, kind, params: r.fn.params.length, fn: r.fn, wrapper: r.wrapper, ...loc(r.fn, nameNode) });
    };
    if (moduleDirective) {
        const locals = new Map();
        for (const stmt of ast.body) {
            const decl = stmt.type === 'ExportNamedDeclaration' ? stmt.declaration : stmt;
            if (!decl)
                continue;
            if (decl.type === 'FunctionDeclaration' && decl.id)
                locals.set(decl.id.name, { fn: decl });
            if (decl.type === 'VariableDeclaration') {
                for (const d of decl.declarations) {
                    const r = d.id.type === 'Identifier' ? resolveFunction(d.init, locals) : undefined;
                    if (r && d.id.type === 'Identifier')
                        locals.set(d.id.name, r);
                }
            }
        }
        for (const stmt of ast.body) {
            if (stmt.type === 'ExportNamedDeclaration') {
                const decl = stmt.declaration;
                if (decl?.type === 'FunctionDeclaration' && decl.id)
                    push(decl.id.name, { fn: decl }, 'module', decl.id);
                if (decl?.type === 'VariableDeclaration') {
                    for (const d of decl.declarations) {
                        if (d.id.type !== 'Identifier')
                            continue;
                        const r = resolveFunction(d.init, locals);
                        if (r)
                            push(d.id.name, r, 'module', d.id);
                    }
                }
                if (!stmt.source) {
                    for (const spec of stmt.specifiers) {
                        if (spec.type !== 'ExportSpecifier' || spec.local.type !== 'Identifier')
                            continue;
                        const r = locals.get(spec.local.name);
                        const exported = spec.exported.type === 'Identifier' ? spec.exported.name : String(spec.exported.value);
                        if (r)
                            push(exported, r, 'module', spec);
                    }
                }
            }
            if (stmt.type === 'ExportDefaultDeclaration') {
                const r = resolveFunction(stmt.declaration, locals);
                if (r)
                    push('default', r, 'module', stmt);
            }
        }
    }
    // inline: async function x() { 'use server'; ... } в любом месте файла
    walk(ast, (node, parent) => {
        if (!isFunction(node) || !fnHasDirective(node))
            return;
        let name = 'inline action';
        let nameNode;
        if (node.type !== 'ArrowFunctionExpression' && node.id) {
            name = node.id.name;
            nameNode = node.id;
        }
        else if (parent?.type === 'VariableDeclarator' && parent.id.type === 'Identifier') {
            name = parent.id.name;
            nameNode = parent.id;
        }
        else if (parent?.type === 'JSXExpressionContainer') {
            name = 'inline action (JSX)';
        }
        push(name, { fn: node }, 'inline', nameNode);
    });
    return { moduleDirective, actions };
}
