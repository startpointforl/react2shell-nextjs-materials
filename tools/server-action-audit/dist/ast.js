import { parse as estreeParse } from '@typescript-eslint/typescript-estree';
const SKIP_KEYS = new Set(['parent', 'loc', 'range', 'tokens', 'comments', 'typeAnnotation', 'returnType', 'typeParameters', 'typeArguments']);
export function parseFile(code, filePath) {
    return estreeParse(code, {
        filePath,
        jsx: /\.(t|j)sx$/.test(filePath) || /\.(m|c)?js$/.test(filePath),
        loc: true,
        range: true,
        comment: true,
    });
}
/** Обход в глубину; visit может вернуть false, чтобы не заходить внутрь узла */
export function walk(root, visit) {
    const stack = [[root, undefined]];
    while (stack.length) {
        const [node, parent] = stack.pop();
        if (visit(node, parent) === false)
            continue;
        const children = [];
        for (const key of Object.keys(node)) {
            if (SKIP_KEYS.has(key))
                continue;
            const value = node[key];
            if (Array.isArray(value)) {
                for (const v of value)
                    if (isNode(v))
                        children.push(v);
            }
            else if (isNode(value)) {
                children.push(value);
            }
        }
        for (let i = children.length - 1; i >= 0; i--)
            stack.push([children[i], node]);
    }
}
function isNode(v) {
    return !!v && typeof v === 'object' && typeof v.type === 'string';
}
export function buildParents(root) {
    const parents = new WeakMap();
    walk(root, (node, parent) => {
        if (parent)
            parents.set(node, parent);
    });
    return parents;
}
export function isFunction(node) {
    return (!!node &&
        (node.type === 'FunctionDeclaration' ||
            node.type === 'FunctionExpression' ||
            node.type === 'ArrowFunctionExpression'));
}
/** Ближайшая функция, внутри которой лежит узел */
export function enclosingFunction(node, parents) {
    let cur = parents.get(node);
    while (cur) {
        if (isFunction(cur))
            return cur;
        cur = parents.get(cur);
    }
    return undefined;
}
export function ancestors(node, parents, stopAt) {
    const out = [];
    let cur = parents.get(node);
    while (cur && cur !== stopAt) {
        out.push(cur);
        cur = parents.get(cur);
    }
    return out;
}
export function contains(outer, inner) {
    return outer.range[0] <= inner.range[0] && inner.range[1] <= outer.range[1];
}
/** Снимает TS-обёртки, скобки, await, ?. */
export function unwrap(node) {
    let cur = node;
    for (;;) {
        switch (cur.type) {
            case 'TSAsExpression':
            case 'TSSatisfiesExpression':
            case 'TSNonNullExpression':
            case 'TSTypeAssertion':
            case 'AwaitExpression':
            case 'ChainExpression':
                cur = cur.expression ?? cur.argument;
                continue;
            default:
                return cur;
        }
    }
}
export function propertyName(node) {
    if (!node.computed && node.property.type === 'Identifier')
        return node.property.name;
    if (node.property.type === 'Literal' && typeof node.property.value === 'string')
        return node.property.value;
    return undefined;
}
/** Имя вызываемого: foo() → foo, a.b.foo() → foo */
export function calleeName(call) {
    const callee = unwrap(call.callee);
    if (callee.type === 'Identifier')
        return callee.name;
    if (callee.type === 'MemberExpression')
        return propertyName(callee);
    return undefined;
}
/** Цепочка a.b.c() → ['a','b','c']; корень-вызов (cookies().delete) даёт ['()', 'delete'] */
export function memberChain(node) {
    const out = [];
    let cur = unwrap(node);
    for (;;) {
        if (cur.type === 'MemberExpression') {
            out.unshift(propertyName(cur) ?? '[]');
            cur = unwrap(cur.object);
        }
        else if (cur.type === 'CallExpression') {
            // db.insert(users).values(...) — проходим сквозь вызов, чтобы найти корень
            const inner = unwrap(cur.callee);
            if (inner.type === 'MemberExpression') {
                out.unshift('()');
                cur = inner;
            }
            else if (inner.type === 'Identifier') {
                out.unshift(inner.name + '()');
                return out;
            }
            else {
                out.unshift('()');
                return out;
            }
        }
        else if (cur.type === 'Identifier') {
            out.unshift(cur.name);
            return out;
        }
        else if (cur.type === 'ThisExpression') {
            out.unshift('this');
            return out;
        }
        else {
            out.unshift('?');
            return out;
        }
    }
}
export function isProcessEnv(node) {
    const n = unwrap(node);
    if (n.type !== 'MemberExpression')
        return undefined;
    const obj = unwrap(n.object);
    if (obj.type === 'MemberExpression' &&
        unwrap(obj.object).type === 'Identifier' &&
        unwrap(obj.object).name === 'process' &&
        propertyName(obj) === 'env') {
        return { name: propertyName(n) };
    }
    return undefined;
}
export function stringValue(node) {
    if (node.type === 'Literal' && typeof node.value === 'string')
        return node.value;
    if (node.type === 'TemplateLiteral' && node.expressions.length === 0)
        return node.quasis[0].value.cooked ?? undefined;
    return undefined;
}
/** Все имена, которые объявляет паттерн (параметр, деструктуризация) */
export function patternNames(pattern, out = []) {
    switch (pattern.type) {
        case 'Identifier':
            out.push(pattern.name);
            break;
        case 'ObjectPattern':
            for (const p of pattern.properties) {
                if (p.type === 'RestElement')
                    patternNames(p.argument, out);
                else
                    patternNames(p.value, out);
            }
            break;
        case 'ArrayPattern':
            for (const el of pattern.elements)
                if (el)
                    patternNames(el, out);
            break;
        case 'AssignmentPattern':
            patternNames(pattern.left, out);
            break;
        case 'RestElement':
            patternNames(pattern.argument, out);
            break;
        case 'TSParameterProperty':
            patternNames(pattern.parameter, out);
            break;
    }
    return out;
}
/** Узлы return, принадлежащие именно этой функции (не вложенным колбэкам) */
export function ownReturns(fn, parents) {
    if (fn.body.type !== 'BlockStatement')
        return [fn.body];
    const out = [];
    walk(fn.body, (node) => {
        if (node !== fn && isFunction(node))
            return false;
        if (node.type === 'ReturnStatement' && node.argument)
            out.push(node.argument);
    });
    void parents;
    return out;
}
export function snippet(code, node, max = 60) {
    const text = code.slice(node.range[0], node.range[1]).replace(/\s+/g, ' ');
    return text.length > max ? text.slice(0, max - 1) + '…' : text;
}
