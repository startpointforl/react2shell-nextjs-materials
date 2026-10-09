import { calleeName, isFunction, memberChain, patternNames, propertyName, unwrap, walk } from './ast.js';
/** Методы, которые достают значение из входа «как есть»: formData.get('x') */
const ACCESSORS = new Set(['get', 'getAll', 'at', 'values', 'entries', 'valueOf']);
const DB_READ_METHOD = /^(findUnique|findUniqueOrThrow|findFirst|findFirstOrThrow|findMany|findOne|findById|find)$/;
/** Грубая проверка «это чтение из БД без ограничения полей» — только для таргетинга dbRows */
function isDbRead(expr) {
    const n = unwrap(expr);
    if (n.type !== 'CallExpression')
        return false;
    const callee = unwrap(n.callee);
    if (callee.type !== 'MemberExpression' || callee.computed || callee.property.type !== 'Identifier')
        return false;
    if (!DB_READ_METHOD.test(callee.property.name))
        return false;
    const opts = n.arguments[0];
    if (opts && opts.type === 'ObjectExpression') {
        const restricted = opts.properties.some((p) => p.type === 'Property' && p.key.type === 'Identifier' && ['select', 'omit', 'columns', 'projection'].includes(p.key.name));
        if (restricted)
            return false;
    }
    return true;
}
/** Вызовы, через которые «грязное» значение протекает в строку/путь без проверки */
const PASSTHROUGH_CALLS = new Set([
    'String', 'join', 'resolve', 'normalize', 'concat', 'trim', 'trimStart', 'trimEnd',
    'toLowerCase', 'toUpperCase', 'slice', 'substring', 'toString',
    'encodeURI', 'encodeURIComponent', 'decodeURI', 'decodeURIComponent', 'fromEntries', 'assign', 'stringify',
]);
/**
 * Внутрипроцедурный taint: что в функции пришло из аргументов Server Action.
 *
 * direct  — само входное значение или его кусок (arg, arg.name, formData.get('x'))
 * derived — значение, собранное из входа (шаблонная строка, path.join, конкатенация)
 *
 * Любой «непрозрачный» вызов (Number(x), schema.parse(x), sanitize(x)) taint обрывает —
 * считаем, что там проверка. Это сознательный компромисс в сторону меньшего шума.
 */
export class Taint {
    fn;
    direct = new Set();
    derived = new Set();
    /** Переменные, присвоенные из чтения БД без select (для return-leak) */
    dbRows = new Set();
    params;
    constructor(fn) {
        this.fn = fn;
        this.params = fn.params.flatMap((p) => patternNames(p));
        for (const name of this.params)
            this.direct.add(name);
        const declarators = [];
        walk(fn.body, (node) => {
            if (node.type === 'VariableDeclarator' && node.init) {
                declarators.push({ id: node.id, init: node.init });
                if (node.id.type === 'Identifier' && isDbRead(node.init))
                    this.dbRows.add(node.id.name);
            }
            if (node.type === 'AssignmentExpression' && node.operator === '=' && node.left.type === 'Identifier') {
                declarators.push({ id: node.left, init: node.right });
                if (isDbRead(node.right))
                    this.dbRows.add(node.left.name);
            }
        });
        // до неподвижной точки: const a = arg; const b = a.x; const s = `${b}`
        for (let changed = true; changed;) {
            changed = false;
            for (const { id, init } of declarators) {
                const kind = this.isDirect(init) ? 'direct' : this.reaches(init) ? 'derived' : undefined;
                if (!kind)
                    continue;
                for (const name of patternNames(id)) {
                    if (this.direct.has(name) || (kind === 'derived' && this.derived.has(name)))
                        continue;
                    (kind === 'direct' ? this.direct : this.derived).add(name);
                    if (kind === 'direct')
                        this.derived.delete(name);
                    changed = true;
                }
            }
        }
    }
    /** Значение — сам вход (или его часть) без преобразований */
    isDirect(expr) {
        if (!expr)
            return false;
        const n = unwrap(expr);
        switch (n.type) {
            case 'Identifier':
                return this.direct.has(n.name);
            case 'MemberExpression':
                return this.isDirect(n.object);
            case 'CallExpression': {
                const callee = unwrap(n.callee);
                const name = calleeName(n);
                if (callee.type === 'MemberExpression' && name && ACCESSORS.has(name))
                    return this.isDirect(callee.object);
                if (name === 'fromEntries' && memberChain(callee)[0] === 'Object')
                    return this.isDirect(n.arguments[0]);
                return false;
            }
            case 'LogicalExpression':
                return this.isDirect(n.left) || this.isDirect(n.right);
            case 'ConditionalExpression':
                return this.isDirect(n.consequent) || this.isDirect(n.alternate);
            default:
                return false;
        }
    }
    /** Вход «доезжает» до выражения напрямую или через склейку строк / путей / объектов */
    reaches(expr) {
        if (!expr)
            return false;
        if (this.isDirect(expr))
            return true;
        const n = unwrap(expr);
        switch (n.type) {
            case 'Identifier':
                return this.derived.has(n.name);
            case 'MemberExpression':
                return this.reaches(n.object);
            case 'TemplateLiteral':
                return n.expressions.some((e) => this.reaches(e));
            case 'BinaryExpression':
                return n.operator === '+' && (this.reaches(n.left) || this.reaches(n.right));
            case 'LogicalExpression':
                return this.reaches(n.left) || this.reaches(n.right);
            case 'ConditionalExpression':
                return this.reaches(n.consequent) || this.reaches(n.alternate);
            case 'ArrayExpression':
                return n.elements.some((e) => !!e && this.reaches(e.type === 'SpreadElement' ? e.argument : e));
            case 'ObjectExpression':
                return n.properties.some((p) => p.type === 'SpreadElement' ? this.reaches(p.argument) : this.reaches(p.value));
            case 'CallExpression':
            case 'NewExpression': {
                const name = calleeName(n);
                if (n.type === 'NewExpression' && name === 'URL')
                    return this.reaches(n.arguments[0]);
                if (!name || !PASSTHROUGH_CALLS.has(name))
                    return false;
                const callee = unwrap(n.callee);
                if (callee.type === 'MemberExpression' && this.reaches(callee.object))
                    return true;
                return n.arguments.some((a) => this.reaches(a.type === 'SpreadElement' ? a.argument : a));
            }
            default:
                return false;
        }
    }
    /** Корневое имя входа: formData.get('x') → formData, arg.a.b → arg */
    rootName(expr) {
        const n = unwrap(expr);
        if (n.type === 'Identifier')
            return n.name;
        if (n.type === 'MemberExpression')
            return this.rootName(n.object);
        if (n.type === 'CallExpression' && unwrap(n.callee).type === 'MemberExpression') {
            return this.rootName(unwrap(n.callee).object);
        }
        return undefined;
    }
    /** Все корневые имена входа, достигающие выражения (для проверки guard'ов) */
    reachingRoots(expr, out = new Set()) {
        if (!expr)
            return out;
        const n = unwrap(expr);
        switch (n.type) {
            case 'Identifier':
                if (this.direct.has(n.name) || this.derived.has(n.name))
                    out.add(n.name);
                break;
            case 'MemberExpression':
                this.reachingRoots(n.object, out);
                break;
            case 'TemplateLiteral':
                n.expressions.forEach((e) => this.reachingRoots(e, out));
                break;
            case 'BinaryExpression':
                this.reachingRoots(n.left, out);
                this.reachingRoots(n.right, out);
                break;
            case 'CallExpression':
            case 'NewExpression': {
                const callee = unwrap(n.callee);
                if (callee.type === 'MemberExpression')
                    this.reachingRoots(callee.object, out);
                n.arguments.forEach((a) => this.reachingRoots(a.type === 'SpreadElement' ? a.argument : a, out));
                break;
            }
        }
        return out;
    }
    /** Все корни, достигающие выражения, защищены typeof/instanceof-проверкой */
    isGuarded(expr) {
        const roots = this.reachingRoots(expr);
        if (roots.size === 0)
            return false;
        for (const r of roots)
            if (!this.hasTypeGuard(r))
                return false;
        return true;
    }
    /** В функции есть typeof/instanceof-проверка этого имени: if (typeof x !== 'string') throw … */
    hasTypeGuard(name) {
        let found = false;
        walk(this.fn.body, (node) => {
            if (found)
                return false;
            if (node.type === 'UnaryExpression' && node.operator === 'typeof') {
                const arg = unwrap(node.argument);
                if (arg.type === 'Identifier' && arg.name === name)
                    found = true;
                if (arg.type === 'MemberExpression' && this.rootName(arg) === name)
                    found = true;
            }
            if (node.type === 'BinaryExpression' && node.operator === 'instanceof') {
                const left = unwrap(node.left);
                if (this.rootName(left) === name)
                    found = true;
            }
        });
        return found;
    }
}
/** Все вызовы внутри функции (включая вложенные колбэки) */
export function callsIn(fn) {
    const out = [];
    walk(fn.body, (node) => {
        if (node.type === 'CallExpression' || node.type === 'NewExpression')
            out.push(node);
    });
    return out;
}
export { isFunction, propertyName };
