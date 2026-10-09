import { calleeName, memberChain, propertyName, stringValue, unwrap } from './ast.js';
import { callsIn } from './taint.js';
// ─── Секреты ───────────────────────────────────────────────────────────────
export const SECRET_NAME = /(secret|token|api[_-]?key|apikey|passw(or)?d|pwd|private[_-]?key|credential|authorization|bearer|access[_-]?key|signing[_-]?key|webhook[_-]?key|client[_-]?secret|salt|dsn)/i;
const NOT_SECRET_NAME = /(public|publishable|NEXT_PUBLIC|placeholder|label|title|url$|endpoint|header[_-]?name)/i;
export function isSecretName(name) {
    return !!name && SECRET_NAME.test(name) && !NOT_SECRET_NAME.test(name);
}
const PLACEHOLDER = /^(your[_-]|example|changeme|change[_-]me|placeholder|xxx|\*{3}|<.*>|todo|dummy|redacted|\.\.\.)/i;
export function shannonEntropy(s) {
    const freq = new Map();
    for (const ch of s)
        freq.set(ch, (freq.get(ch) ?? 0) + 1);
    let h = 0;
    for (const n of freq.values()) {
        const p = n / s.length;
        h -= p * Math.log2(p);
    }
    return h;
}
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const CONN_STRING_WITH_PASSWORD = /^[a-z][a-z0-9+.-]*:\/\/[^\s:/@]+:[^\s@/]+@/i;
/** Похоже ли значение на секрет (с учётом имени, к которому оно привязано) */
export function judgeSecret(value, nameHint) {
    if (value.length < 8 || PLACEHOLDER.test(value))
        return undefined;
    if (CONN_STRING_WITH_PASSWORD.test(value))
        return { confidence: 'high', reason: 'connection string with a password' };
    if (/^Bearer\s+\S{10,}$/.test(value))
        return { confidence: 'high', reason: 'Bearer token' };
    if (/\s/.test(value))
        return undefined;
    if (/^(https?:)?\/\//.test(value) || value.startsWith('/'))
        return undefined;
    const tokenLike = /^[A-Za-z0-9_\-+/=.:]+$/.test(value) && /[A-Za-z]/.test(value) && /\d/.test(value);
    const highEntropy = tokenLike && value.length >= 20 && shannonEntropy(value) >= 3.5 && !UUID.test(value);
    const named = isSecretName(nameHint);
    if (named && (highEntropy || (tokenLike && value.length >= 12))) {
        return { confidence: 'high', reason: `key-like value in "${nameHint}"` };
    }
    if (highEntropy)
        return { confidence: 'medium', reason: 'high-entropy string (looks like a key/token)' };
    if (named)
        return { confidence: 'medium', reason: `string literal in "${nameHint}"` };
    return undefined;
}
/** Mask a detected secret so the report itself does not leak it */
export function mask(value) {
    return `${value.slice(0, 4)}… (${value.length} chars)`;
}
/** process.env.SECRET (кроме NEXT_PUBLIC_*), secretName, obj.apiKey, литерал-секрет */
export function secretishExpression(expr, envInits) {
    const n = unwrap(expr);
    if (n.type === 'MemberExpression') {
        const chain = memberChain(n);
        if (chain[0] === 'process' && chain[1] === 'env') {
            const name = chain[2];
            if (name && !name.startsWith('NEXT_PUBLIC_'))
                return `process.env.${name}`;
            return undefined;
        }
        const prop = propertyName(n);
        if (isSecretName(prop))
            return chain.join('.');
        return undefined;
    }
    if (n.type === 'Identifier') {
        if (isSecretName(n.name))
            return n.name;
        const init = envInits.get(n.name);
        if (init) {
            const inner = secretishExpression(init, new Map());
            if (inner)
                return `${n.name} (= ${inner})`;
        }
        return undefined;
    }
    if (n.type === 'LogicalExpression')
        return secretishExpression(n.left, envInits) ?? secretishExpression(n.right, envInits);
    const s = stringValue(n);
    if (s && judgeSecret(s))
        return 'string literal';
    return undefined;
}
// ─── Мутации / БД ──────────────────────────────────────────────────────────
const MUTATION_METHODS = new Set([
    'create', 'createMany', 'createManyAndReturn', 'update', 'updateMany', 'upsert', 'delete', 'deleteMany',
    'insert', 'insertMany', 'insertOne', 'updateOne', 'deleteOne', 'replaceOne', 'findOneAndUpdate',
    'findOneAndDelete', 'findByIdAndUpdate', 'findByIdAndDelete', 'destroy', 'remove', 'save', 'bulkWrite',
    '$executeRaw', '$executeRawUnsafe',
]);
const READ_METHODS = new Set([
    'findUnique', 'findUniqueOrThrow', 'findFirst', 'findFirstOrThrow', 'findMany', 'findOne', 'findById', 'find',
]);
const DB_ROOT = /^(db|database|prisma|drizzle|knex|sql|pg|pool|supabase|mongo|mongoose|client|tx|trx|repo|repository|orm|kv|redis|firestore|collection|model|em|entityManager|dataSource|turso|neon|xata|payload)$/i;
const NOT_DB_ROOT = new Set([
    'cookies()', 'headers()', 'Object', 'Array', 'Map', 'Set', 'WeakMap', 'Promise', 'console', 'Math', 'JSON',
    'Reflect', 'formData', 'searchParams', 'url', 'URL', 'cache', 'params', 'router', 'window', 'document',
    'localStorage', 'sessionStorage', 'res', 'response', 'request', 'req', 'this', '?', '()', 'path', 'fs',
]);
function looksLikeDb(chain) {
    const root = chain[0];
    if (NOT_DB_ROOT.has(root))
        return false;
    if (DB_ROOT.test(root))
        return true;
    // prisma-стиль: something.model.create() — минимум два звена до метода
    return chain.length >= 3 && !chain.includes('()');
}
export function isMutationCall(call) {
    if (call.type !== 'CallExpression')
        return false;
    const callee = unwrap(call.callee);
    const name = calleeName(call);
    if (name === 'fetch' && callee.type === 'Identifier') {
        const init = call.arguments[1];
        if (init && init.type === 'ObjectExpression') {
            for (const p of init.properties) {
                if (p.type !== 'Property' || p.key.type !== 'Identifier' || p.key.name !== 'method')
                    continue;
                const m = stringValue(p.value);
                if (m && /^(post|put|patch|delete)$/i.test(m))
                    return true;
            }
        }
        return false;
    }
    if (callee.type !== 'MemberExpression' || !name || !MUTATION_METHODS.has(name))
        return false;
    return looksLikeDb(memberChain(callee));
}
export function isDbReadCall(call) {
    const n = unwrap(call);
    if (n.type !== 'CallExpression')
        return false;
    const callee = unwrap(n.callee);
    if (callee.type !== 'MemberExpression')
        return false;
    const name = calleeName(n);
    const chain = memberChain(callee);
    // drizzle: db.select().from(users) без списка колонок
    if (name === 'from' && callee.object.type === 'CallExpression' && calleeName(callee.object) === 'select') {
        return callee.object.arguments.length === 0 && looksLikeDb(memberChain(unwrap(callee.object.callee)));
    }
    if (!name || !READ_METHODS.has(name) || !looksLikeDb(chain))
        return false;
    const opts = n.arguments[0];
    if (opts && opts.type === 'ObjectExpression') {
        const restricted = opts.properties.some((p) => p.type === 'Property' && p.key.type === 'Identifier' && ['select', 'omit', 'columns', 'projection'].includes(p.key.name));
        if (restricted)
            return false;
    }
    // mongoose: .find().select('name') / .lean() — не пытаемся угадывать дальше
    return true;
}
export function mutationsIn(fn) {
    return callsIn(fn).filter(isMutationCall);
}
// ─── Авторизация / валидация ───────────────────────────────────────────────
const AUTH_CALL = /(auth|session|currentuser|getuser|requireuser|requireadmin|verifytoken|verifyjwt|verifysession|permission|authoriz|isadmin|isowner|checkaccess|getclaims|protect|ensureuser|ensureadmin|requirerole|assertrole|getviewer|validaterequest)/i;
const AUTH_WRAPPER = /(auth|protect|safe|admin|user|session|guard|permission|role|private|secure)/i;
export function isAuthCall(call) {
    const name = calleeName(call);
    if (!name)
        return false;
    if (AUTH_CALL.test(name))
        return true;
    return /^can[A-Z]/.test(name) || /^(can|hasRole|hasPermission|guard)$/.test(name);
}
export function isAuthWrapper(wrapper) {
    return !!wrapper && AUTH_WRAPPER.test(wrapper);
}
const VALIDATION_CALL = /^(parse|safeParse|parseAsync|safeParseAsync|validate\w*|assert\w*|is[A-Z]\w*|check\w*|decode|sanitize\w*|coerce|safeParseFormData|parseWithZod|v?parse)$/;
const VALIDATION_WRAPPER = /(schema|input|validat|safe|zod|valibot|yup)/i;
export function isValidationCall(call) {
    const name = calleeName(call);
    if (!name)
        return false;
    if (VALIDATION_CALL.test(name))
        return true;
    return ['Number', 'parseInt', 'parseFloat', 'BigInt', 'Boolean'].includes(name);
}
export function isValidationWrapper(wrapper) {
    return !!wrapper && VALIDATION_WRAPPER.test(wrapper);
}
