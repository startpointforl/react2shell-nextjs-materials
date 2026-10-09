import { stringValue, walk } from '../ast.js';
import { judgeSecret, mask } from '../patterns.js';
/** Имя, к которому привязан строковый литерал: const apiKey = '...', { token: '...' }, foo('...') */
function nameHintFor(node, parent) {
    if (!parent)
        return undefined;
    if (parent.type === 'VariableDeclarator' && parent.id.type === 'Identifier')
        return parent.id.name;
    if (parent.type === 'AssignmentExpression' && parent.left.type === 'Identifier')
        return parent.left.name;
    if (parent.type === 'Property' && parent.value === node) {
        if (parent.key.type === 'Identifier')
            return parent.key.name;
        if (parent.key.type === 'Literal')
            return String(parent.key.value);
    }
    if (parent.type === 'PropertyDefinition' && parent.key.type === 'Identifier')
        return parent.key.name;
    return undefined;
}
function analyze(action, ctx) {
    const out = [];
    walk(action.fn.body, (node, parent) => {
        const value = node.type === 'Literal' || node.type === 'TemplateLiteral' ? stringValue(node) : undefined;
        if (value === undefined)
            return;
        const hint = nameHintFor(node, parent);
        const verdict = judgeSecret(value, hint);
        if (!verdict)
            return;
        out.push({
            ruleId: 'hardcoded-secret',
            type: 'Hardcoded secret',
            severity: verdict.confidence === 'high' ? 'high' : 'medium',
            confidence: verdict.confidence,
            file: ctx.file,
            line: node.loc.start.line,
            column: node.loc.start.column + 1,
            endLine: node.loc.end.line,
            endColumn: node.loc.end.column + 1,
            action: action.name,
            cve: ['CVE-2025-55183'],
            message: `Possible hardcoded secret in the action body — ${verdict.reason} (${mask(value)})`,
            why: 'Source disclosure (CVE-2025-55183) exposes literals baked into the function source. ' +
                'A process.env value is not exposed this way; a string literal ships to the client with the source.',
            fix: 'Move the secret to an environment variable (process.env.…, not NEXT_PUBLIC_) and upgrade React.',
        });
    });
    return out;
}
export const hardcodedSecretRule = {
    meta: {
        id: 'hardcoded-secret',
        title: 'Hardcoded secret',
        category: 'cve',
        cve: ['CVE-2025-55183'],
        description: 'A string literal that looks like a key/token (high entropy or a SECRET/KEY/TOKEN name) inside a ' +
            'Server Action body. Source disclosure (55183) exposes such literals, but not process.env.',
        helpUri: 'https://react.dev/blog/2025/12/11/denial-of-service-and-source-code-exposure-in-react-server-components',
    },
    check(ctx) {
        return ctx.actions.flatMap((a) => analyze(a, ctx));
    },
};
