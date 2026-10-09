import { snippet, unwrap } from '../ast.js';
import { callsIn, Taint } from '../taint.js';
import { isMutationCall, isValidationCall, isValidationWrapper } from '../patterns.js';
/** Любой аргумент мутации (или его часть) берётся прямо из входа экшена */
function taintedMutationArg(call, taint) {
    for (const arg of call.arguments) {
        const a = arg.type === 'SpreadElement' ? arg.argument : arg;
        if (taint.reaches(a))
            return a;
        // db.update({ data: { ...input } }) — заглянем на уровень свойств
        const u = unwrap(a);
        if (u.type === 'ObjectExpression') {
            for (const p of u.properties) {
                if (p.type === 'SpreadElement' && taint.reaches(p.argument))
                    return p.argument;
                if (p.type === 'Property' && taint.reaches(p.value))
                    return p.value;
            }
        }
    }
    return undefined;
}
export const missingValidationRule = {
    meta: {
        id: 'missing-validation',
        title: 'Missing input validation',
        category: 'hygiene',
        description: 'A Server Action argument reaches a mutation/logic without validation (zod .parse, typeof, Number(), ' +
            'a schema wrapper). A common bug source when the action is treated as an internal function.',
    },
    check(ctx) {
        const out = [];
        for (const action of ctx.actions) {
            if (action.params === 0)
                continue;
            if (isValidationWrapper(action.wrapper))
                continue;
            const taint = new Taint(action.fn);
            // есть ли вообще валидация входа в теле
            const validated = callsIn(action.fn).some((c) => isValidationCall(c) && c.arguments.some((a) => taint.reaches(a.type === 'SpreadElement' ? a.argument : a)));
            if (validated)
                continue;
            const mutations = callsIn(action.fn).filter((c) => c.type === 'CallExpression' && isMutationCall(c));
            let hit;
            for (const m of mutations.sort((a, b) => a.range[0] - b.range[0])) {
                hit = taintedMutationArg(m, taint);
                if (hit)
                    break;
            }
            if (!hit)
                continue;
            out.push({
                ruleId: 'missing-validation',
                type: 'Missing input validation',
                severity: 'low',
                confidence: 'heuristic',
                file: ctx.file,
                line: hit.loc.start.line,
                column: hit.loc.start.column + 1,
                endLine: hit.loc.end.line,
                endColumn: hit.loc.end.column + 1,
                action: action.name,
                message: `${action.name}: input reaches a mutation without validation — \`${snippet(ctx.code, hit)}\``,
                why: 'A Server Action runs with an arbitrary request body. Without validation, arbitrary types and fields ' +
                    'reach the database — from crashes to mass assignment.',
                fix: 'Validate the input with a schema (zod/valibot .parse) or explicit typeof/Number() before use.',
            });
        }
        return out;
    },
};
