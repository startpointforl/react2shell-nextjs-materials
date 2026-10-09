/**
 * Подавление находок построчными комментариями:
 *   // server-action-audit-ignore <rule?>            — вся следующая непустая строка
 *   // server-action-audit-ignore-next-line <rule?>  — то же явно
 *   code // server-action-audit-ignore-line <rule?>  — текущая строка
 * Без <rule> гасятся все правила на строке.
 */
const RE = /server-action-audit-ignore(-next-line|-line)?\b[ \t]*(.*)$/;
export function collectSuppressions(code) {
    const lines = code.split(/\r?\n/);
    const out = [];
    lines.forEach((text, i) => {
        const commentIdx = text.indexOf('//');
        if (commentIdx === -1)
            return;
        const m = RE.exec(text.slice(commentIdx));
        if (!m)
            return;
        const kind = m[1];
        const rules = m[2].trim() ? new Set(m[2].trim().split(/[\s,]+/)) : null;
        const isInline = kind === '-line' || text.slice(0, commentIdx).trim() !== '';
        let target = isInline ? i + 1 : i + 2; // 1-based; next-line → следующая строка
        // next-line: пропускаем пустые строки до реального кода
        if (!isInline) {
            while (target - 1 < lines.length && lines[target - 1]?.trim() === '')
                target++;
        }
        out.push({ line: target, rules });
    });
    return out;
}
export function filterSuppressed(findings, suppressions) {
    if (suppressions.length === 0)
        return { kept: findings, suppressed: 0 };
    const kept = [];
    let suppressed = 0;
    for (const f of findings) {
        const hit = suppressions.some((s) => s.line === f.line && (s.rules === null || s.rules.has(f.ruleId)));
        if (hit)
            suppressed++;
        else
            kept.push(f);
    }
    return { kept, suppressed };
}
