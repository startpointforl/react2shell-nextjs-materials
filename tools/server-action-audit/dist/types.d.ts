import type { TSESTree } from '@typescript-eslint/typescript-estree';
export type Node = TSESTree.Node;
export type FunctionNode = TSESTree.FunctionDeclaration | TSESTree.FunctionExpression | TSESTree.ArrowFunctionExpression;
export type Severity = 'high' | 'medium' | 'low';
/**
 * high      — паттерн почти наверняка тот, о котором речь (но это всё ещё не доказательство дыры)
 * medium    — паттерн найден, но мы не видим всей картины (поток данных, контекст)
 * heuristic — догадка по именам и форме кода; ложные срабатывания ожидаемы
 */
export type Confidence = 'high' | 'medium' | 'heuristic';
/** cve — привязано к CVE React2Shell; hygiene — общая гигиена Server Actions */
export type Category = 'cve' | 'hygiene';
export interface RuleMeta {
    id: string;
    title: string;
    category: Category;
    cve?: string[];
    /** Короткое «почему это риск» для README */
    description: string;
    helpUri?: string;
}
export interface Finding {
    ruleId: string;
    /** Short human-readable type, e.g. "Source disclosure", "Command injection" */
    type: string;
    severity: Severity;
    confidence: Confidence;
    file: string;
    line: number;
    column: number;
    endLine: number;
    endColumn: number;
    /** Name of the Server Action the finding sits in (or around) */
    action?: string;
    /** One concise line shown in the text report */
    message: string;
    /** Short rationale — kept in JSON, not printed in the text report */
    why: string;
    /** Short remediation hint — kept in JSON, not printed in the text report */
    fix: string;
    cve?: string[];
}
export interface ServerAction {
    name: string;
    file: string;
    line: number;
    column: number;
    /** module — файл с 'use server' сверху; inline — директива внутри функции */
    kind: 'module' | 'inline';
    params: number;
    fn: FunctionNode;
    /** export const x = wrapper(async () => ...) — имя обёртки (next-safe-action, withAuth…) */
    wrapper?: string;
}
export interface FileContext {
    /** Путь относительно корня сканирования, через / */
    file: string;
    absPath: string;
    code: string;
    ast: TSESTree.Program;
    parents: WeakMap<Node, Node>;
    moduleDirective: boolean;
    actions: ServerAction[];
}
export interface ProjectContext {
    root: string;
    /** Имена всех экспортируемых Server Actions в проекте (для правила про .bind) */
    actionNames: Set<string>;
}
export interface Rule {
    meta: RuleMeta;
    check(ctx: FileContext, project: ProjectContext): Finding[];
}
export interface ActionSummary {
    name: string;
    file: string;
    line: number;
    kind: 'module' | 'inline';
    params: number;
    wrapper?: string;
    mutates: boolean;
    authCheck: boolean;
}
export interface ScanResult {
    root: string;
    filesScanned: number;
    filesWithActions: number;
    findings: Finding[];
    actions: ActionSummary[];
    parseErrors: {
        file: string;
        message: string;
    }[];
    suppressed: number;
}
