import type { TSESTree } from '@typescript-eslint/typescript-estree';
import { isFunction, propertyName } from './ast.js';
import type { FunctionNode, Node } from './types.js';
/**
 * Внутрипроцедурный taint: что в функции пришло из аргументов Server Action.
 *
 * direct  — само входное значение или его кусок (arg, arg.name, formData.get('x'))
 * derived — значение, собранное из входа (шаблонная строка, path.join, конкатенация)
 *
 * Любой «непрозрачный» вызов (Number(x), schema.parse(x), sanitize(x)) taint обрывает —
 * считаем, что там проверка. Это сознательный компромисс в сторону меньшего шума.
 */
export declare class Taint {
    readonly fn: FunctionNode;
    readonly direct: Set<string>;
    readonly derived: Set<string>;
    /** Переменные, присвоенные из чтения БД без select (для return-leak) */
    readonly dbRows: Set<string>;
    readonly params: string[];
    constructor(fn: FunctionNode);
    /** Значение — сам вход (или его часть) без преобразований */
    isDirect(expr: Node | null | undefined): boolean;
    /** Вход «доезжает» до выражения напрямую или через склейку строк / путей / объектов */
    reaches(expr: Node | null | undefined): boolean;
    /** Корневое имя входа: formData.get('x') → formData, arg.a.b → arg */
    rootName(expr: Node): string | undefined;
    /** Все корневые имена входа, достигающие выражения (для проверки guard'ов) */
    reachingRoots(expr: Node | null | undefined, out?: Set<string>): Set<string>;
    /** Все корни, достигающие выражения, защищены typeof/instanceof-проверкой */
    isGuarded(expr: Node): boolean;
    /** В функции есть typeof/instanceof-проверка этого имени: if (typeof x !== 'string') throw … */
    hasTypeGuard(name: string): boolean;
}
/** Все вызовы внутри функции (включая вложенные колбэки) */
export declare function callsIn(fn: FunctionNode): (TSESTree.CallExpression | TSESTree.NewExpression)[];
export { isFunction, propertyName };
