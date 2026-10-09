import type { TSESTree } from '@typescript-eslint/typescript-estree';
import type { FunctionNode, Node } from './types.js';
export declare function parseFile(code: string, filePath: string): TSESTree.Program;
/** Обход в глубину; visit может вернуть false, чтобы не заходить внутрь узла */
export declare function walk(root: Node, visit: (node: Node, parent: Node | undefined) => void | false): void;
export declare function buildParents(root: Node): WeakMap<Node, Node>;
export declare function isFunction(node: Node | undefined): node is FunctionNode;
/** Ближайшая функция, внутри которой лежит узел */
export declare function enclosingFunction(node: Node, parents: WeakMap<Node, Node>): FunctionNode | undefined;
export declare function ancestors(node: Node, parents: WeakMap<Node, Node>, stopAt?: Node): Node[];
export declare function contains(outer: Node, inner: Node): boolean;
/** Снимает TS-обёртки, скобки, await, ?. */
export declare function unwrap(node: Node): Node;
export declare function propertyName(node: TSESTree.MemberExpression): string | undefined;
/** Имя вызываемого: foo() → foo, a.b.foo() → foo */
export declare function calleeName(call: TSESTree.CallExpression | TSESTree.NewExpression): string | undefined;
/** Цепочка a.b.c() → ['a','b','c']; корень-вызов (cookies().delete) даёт ['()', 'delete'] */
export declare function memberChain(node: Node): string[];
export declare function isProcessEnv(node: Node): {
    name?: string;
} | undefined;
export declare function stringValue(node: Node): string | undefined;
/** Все имена, которые объявляет паттерн (параметр, деструктуризация) */
export declare function patternNames(pattern: Node, out?: string[]): string[];
/** Узлы return, принадлежащие именно этой функции (не вложенным колбэкам) */
export declare function ownReturns(fn: FunctionNode, parents: WeakMap<Node, Node>): Node[];
export declare function snippet(code: string, node: Node, max?: number): string;
