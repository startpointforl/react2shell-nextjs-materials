import type { TSESTree } from '@typescript-eslint/typescript-estree';
import type { FunctionNode, Node } from './types.js';
export declare const SECRET_NAME: RegExp;
export declare function isSecretName(name: string | undefined): boolean;
export declare function shannonEntropy(s: string): number;
export interface SecretVerdict {
    confidence: 'high' | 'medium';
    reason: string;
}
/** Похоже ли значение на секрет (с учётом имени, к которому оно привязано) */
export declare function judgeSecret(value: string, nameHint?: string): SecretVerdict | undefined;
/** Mask a detected secret so the report itself does not leak it */
export declare function mask(value: string): string;
/** process.env.SECRET (кроме NEXT_PUBLIC_*), secretName, obj.apiKey, литерал-секрет */
export declare function secretishExpression(expr: Node, envInits: Map<string, Node>): string | undefined;
export declare function isMutationCall(call: TSESTree.CallExpression | TSESTree.NewExpression): boolean;
export declare function isDbReadCall(call: Node): boolean;
export declare function mutationsIn(fn: FunctionNode): TSESTree.CallExpression[];
export declare function isAuthCall(call: TSESTree.CallExpression | TSESTree.NewExpression): boolean;
export declare function isAuthWrapper(wrapper: string | undefined): boolean;
export declare function isValidationCall(call: TSESTree.CallExpression | TSESTree.NewExpression): boolean;
export declare function isValidationWrapper(wrapper: string | undefined): boolean;
