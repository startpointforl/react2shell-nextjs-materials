import type { TSESTree } from '@typescript-eslint/typescript-estree';
import type { ServerAction } from './types.js';
export declare function hasDirective(body: TSESTree.Statement[] | TSESTree.ProgramStatement[], directive: string): boolean;
export declare function findActions(ast: TSESTree.Program, file: string): {
    moduleDirective: boolean;
    actions: ServerAction[];
};
