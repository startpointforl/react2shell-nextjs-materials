import type { Finding } from './types.js';
interface Suppression {
    line: number;
    rules: Set<string> | null;
}
export declare function collectSuppressions(code: string): Suppression[];
export declare function filterSuppressed(findings: Finding[], suppressions: Suppression[]): {
    kept: Finding[];
    suppressed: number;
};
export {};
