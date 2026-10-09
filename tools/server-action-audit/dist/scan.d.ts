import type { Rule, ScanResult } from './types.js';
export interface ScanOptions {
    heuristics: boolean;
    rules?: Rule[];
}
export declare function scan(target: string, opts: ScanOptions): ScanResult;
