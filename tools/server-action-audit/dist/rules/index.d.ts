import type { Rule } from '../types.js';
/** CVE-правила (high-сигнал по теме доклада) + эвристики гигиены */
export declare const CVE_RULES: Rule[];
export declare const HYGIENE_RULES: Rule[];
export declare const ALL_RULES: Rule[];
export declare function rulesFor(opts: {
    heuristics: boolean;
}): Rule[];
