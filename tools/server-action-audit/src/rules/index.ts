import type { Rule } from '../types.js'
import { stringifyArgRule } from './stringify-arg.js'
import { hardcodedSecretRule } from './hardcoded-secret.js'
import { boundSecretRule } from './bound-secret.js'
import { missingAuthRule } from './missing-auth.js'
import { missingValidationRule } from './missing-validation.js'
import { dangerousSinkRule } from './dangerous-sink.js'
import { massAssignmentRule } from './mass-assignment.js'
import { returnLeakRule } from './return-leak.js'

/** CVE-правила (high-сигнал по теме доклада) + эвристики гигиены */
export const CVE_RULES: Rule[] = [stringifyArgRule, hardcodedSecretRule, boundSecretRule]
export const HYGIENE_RULES: Rule[] = [
  dangerousSinkRule,
  massAssignmentRule,
  returnLeakRule,
  missingAuthRule,
  missingValidationRule,
]
export const ALL_RULES: Rule[] = [...CVE_RULES, ...HYGIENE_RULES]

export function rulesFor(opts: { heuristics: boolean }): Rule[] {
  return opts.heuristics ? ALL_RULES : CVE_RULES
}
