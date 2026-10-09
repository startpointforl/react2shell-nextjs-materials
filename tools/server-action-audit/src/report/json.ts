import type { ScanResult } from '../types.js'

export function renderJson(result: ScanResult): string {
  const counts = { high: 0, medium: 0, low: 0 }
  for (const f of result.findings) counts[f.severity]++
  return JSON.stringify(
    {
      tool: 'server-action-audit',
      version: 1,
      root: result.root,
      summary: {
        filesScanned: result.filesScanned,
        filesWithActions: result.filesWithActions,
        actions: result.actions.length,
        findings: result.findings.length,
        suppressed: result.suppressed,
        counts,
      },
      findings: result.findings,
      actions: result.actions,
      parseErrors: result.parseErrors,
    },
    null,
    2,
  )
}
