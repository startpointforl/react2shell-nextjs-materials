import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative, sep } from 'node:path'

const IGNORE_DIRS = new Set([
  'node_modules', '.next', '.git', 'dist', 'build', 'out', 'coverage', '.turbo', '.vercel', '.cache',
])
const EXT = /\.(c|m)?(t|j)sx?$/
const SKIP_FILE = /\.(d\.ts|test\.|spec\.|stories\.)/

export function discoverFiles(target: string): string[] {
  const out: string[] = []
  const st = statSync(target)
  if (st.isFile()) return EXT.test(target) ? [target] : []

  const walk = (dir: string) => {
    let entries: import('node:fs').Dirent[]
    try {
      entries = readdirSync(dir, { withFileTypes: true }) as import('node:fs').Dirent[]
    } catch {
      return
    }
    for (const e of entries) {
      const full = join(dir, e.name)
      if (e.isDirectory()) {
        if (IGNORE_DIRS.has(e.name) || e.name.startsWith('.')) continue
        walk(full)
      } else if (e.isFile() && EXT.test(e.name) && !SKIP_FILE.test(e.name)) {
        out.push(full)
      }
    }
  }
  walk(target)
  return out.sort()
}

export function readCode(path: string): string {
  return readFileSync(path, 'utf8')
}

export function toRel(root: string, abs: string): string {
  const r = relative(root, abs) || abs
  return r.split(sep).join('/')
}

/**
 * Беглая проверка, стоит ли вообще парсить файл: есть 'use server' (экшены) либо
 * привязка экшена через .bind() (секрет может уходить из клиентского компонента).
 */
export function mightHaveServerCode(code: string): boolean {
  return code.includes('use server') || /\.bind\s*\(/.test(code)
}
