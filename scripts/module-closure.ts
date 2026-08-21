/**
 * Every local module a file pulls in, transitively.
 *
 * Two separate checks certify a page as "renders no data" by grepping THAT FILE
 * for a database call. Neither followed imports, so a page whose query sat one
 * module away was certified dataless by both -- and `/login`, an anonymous route,
 * rendered every tenant in the system through a service-role helper while the guard
 * tests (166/166) and the secret scan both passed.
 *
 * A claim about what a page does has to cover the code the page actually runs.
 */
import { existsSync, readFileSync, statSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'

const EXTENSIONS = ['.ts', '.tsx', '.js', '.jsx', '.mts', '.cts', '.mjs', '.cjs']

/** Resolves one import specifier to a file on disk, or null if it is a package. */
function resolveSpecifier(specifier: string, fromFile: string, root: string): string | null {
  let base: string
  if (specifier.startsWith('@/')) base = join(root, specifier.slice(2))
  else if (specifier.startsWith('.')) base = resolve(dirname(fromFile), specifier)
  else return null // a node_modules package: not our code

  for (const extension of EXTENSIONS) {
    if (existsSync(base + extension)) return base + extension
  }
  if (existsSync(base) && statSync(base).isDirectory()) {
    for (const extension of EXTENSIONS) {
      const index = join(base, 'index' + extension)
      if (existsSync(index)) return index
    }
  }
  return existsSync(base) && statSync(base).isFile() ? base : null
}

/**
 * True when the whole module is a server-action module -- its FIRST statement is
 * the 'use server' directive.
 *
 * Such a module is a separate entry point: nothing in it runs while the importing
 * page renders, it is reached only by a POST, and every export in it is checked for
 * CSRF, session and audit by tests/app/guards.test.ts. Following a page into its own
 * actions file would make every page that has a form look like it queries at render
 * time. A file with an INLINE 'use server' inside a function body is not this -- the
 * directive is not first -- so it stays in the closure and is read.
 */
function isServerActionModule(source: string): boolean {
  const firstStatement = source
    .replace(/^\s*(\/\*[\s\S]*?\*\/|\/\/.*$)\s*/gm, '')
    .trimStart()
  return /^['"]use server['"]/.test(firstStatement)
}

/**
 * The file plus every local module reachable from it. Cycles terminate; a
 * specifier that resolves to nothing is simply not our code.
 */
export function moduleClosure(entry: string, root = process.cwd()): string[] {
  const seen = new Set<string>()
  const queue = [entry]
  while (queue.length) {
    const file = queue.pop()!
    if (seen.has(file) || !existsSync(file)) continue
    const source = readFileSync(file, 'utf8')
    // Never skip the entry itself, whatever it is.
    if (file !== entry && isServerActionModule(source)) continue
    seen.add(file)
    // static imports, re-exports, and dynamic import() alike
    const specifiers = [
      ...source.matchAll(/(?:from|import)\s*\(?\s*['"]([^'"]+)['"]/g),
    ].map((match) => match[1]!)
    for (const specifier of specifiers) {
      const resolved = resolveSpecifier(specifier, file, root)
      if (resolved) queue.push(resolved)
    }
  }
  return [...seen]
}

/** The concatenated source of a file and everything it imports. */
export function closureSource(entry: string, root = process.cwd()): string {
  return moduleClosure(entry, root).map((file) => readFileSync(file, 'utf8')).join('\n')
}
