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
import { builtinModules } from 'node:module'
import ts from 'typescript'

const EXTENSIONS = ['.ts', '.tsx', '.js', '.jsx', '.mts', '.cts', '.mjs', '.cjs']

/** Resolves one import specifier to a file on disk, or null if it is a package. */
export function resolveLocal(specifier: string, fromFile: string, root = process.cwd()): string | null {
  return resolveSpecifier(specifier, fromFile, root)
}

function resolveSpecifier(specifier: string, fromFile: string, root: string): string | null {
  const candidates: string[] = []
  if (specifier.startsWith('@/')) candidates.push(join(root, specifier.slice(2)))
  else if (specifier.startsWith('.')) candidates.push(resolve(dirname(fromFile), specifier))
  // tsconfig sets "baseUrl": ".", so `import { x } from 'lib/reporting'` is OURS and
  // resolves from the project root. Treating every non-@/ non-relative specifier as a
  // node_modules package dropped it silently -- npm run verify was green, 281 tests
  // passing, while an anonymous /login served every tenant through that import.
  else candidates.push(join(root, specifier))

  for (const base of candidates) {
    const hit = resolveFrom(base)
    if (hit) return hit
  }
  return null
}

/** True when a specifier really is a node_modules package, rather than merely unresolved. */
export function isPackage(specifier: string, root: string): boolean {
  if (specifier.startsWith('@/') || specifier.startsWith('.')) return false
  // Node builtins are packages that live in no directory.
  if (specifier.startsWith('node:') || builtinModules.includes(specifier)) return true
  const name = specifier.startsWith('@')
    ? specifier.split('/').slice(0, 2).join('/')
    : specifier.split('/')[0]!
  return existsSync(join(root, 'node_modules', name))
}

function resolveFrom(base: string): string | null {

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
 * Whether a module's FIRST statement is the 'use server' directive, decided on the
 * parsed syntax tree rather than by stripping comments and matching a prefix.
 *
 * Exported so callers can reason about action modules explicitly instead of this
 * file silently deleting them from the graph.
 */
export function moduleKind(source: string): 'server-action' | 'ordinary' {
  const parsed = ts.createSourceFile('probe.tsx', source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX)
  const first = parsed.statements[0]
  if (first && ts.isExpressionStatement(first) && ts.isStringLiteral(first.expression)
      && first.expression.text === 'use server') {
    return 'server-action'
  }
  return 'ordinary'
}

/**
 * True when any import()/require() call takes something other than a single string
 * literal. preProcessFile silently returns the literal head of a concatenation, so
 * without this `import('@/a' + 'b')` would resolve to the wrong module and the graph
 * would look complete.
 */
function hasComputedSpecifier(source: string, fileName: string): boolean {
  const parsed = ts.createSourceFile(fileName, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX)
  let computed = false
  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node)) {
      const callee = node.expression
      const isLoader = callee.kind === ts.SyntaxKind.ImportKeyword
        || (ts.isIdentifier(callee) && callee.text === 'require')
      if (isLoader) {
        const arg = node.arguments[0]
        // isStringLiteralLike, not isStringLiteral: `import(`./x`)` is a
        // NoSubstitutionTemplateLiteral with exactly one static answer, and
        // preProcessFile resolves it correctly. Rejecting it told the engineer to
        // "use a literal import" in a file that already had one -- a false positive
        // on honest code, which is what gets a check weakened rather than fixed.
        if (!arg || !ts.isStringLiteralLike(arg)) computed = true
      }
    }
    ts.forEachChild(node, visit)
  }
  visit(parsed)
  return computed
}

/** Modules that can load code without naming it in an import. */
const OPAQUE_LOADERS = new Set([
  'node:worker_threads', 'worker_threads',
  'node:module', 'module',
  'node:vm', 'vm',
  'node:child_process', 'child_process',
])

/**
 * The file plus every local module reachable from it. Cycles terminate; a
 * specifier that resolves to nothing is simply not our code.
 */
export function moduleClosure(entry: string, root = process.cwd()): string[] {
  const { files, unanalyzable } = closureOf(entry, root)
  assertComplete(entry, unanalyzable)
  return files
}

/**
 * The single gate every caller passes through.
 *
 * closureOf had TWO consumers and only closureSource was wired to the accounting;
 * moduleClosure returned a bare `.files` list and dropped `unanalyzable` on the
 * floor. The dataless-page guard calls moduleClosure, so the completeness proof was
 * computed and then thrown away before it reached the one check that certifies a
 * page reads no tenant data -- and a computed dynamic import walked straight
 * through: 96/96 guards, 281 tests, 9/9 secret checks, exit 0, with an anonymous
 * /login serving every tenant.
 *
 * The detection generalised; the propagation did not. So there is now exactly one
 * place that decides what an incomplete graph means, and no way to read the files
 * without passing it.
 */
function assertComplete(entry: string, unanalyzable: string[]): void {
  if (unanalyzable.length === 0) return
  throw new Error(
    `cannot determine what ${entry} runs: ${[...new Set(unanalyzable)].join(', ')} `
    + 'import(s) a module this resolver cannot follow, so the module graph is '
    + 'incomplete. Use a literal import.',
  )
}



/** The closure, plus any file in it whose imports could not be followed. */
export function closureOf(entry: string, root = process.cwd()):
    { files: string[]; unanalyzable: string[] } {
  const seen = new Set<string>()
  const unanalyzable: string[] = []
  const queue = [entry]
  while (queue.length) {
    const file = queue.pop()!
    if (seen.has(file) || !existsSync(file)) continue
    const raw = readFileSync(file, 'utf8')
    const kind = moduleKind(raw)

    // A 'use server' module IS followed. The old code dropped it before any
    // accounting ran -- no site, no specifier, no error -- on the premise that
    // "nothing in it runs while the importing page renders". That premise is false
    // twice over: module-level statements execute at import, and an exported action
    // is an ordinary async function a page may call inline. A zero-export module
    // starting with 'use server' satisfied every action check vacuously and served
    // every tenant from an anonymous /login at 285/285 green.
    seen.add(file)

    // EXTRACTION IS NOW THE COMPILER'S JOB, NOT A REGEX'S.
    //
    // Four rounds widened a regex that stood in for "what modules does this file
    // pull in", and each round found the next gap: require, a webpack magic comment,
    // a tsconfig baseUrl specifier, `Buffer.from('x','utf8')` mistaken for an import.
    // TypeScript is already a dependency and already answers this question exactly,
    // so ask it. preProcessFile understands import, export-from, import-equals,
    // require and dynamic import, and returns nothing for member calls named `from`
    // or for the string "import 'x'" inside a JSX attribute.
    const preprocessed = ts.preProcessFile(raw, true, true)
    const specifiers = preprocessed.importedFiles.map((f) => f.fileName)

    // preProcessFile returns the literal HEAD of a concatenated specifier
    // (`import('@/a' + 'b')` yields '@/a'), which would silently resolve to the
    // wrong module, so a non-literal argument is still detected -- on the AST now,
    // not by counting regex matches.
    if (hasComputedSpecifier(raw, file)) unanalyzable.push(file)

    // Some modules can load code without naming it in an import: worker threads,
    // createRequire, vm, child processes. Aliasing defeated the old name-matching
    // (`new wt.Worker(...)`, `createRequire as cr`), so the test is now on the
    // IMPORT rather than the call site, which no alias can hide.
    if (specifiers.some((m) => OPAQUE_LOADERS.has(m))) unanalyzable.push(file)

    for (const specifier of specifiers) {
      const resolved = resolveSpecifier(specifier, file, root)
      if (resolved) queue.push(resolved)
      // Unresolved is only acceptable when the specifier is genuinely a package on
      // disk. "Does not start with @/ or ." is not the same as "is a package".
      else if (!isPackage(specifier, root)) unanalyzable.push(file)
    }
  }
  return { files: [...seen], unanalyzable }
}

/**
 * The concatenated source of a file and everything it imports.
 *
 * Throws when the closure contains an import this resolver cannot follow: a caller
 * asking "does anything here query the database" must not receive a confident "no"
 * built from an incomplete graph.
 */
export function closureSource(entry: string, root = process.cwd()): string {
  const { files, unanalyzable } = closureOf(entry, root)
  assertComplete(entry, unanalyzable)
  return files.map((file) => readFileSync(file, 'utf8')).join('\n')
}
