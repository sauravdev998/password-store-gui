import { useEffect, useMemo, useState } from 'react'
import { EntryDetail } from './components/EntryDetail'
import { Tree } from './components/Tree'
import { AlertIcon, LockIcon, StoreIcon } from './lib/icons'
import { useAutoOpen } from './lib/prefs'
import { listTree, type Node, type Tree as StoreTree } from './lib/commands'

/** Entries only — folders are structure, not things the user came for. */
function countEntries(nodes: Node[]): number {
  return nodes.reduce(
    (total, node) => total + (node.kind === 'dir' ? countEntries(node.children) : 1),
    0,
  )
}

function App() {
  const [tree, setTree] = useState<StoreTree | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [selected, setSelected] = useState<string | null>(null)
  const [autoOpen, setAutoOpen] = useAutoOpen()

  useEffect(() => {
    listTree()
      .then(setTree)
      .catch((e: unknown) => setError(String(e)))
  }, [])

  const entryCount = useMemo(() => (tree ? countEntries(tree.nodes) : 0), [tree])

  return (
    <div className="flex h-full bg-canvas text-ink">
      <aside className="flex w-68 shrink-0 flex-col border-r border-line bg-panel">
        <header className="flex shrink-0 items-center gap-2 px-4 pt-4 pb-3">
          <StoreIcon className="size-4 shrink-0 text-ink-faint" />
          <h1 className="flex-1 truncate text-sm font-semibold tracking-tight">Password Store</h1>
          {entryCount > 0 && (
            <span className="text-xs text-ink-faint tabular-nums">{entryCount}</span>
          )}
        </header>

        <nav aria-label="Store contents" className="flex-1 overflow-y-auto px-1.5">
          {error && (
            <div
              role="alert"
              className="m-1.5 flex items-start gap-2 rounded-panel border border-danger-line bg-danger-soft px-3 py-2.5 text-xs leading-relaxed text-danger-ink"
            >
              <AlertIcon className="mt-px size-3.5 shrink-0" />
              <span className="min-w-0 break-words">{error}</span>
            </div>
          )}
          {!tree && !error && (
            <p className="px-2.5 py-2 text-xs text-ink-muted">Reading the store…</p>
          )}
          {tree && <Tree nodes={tree.nodes} selected={selected} onSelect={setSelected} />}
        </nav>

        <div className="shrink-0 border-t border-line">
          <label className="flex cursor-pointer items-center gap-2.5 px-4 py-3 text-xs text-ink-muted select-none">
            <input
              type="checkbox"
              checked={autoOpen}
              className="size-3.5 shrink-0 accent-[var(--c-accent)]"
              onChange={(event) => setAutoOpen(event.target.checked)}
            />
            <span className="leading-snug">Open entries on select</span>
          </label>

          {tree && tree.unsupported.length > 0 && (
            // Surfaced rather than dropped: a file that exists but is invisible
            // in the GUI is worse than one shown as unusable.
            <details className="border-t border-line px-4 py-2.5 text-xs text-ink-muted">
              <summary className="cursor-pointer rounded-row py-0.5 select-none hover:text-ink">
                {tree.unsupported.length}{' '}
                {tree.unsupported.length === 1 ? 'file has' : 'files have'} names this app cannot
                use
              </summary>
              <ul className="mt-2 space-y-1 font-mono break-all text-ink-faint">
                {tree.unsupported.map((path) => (
                  <li key={path}>{path}</li>
                ))}
              </ul>
            </details>
          )}
        </div>
      </aside>

      <main className="min-w-0 flex-1 overflow-hidden">
        {selected ? (
          // Keyed by name so selecting another entry unmounts the detail view:
          // a revealed value cannot survive the switch.
          <EntryDetail
            key={selected}
            name={selected}
            autoOpen={autoOpen}
            onAutoOpenChange={setAutoOpen}
          />
        ) : (
          <NothingSelected />
        )}
      </main>
    </div>
  )
}

/**
 * The resting state of the window.
 *
 * It uses the space to say what selecting an entry will and will not do, since
 * the answer is the app's central promise and is not guessable: everything in
 * the store stays encrypted until asked for, by name.
 */
function NothingSelected() {
  return (
    <div className="flex h-full flex-col items-center justify-center px-8 text-center">
      <LockIcon className="size-9 text-ink-faint" />
      <p className="mt-4 text-sm font-medium text-ink">Nothing selected</p>
      <p className="mt-1.5 max-w-xs text-xs leading-relaxed text-ink-muted">
        Pick an entry to see what it holds. Nothing is decrypted until you ask for it.
      </p>
    </div>
  )
}

export default App
