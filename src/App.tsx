import { useEffect, useState } from 'react'
import { EntryDetail } from './components/EntryDetail'
import { Tree } from './components/Tree'
import { listTree, type Tree as StoreTree } from './lib/commands'

function App() {
  const [tree, setTree] = useState<StoreTree | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [selected, setSelected] = useState<string | null>(null)

  useEffect(() => {
    listTree()
      .then(setTree)
      .catch((e: unknown) => setError(String(e)))
  }, [])

  return (
    <div className="flex h-full bg-white text-neutral-900 dark:bg-neutral-900 dark:text-neutral-100">
      <aside className="flex w-72 shrink-0 flex-col border-r border-neutral-200 dark:border-neutral-800">
        <h1 className="border-b border-neutral-200 px-3 py-2 text-sm font-semibold dark:border-neutral-800">
          Password Store
        </h1>

        <nav className="flex-1 overflow-y-auto p-1">
          {error && (
            <p className="m-2 rounded border border-red-300 bg-red-50 px-2 py-1.5 text-xs text-red-700 dark:border-red-900 dark:bg-red-950 dark:text-red-300">
              {error}
            </p>
          )}
          {!tree && !error && <p className="px-2 py-1 text-xs text-neutral-500">Loading…</p>}
          {tree && <Tree nodes={tree.nodes} selected={selected} onSelect={setSelected} />}
        </nav>

        {tree && tree.unsupported.length > 0 && (
          // Surfaced rather than dropped: a file that exists but is invisible
          // in the GUI is worse than one shown as unusable.
          <details className="border-t border-neutral-200 px-3 py-2 text-xs text-neutral-500 dark:border-neutral-800">
            <summary className="cursor-pointer">
              {tree.unsupported.length} file(s) with unsupported names
            </summary>
            <ul className="mt-1 space-y-0.5 font-mono break-all">
              {tree.unsupported.map((path) => (
                <li key={path}>{path}</li>
              ))}
            </ul>
          </details>
        )}
      </aside>

      <main className="flex-1 overflow-hidden">
        {selected ? (
          // Keyed by name so selecting another entry unmounts the detail view:
          // a revealed value cannot survive the switch.
          <EntryDetail key={selected} name={selected} />
        ) : (
          <p className="flex h-full items-center justify-center text-sm text-neutral-500">
            Select an entry.
          </p>
        )}
      </main>
    </div>
  )
}

export default App
