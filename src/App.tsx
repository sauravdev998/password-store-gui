import { useEffect, useState } from 'react'
import { coreVersion } from './lib/commands'

function App() {
  const [version, setVersion] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    coreVersion().then(setVersion).catch((e: unknown) => setError(String(e)))
  }, [])

  return (
    <div className="flex h-full bg-white text-neutral-900 dark:bg-neutral-900 dark:text-neutral-100">
      <aside className="w-64 shrink-0 border-r border-neutral-200 p-3 dark:border-neutral-800">
        <h1 className="text-sm font-semibold">Password Store</h1>
        <p className="mt-1 text-xs text-neutral-500">Tree — Phase 1</p>
      </aside>
      <main className="flex flex-1 items-center justify-center p-6">
        <p className="font-mono text-xs text-neutral-500">
          {error ?? (version ? `core ${version}` : 'connecting to core…')}
        </p>
      </main>
    </div>
  )
}

export default App
