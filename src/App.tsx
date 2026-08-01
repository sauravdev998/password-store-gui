import { useCallback, useEffect, useMemo, useState } from 'react'
import { ClipboardNotice, type Clipped } from './components/ClipboardNotice'
import { DeleteDialog } from './components/DeleteDialog'
import { EditEntryDialog } from './components/EditEntryDialog'
import { EntryDetail } from './components/EntryDetail'
import { MoveDialog } from './components/MoveDialog'
import { NewEntryDialog } from './components/NewEntryDialog'
import { Tree } from './components/Tree'
import { useNow } from './hooks/useNow'
import { AlertIcon, CheckIcon, LockIcon, PlusIcon, StoreIcon } from './lib/icons'
import { useAutoOpen } from './lib/prefs'
import {
  clearClipboard,
  listTree,
  storeHasHistory,
  type Node,
  type Tree as StoreTree,
  type WriteReceipt,
} from './lib/commands'

/** Entries only — folders are structure, not things the user came for. */
function countEntries(nodes: Node[]): number {
  return nodes.reduce(
    (total, node) => total + (node.kind === 'dir' ? countEntries(node.children) : 1),
    0,
  )
}

/** The folder an entry sits in, with its trailing slash, or `''` at the root. */
function folderOf(name: string | null): string {
  if (!name) return ''
  const cut = name.lastIndexOf('/')
  return cut === -1 ? '' : name.slice(0, cut + 1)
}

/** Which dialog is open. Only one at a time, and none of them is ever hidden. */
type OpenDialog =
  | { kind: 'new'; folder: string }
  | { kind: 'edit'; name: string }
  | { kind: 'move'; mode: 'rename' | 'duplicate'; from: string }
  | { kind: 'delete'; name: string }

/** What just happened, in one line. */
type Notice = {
  /** `warn` stays until dismissed; `ok` is a confirmation and fades. */
  tone: 'ok' | 'warn'
  message: string
}

/**
 * Turn a mutation's receipt into something worth saying.
 *
 * The interesting case is the middle one: the entry *was* written and the
 * commit was not made. Reporting that as a plain failure would be a lie in the
 * direction that gets a password lost — the user would retry and hit "already
 * exists" — so the sentence puts the write first and the history second (§4.1
 * principle 5).
 */
function noticeFor(done: string, receipt: WriteReceipt): Notice {
  const { commit } = receipt
  if (commit?.status === 'failed') {
    return {
      tone: 'warn',
      message: `${done}. It could not be added to your store's history: ${commit.reason}`,
    }
  }
  return {
    tone: 'ok',
    message: commit ? `${done}, and added to your store's history.` : `${done}.`,
  }
}

function App() {
  const [tree, setTree] = useState<StoreTree | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [selected, setSelected] = useState<string | null>(null)
  const [autoOpen, setAutoOpen] = useAutoOpen()
  const [dialog, setDialog] = useState<OpenDialog | null>(null)
  const [notice, setNotice] = useState<Notice | null>(null)
  const [clipped, setClipped] = useState<Clipped | null>(null)
  // `null` until the core has been asked. Nothing claims either way meanwhile.
  const [versioned, setVersioned] = useState<boolean | null>(null)
  // Bumped after an edit so the detail pane remounts: it re-reads the entry's
  // shape, and every revealed value from before the edit goes with the unmount.
  const [revision, setRevision] = useState(0)

  const refresh = useCallback(async () => {
    try {
      setTree(await listTree())
      setError(null)
    } catch (e: unknown) {
      setError(String(e))
    }
  }, [])

  useEffect(() => {
    void refresh()
    storeHasHistory()
      .then(setVersioned)
      .catch(() => {
        // The store itself failed to open, which `refresh` already reports.
        // Leaving this unknown is better than asserting one of the two.
      })
  }, [refresh])

  // Only ticks while there is a clipboard window to count down.
  const now = useNow(clipped ? 500 : null)

  // The window is over: drop it, which also stops the tick above. Without this
  // the interval outlives what it was counting.
  useEffect(() => {
    if (clipped && now >= clipped.clearsAt) setClipped(null)
  }, [clipped, now])

  // A confirmation has done its job in a few seconds. A warning has not: it is
  // the only place a failed commit is ever mentioned, so it waits to be read.
  useEffect(() => {
    if (notice?.tone !== 'ok') return
    const timer = window.setTimeout(() => setNotice(null), 6000)
    return () => window.clearTimeout(timer)
  }, [notice])

  const entryCount = useMemo(() => (tree ? countEntries(tree.nodes) : 0), [tree])

  /** Everything a completed mutation has in common. */
  function settle(done: string, receipt: WriteReceipt, nextSelection?: string | null) {
    setDialog(null)
    setNotice(noticeFor(done, receipt))
    // A receipt is the most reliable answer to "does this store have a
    // history" there is: it comes from the write that just happened.
    setVersioned(receipt.commit !== null)
    if (nextSelection !== undefined) setSelected(nextSelection)
    void refresh()
  }

  async function clearNow() {
    setClipped(null)
    try {
      await clearClipboard()
    } catch (e: unknown) {
      setError(String(e))
    }
  }

  return (
    <div className="flex h-full bg-canvas text-ink">
      <aside className="flex w-68 shrink-0 flex-col border-r border-line bg-panel">
        <header className="flex shrink-0 items-center gap-2 px-4 pt-4 pb-3">
          <StoreIcon className="size-4 shrink-0 text-ink-faint" />
          <h1 className="min-w-0 flex-1 truncate text-sm font-semibold tracking-tight">
            Password Store
          </h1>
          {entryCount > 0 && (
            <span className="text-xs text-ink-faint tabular-nums">{entryCount}</span>
          )}
          <button
            type="button"
            aria-label="New entry"
            title="New entry"
            className="-mr-1 shrink-0 rounded-row p-1 text-ink-faint transition-colors hover:bg-raised hover:text-ink"
            onClick={() => setDialog({ kind: 'new', folder: folderOf(selected) })}
          >
            <PlusIcon className="size-4" />
          </button>
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
          {tree && (
            <Tree
              nodes={tree.nodes}
              selected={selected}
              onSelect={setSelected}
              onCreate={() => setDialog({ kind: 'new', folder: '' })}
            />
          )}
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

      <main className="flex min-w-0 flex-1 flex-col overflow-hidden">
        {notice && <NoticeBar notice={notice} onDismiss={() => setNotice(null)} />}

        <div className="min-h-0 flex-1">
          {selected ? (
            // Keyed by name so selecting another entry unmounts the detail
            // view: a revealed value cannot survive the switch. The revision
            // does the same after an edit, when the values are stale as well.
            <EntryDetail
              key={`${selected}@${revision}`}
              name={selected}
              autoOpen={autoOpen}
              onAutoOpenChange={setAutoOpen}
              clipped={clipped}
              onCopied={setClipped}
              onEdit={() => setDialog({ kind: 'edit', name: selected })}
              onRename={() => setDialog({ kind: 'move', mode: 'rename', from: selected })}
              onDuplicate={() => setDialog({ kind: 'move', mode: 'duplicate', from: selected })}
              onDelete={() => setDialog({ kind: 'delete', name: selected })}
            />
          ) : (
            <NothingSelected onCreate={() => setDialog({ kind: 'new', folder: '' })} />
          )}
        </div>

        {clipped && <ClipboardNotice clipped={clipped} now={now} onClear={clearNow} />}
      </main>

      {dialog?.kind === 'new' && (
        <NewEntryDialog
          folder={dialog.folder}
          onCancel={() => setDialog(null)}
          onCreated={(name, receipt) => {
            if (receipt.clipboard) {
              const windowMs = receipt.clipboard.clearsInSecs * 1000
              setClipped({
                entry: name,
                slot: 'password',
                label: 'Generated password',
                clearsAt: Date.now() + windowMs,
                windowMs,
              })
            }
            settle(`Created ${name}`, receipt, name)
          }}
        />
      )}

      {dialog?.kind === 'edit' && (
        <EditEntryDialog
          name={dialog.name}
          onCancel={() => setDialog(null)}
          onSaved={(receipt) => {
            const { name } = dialog
            setRevision((prev) => prev + 1)
            settle(`Saved ${name}`, receipt)
          }}
        />
      )}

      {dialog?.kind === 'move' && (
        <MoveDialog
          mode={dialog.mode}
          from={dialog.from}
          onCancel={() => setDialog(null)}
          onDone={(to, receipt) => {
            const { from, mode } = dialog
            settle(mode === 'rename' ? `Renamed ${from} to ${to}` : `Duplicated ${from} as ${to}`, receipt, to)
          }}
        />
      )}

      {dialog?.kind === 'delete' && (
        <DeleteDialog
          name={dialog.name}
          // Unknown reads as unversioned: promising a history that may not
          // exist is the failure that costs someone their entry.
          versioned={versioned === true}
          onCancel={() => setDialog(null)}
          onDeleted={(receipt) => settle(`Deleted ${dialog.name}`, receipt, null)}
        />
      )}
    </div>
  )
}

/**
 * The line above the entry, after something has happened to the store.
 *
 * It exists mainly for the two outcomes nothing else on screen can show: a
 * deletion, which removes the thing the user was looking at, and a commit that
 * did not go through, which leaves the store correct and its history behind.
 */
function NoticeBar({ notice, onDismiss }: { notice: Notice; onDismiss: () => void }) {
  const warn = notice.tone === 'warn'

  return (
    <div
      role="status"
      aria-live="polite"
      className={`flex shrink-0 items-start gap-2.5 border-b px-6 py-2.5 text-xs leading-relaxed ${
        warn
          ? 'border-danger-line bg-danger-soft text-danger-ink'
          : 'border-line bg-panel text-ink-muted'
      }`}
    >
      {warn ? (
        <AlertIcon className="mt-px size-3.5 shrink-0" />
      ) : (
        <CheckIcon className="mt-px size-3.5 shrink-0" />
      )}
      <span className="min-w-0 flex-1 break-words">{notice.message}</span>
      <button
        type="button"
        className="shrink-0 rounded-row px-1.5 font-medium opacity-70 transition-opacity hover:opacity-100"
        onClick={onDismiss}
      >
        Dismiss
      </button>
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
function NothingSelected({ onCreate }: { onCreate: () => void }) {
  return (
    <div className="flex h-full flex-col items-center justify-center px-8 text-center">
      <LockIcon className="size-9 text-ink-faint" />
      <p className="mt-4 text-sm font-medium text-ink">Nothing selected</p>
      <p className="mt-1.5 max-w-xs text-xs leading-relaxed text-ink-muted">
        Pick an entry to see what it holds. Nothing is decrypted until you ask for it.
      </p>
      <button
        type="button"
        className="mt-5 inline-flex items-center gap-1.5 rounded-row border border-line-strong/45 px-3 py-1.5 text-xs font-medium text-ink-muted transition-colors hover:border-line-strong hover:bg-raised hover:text-ink"
        onClick={onCreate}
      >
        <PlusIcon className="size-3.5" />
        New entry
      </button>
    </div>
  )
}

export default App
