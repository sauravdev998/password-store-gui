import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { ClipboardNotice, type Clipped } from './components/ClipboardNotice'
import { DeleteDialog } from './components/DeleteDialog'
import { EditEntryDialog } from './components/EditEntryDialog'
import { EntryDetail } from './components/EntryDetail'
import { MoveDialog } from './components/MoveDialog'
import { HistoryDialog } from './components/HistoryDialog'
import { NewEntryDialog } from './components/NewEntryDialog'
import { SettingsDialog } from './components/SettingsDialog'
import { SyncPanel } from './components/SyncPanel'
import { Tree } from './components/Tree'
import { useAutoLock } from './hooks/useAutoLock'
import { useNow } from './hooks/useNow'
import {
  AlertIcon,
  CheckIcon,
  GearIcon,
  LockIcon,
  PlusIcon,
  SearchIcon,
  StoreIcon,
} from './lib/icons'
import { behaviour, useSettings } from './lib/settings'
import {
  clearClipboard,
  listTree,
  storeHasHistory,
  type Node,
  type SyncOutcome,
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
  | { kind: 'history'; name: string }
  | { kind: 'settings' }

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

/**
 * Turn a finished sync into something worth saying.
 *
 * The interesting case is again the failure: a conflict has to say what was
 * *not* done. "Nothing on this computer was changed" is the fact that stops the
 * user hunting for damage — and it is true, because the core rolls a conflicted
 * merge back rather than leaving markers inside ciphertext.
 */
function describeSync(outcome: SyncOutcome): Notice {
  switch (outcome.status) {
    case 'noRemote':
      return {
        tone: 'ok',
        message: 'This store is not shared with a remote, so there was nothing to sync.',
      }
    case 'upToDate':
      return { tone: 'ok', message: 'Your store is already in step with its remote.' }
    case 'synced': {
      const parts: string[] = []
      if (outcome.pulled > 0) parts.push(`brought in ${changes(outcome.pulled)}`)
      if (outcome.pushed > 0) parts.push(`sent ${changes(outcome.pushed)}`)
      return { tone: 'ok', message: `Synced: ${parts.join(', ')}.` }
    }
    case 'conflicted':
      return {
        tone: 'warn',
        message:
          `Your store and its remote both changed ${listed(outcome.entries)}, so they could not ` +
          `be combined automatically. Nothing on this computer was changed. Decide which version ` +
          `you want to keep, then sync again.`,
      }
  }
}

const changes = (count: number) => (count === 1 ? '1 change' : `${count} changes`)

/** Nothing configured, for the moment before the core has answered. */
const EMPTY_SETTINGS = {
  storeDir: null,
  clipTimeSecs: null,
  generatedLength: null,
  lockAfterSecs: null,
  lockOnBlur: null,
  openOnSelect: null,
} as const

/** Name the entries in a sentence, without letting a long list run away. */
function listed(entries: string[]): string {
  if (entries.length === 0) return 'the same entries'
  if (entries.length <= 3) return entries.join(', ')
  return `${entries.slice(0, 3).join(', ')} and ${entries.length - 3} more`
}

function App() {
  const [tree, setTree] = useState<StoreTree | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [selected, setSelected] = useState<string | null>(null)
  const { settings, error: settingsError, save: saveSettings } = useSettings()
  const { lockAfterSecs, lockOnBlur, openOnSelect } = behaviour(settings)
  const [dialog, setDialog] = useState<OpenDialog | null>(null)
  const [filter, setFilter] = useState('')
  const [locked, setLocked] = useState(false)
  // Bumped when what is on screen should stop showing, short of a remount.
  const [relock, setRelock] = useState(0)
  const [notice, setNotice] = useState<Notice | null>(null)
  const [clipped, setClipped] = useState<Clipped | null>(null)
  // `null` until the core has been asked. Nothing claims either way meanwhile.
  const [versioned, setVersioned] = useState<boolean | null>(null)
  // Bumped after an edit so the detail pane remounts: it re-reads the entry's
  // shape, and every revealed value from before the edit goes with the unmount.
  const [revision, setRevision] = useState(0)
  // Bumped whenever the store changed at all, so the sync panel's counts follow
  // without it having to know what happened. Kept apart from `revision`, which
  // costs a remount and is only warranted when revealed values went stale.
  const [storeRevision, setStoreRevision] = useState(0)

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

  /**
   * Invariant 7. What each event does is deliberately different — see
   * `useAutoLock` for why the two are not one rule.
   *
   * Neither touches the clipboard. Leaving the window is precisely when a
   * copied password is about to be pasted, and by the time the window has gone
   * idle Invariant 6's timer has long since cleared it anyway; wiping it here
   * would only ever destroy something the user copied from somewhere else.
   */
  useAutoLock({
    idleSecs: lockAfterSecs,
    onBlurEnabled: lockOnBlur,
    enabled: !locked,
    onIdle: () => {
      setLocked(true)
      // Everything holding plaintext goes: the edit form and the history's open
      // version (ADR-8, ADR-10) with the dialog, the revealed rows with the
      // selection. Deselecting rather than remounting is what stops the unlock
      // from decrypting again on its own under "open entries on select" — the
      // user picks an entry back up, and picking it up is the request.
      setDialog(null)
      setSelected(null)
      setNotice(null)
    },
    onBlur: () => setRelock((prev) => prev + 1),
  })

  // Cmd/Ctrl+F reaches the filter from anywhere, which is the point of having
  // one: a store is searched in the middle of doing something else.
  const search = useRef<HTMLInputElement>(null)
  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === 'f' && (event.metaKey || event.ctrlKey)) {
        event.preventDefault()
        search.current?.focus()
        search.current?.select()
      }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [])

  /** Everything a completed mutation has in common. */
  function settle(done: string, receipt: WriteReceipt, nextSelection?: string | null) {
    setDialog(null)
    setNotice(noticeFor(done, receipt))
    // A receipt is the most reliable answer to "does this store have a
    // history" there is: it comes from the write that just happened.
    setVersioned(receipt.commit !== null)
    if (nextSelection !== undefined) setSelected(nextSelection)
    setStoreRevision((prev) => prev + 1)
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
            className="shrink-0 rounded-row p-1 text-ink-faint transition-colors hover:bg-raised hover:text-ink"
            onClick={() => setDialog({ kind: 'new', folder: folderOf(selected) })}
          >
            <PlusIcon className="size-4" />
          </button>
          <button
            type="button"
            aria-label="Settings"
            title="Settings"
            className="-mr-1 shrink-0 rounded-row p-1 text-ink-faint transition-colors hover:bg-raised hover:text-ink"
            onClick={() => setDialog({ kind: 'settings' })}
          >
            <GearIcon className="size-4" />
          </button>
        </header>

        {/* Names only, and the placeholder says so: searching what entries
            contain would mean decrypting all of them to answer a keystroke,
            which is the prompt-you-did-not-ask-for that §4.1 principle 1
            exists to forbid. */}
        <div className="relative shrink-0 px-3 pb-2.5">
          <SearchIcon className="pointer-events-none absolute top-1/2 left-5 size-3.5 -translate-y-1/2 text-ink-faint" />
          <input
            ref={search}
            type="search"
            value={filter}
            aria-label="Filter entries by name"
            placeholder="Filter by name"
            spellCheck={false}
            className="w-full rounded-row border border-line-strong/40 bg-raised py-1.5 pr-2.5 pl-8 text-xs text-ink transition-colors placeholder:text-ink-faint hover:border-line-strong/70 focus:border-line-strong"
            onChange={(event) => setFilter(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === 'Escape' && filter !== '') {
                // Clear first, blur second: Escape inside a search box should
                // undo the search before it gives up the field.
                event.preventDefault()
                setFilter('')
              }
            }}
          />
        </div>

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
              filter={filter}
            />
          )}
        </nav>

        {/* `divide-y` rather than a border on each: the sync panel renders
            nothing at all on a store with no history, and a divider drawn by
            the container only appears between children that exist. */}
        <div className="shrink-0 divide-y divide-line border-t border-line">
          <SyncPanel
            revision={storeRevision}
            onStarted={() => setNotice(null)}
            onOutcome={(outcome) => {
              setNotice(describeSync(outcome))
              // A sync can bring entries in, so the tree is stale either way —
              // and after a conflict nothing changed, which `refresh` confirms
              // rather than assumes.
              setStoreRevision((prev) => prev + 1)
              setRevision((prev) => prev + 1)
              void refresh()
            }}
            onError={(message) => setNotice({ tone: 'warn', message })}
          />

          {settingsError && (
            // The app runs on the built-in defaults when this happens, which is
            // survivable but not something to leave unsaid: a user whose lock
            // timeout is quietly not the one they chose should know why.
            <p className="px-4 py-2.5 text-xs leading-relaxed text-ink-muted">
              Your settings could not be read, so the built-in ones are in use. {settingsError}
            </p>
          )}

          {tree && tree.unsupported.length > 0 && (
            // Surfaced rather than dropped: a file that exists but is invisible
            // in the GUI is worse than one shown as unusable.
            <details className="px-4 py-2.5 text-xs text-ink-muted">
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
              autoOpen={openOnSelect}
              onAutoOpenChange={(next) => {
                // The core is the one place this lives now, so the checkbox in
                // the locked panel writes through to it like the settings
                // panel does. A failure is not worth a notice: the box springs
                // back, which says the same thing.
                void saveSettings({
                  ...(settings?.configured ?? EMPTY_SETTINGS),
                  openOnSelect: next,
                }).catch(() => {})
              }}
              relock={relock}
              clipped={clipped}
              onCopied={setClipped}
              onEdit={() => setDialog({ kind: 'edit', name: selected })}
              // Offered only when there is a history to show. Unknown reads as
              // none, the same way the delete confirmation treats it: a button
              // that opens an empty list is worse than no button.
              onHistory={
                versioned === true ? () => setDialog({ kind: 'history', name: selected }) : undefined
              }
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

      {dialog?.kind === 'history' && (
        // Mounted only while open, like every other dialog, and for the
        // sharpest version of the reason: it can hold a whole decrypted past
        // version (ADR-10), and unmounting is what guarantees that string goes.
        <HistoryDialog
          name={dialog.name}
          clipped={clipped}
          onCopied={setClipped}
          onClose={() => setDialog(null)}
        />
      )}

      {dialog?.kind === 'settings' && settings && (
        <SettingsDialog
          settings={settings}
          onSave={saveSettings}
          onClose={() => setDialog(null)}
        />
      )}

      {locked && <LockScreen onUnlock={() => setLocked(false)} />}
    </div>
  )
}

/**
 * What is left after an idle lock.
 *
 * It is deliberately not a password prompt, and says so: this app never handles
 * a passphrase (Invariant 3), so there is nothing here to authenticate against.
 * The security was done before this appeared — everything decrypted was dropped
 * when the timer fired — and what remains is a screen saying so, and a button.
 * Claiming otherwise would be a lock that only looks like one.
 */
function LockScreen({ onUnlock }: { onUnlock: () => void }) {
  const ref = useRef<HTMLDialogElement>(null)

  useEffect(() => {
    const dialog = ref.current
    if (dialog && !dialog.open) dialog.showModal()
  }, [])

  return (
    // A real `<dialog>` on `showModal`, for the reason `Dialog.tsx` gives: only
    // the modal form makes everything behind it inert and traps focus. A plain
    // overlay div covers the window visually and does nothing else — the tree,
    // the filter, Sync and Settings all stayed on the Tab order behind it, so a
    // locked window could still be driven from the keyboard. On a screen whose
    // whole job is that nothing is reachable, that is the bug.
    <dialog
      ref={ref}
      aria-label="Locked"
      // Escape dismisses it, like every other dialog here. Nothing is being
      // guarded at this point: the clearing already happened when the timer
      // fired, and this app holds no passphrase to ask for (Invariant 3), so
      // the screen reports what was done rather than standing between the user
      // and anything.
      onClose={onUnlock}
      className="fixed inset-0 m-0 flex h-full max-h-none w-full max-w-none flex-col items-center justify-center border-0 bg-canvas px-8 text-center text-ink"
    >
      <LockIcon className="size-10 text-ink-faint" />
      <p className="mt-5 text-base font-semibold text-ink">Locked while you were away</p>
      <p className="mt-2 max-w-sm text-sm leading-relaxed text-ink-muted">
        Everything that was showing has been hidden, and anything you had open was closed. Your
        store is untouched.
      </p>
      <button
        type="button"
        autoFocus
        className="mt-6 inline-flex items-center gap-2 rounded-row bg-accent px-4 py-2 text-sm font-semibold text-accent-on shadow-lift transition-[filter] duration-150 hover:brightness-105 active:brightness-95"
        onClick={() => ref.current?.close()}
      >
        <LockIcon className="size-4" open />
        Continue
      </button>
    </dialog>
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
