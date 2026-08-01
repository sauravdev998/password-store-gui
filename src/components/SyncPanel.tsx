import { useCallback, useEffect, useState } from 'react'
import { ArrowIcon, SyncIcon } from '../lib/icons'
import { syncStatus, syncStore, type SyncOutcome, type SyncStatus } from '../lib/commands'

/**
 * Where the store stands relative to its remote, and the one control that
 * changes it.
 *
 * Two things shape this component.
 *
 * **Reading the state is free; changing it is not.** {@link syncStatus} looks
 * only at what is already on disk, so it runs on arrival and after every
 * change without ever reaching the network, prompting for a credential, or
 * decrypting anything. Only the button reaches out — and it may put a
 * passphrase prompt on screen for an ssh key, which is why the panel says so
 * before it is pressed rather than after.
 *
 * **The outcome does not belong here.** A conflict names entries, and this
 * column is too narrow to name them in; a conflict is also the one result the
 * user must not be able to miss. So results are handed up to `App`, which has
 * the width and already owns the notice that does not fade. This component
 * reports what happened and keeps only what it needs to draw itself.
 */
type Props = {
  /** Told before the sync starts, so the window can say it is working. */
  onStarted: () => void
  onOutcome: (outcome: SyncOutcome) => void
  onError: (message: string) => void
  /**
   * Bumped by the window whenever the store changed under it, so the counts
   * follow a mutation without this component having to know what happened.
   */
  revision: number
}

export function SyncPanel({ onStarted, onOutcome, onError, revision }: Props) {
  const [status, setStatus] = useState<SyncStatus | null>(null)
  const [busy, setBusy] = useState(false)

  const refresh = useCallback(async () => {
    try {
      setStatus(await syncStatus())
    } catch {
      // The store itself failed to open, which the window already reports.
      // Saying nothing here is better than claiming a sync state we do not
      // have.
      setStatus(null)
    }
  }, [])

  useEffect(() => {
    void refresh()
  }, [refresh, revision])

  // A store with no history has no remote and no sync, and an explanation of
  // something it does not do would be noise in the one column the user reads
  // to find an entry.
  if (!status) return null

  const { tracking, uncommitted } = status

  async function sync() {
    setBusy(true)
    onStarted()
    try {
      const outcome = await syncStore()
      onOutcome(outcome)
    } catch (e: unknown) {
      onError(String(e))
    } finally {
      setBusy(false)
      void refresh()
    }
  }

  return (
    <div className="border-t border-line px-4 py-3">
      <div className="flex items-center gap-2">
        <button
          type="button"
          disabled={busy || !tracking}
          title={
            tracking
              ? `Exchange changes with ${tracking.upstream}`
              : 'This store is not shared with a remote'
          }
          className="inline-flex items-center gap-1.5 rounded-row border border-line-strong/45 px-2 py-1 text-xs font-medium text-ink-muted transition-colors hover:border-line-strong hover:bg-raised hover:text-ink disabled:cursor-not-allowed disabled:opacity-55 disabled:hover:border-line-strong/45 disabled:hover:bg-transparent disabled:hover:text-ink-muted"
          onClick={() => void sync()}
        >
          <SyncIcon className={`size-3.5 ${busy ? 'animate-waiting' : ''}`} />
          {busy ? 'Syncing…' : 'Sync'}
        </button>

        {tracking && (tracking.behind > 0 || tracking.ahead > 0) && (
          <span className="flex items-center gap-2 text-xs text-ink-muted tabular-nums">
            {tracking.behind > 0 && (
              <span className="flex items-center gap-0.5">
                <ArrowIcon className="size-3.5 text-ink-faint" />
                <span className="sr-only">{tracking.behind} to come in, </span>
                <span aria-hidden="true">{tracking.behind}</span>
              </span>
            )}
            {tracking.ahead > 0 && (
              <span className="flex items-center gap-0.5">
                <ArrowIcon className="size-3.5 text-ink-faint" up />
                <span className="sr-only">{tracking.ahead} to go out</span>
                <span aria-hidden="true">{tracking.ahead}</span>
              </span>
            )}
          </span>
        )}
      </div>

      <p className="mt-2 text-xs leading-relaxed text-ink-faint">
        {tracking ? (
          <>
            Shared with <span className="font-mono break-all">{tracking.upstream}</span>. Syncing
            may ask for your key's passphrase.
          </>
        ) : (
          // Said plainly rather than left to be inferred from a greyed-out
          // button: the store *is* versioned, so "nothing happens when I press
          // Sync" has a cause the user cannot see (§4.1 principle 5).
          <>This store keeps a history on this computer, but is not shared with a remote.</>
        )}
      </p>

      {uncommitted > 0 && (
        // Every change this app makes records itself, so anything uncommitted
        // came from somewhere else — and a sync that sent everything *but*
        // those would leave the user believing they had gone out.
        <p className="mt-2 text-xs leading-relaxed text-danger-ink">
          {uncommitted === 1 ? '1 file has changes' : `${uncommitted} files have changes`} that are
          not in the history yet, so syncing will not send them.
        </p>
      )}
    </div>
  )
}

