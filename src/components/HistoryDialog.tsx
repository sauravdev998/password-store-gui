import { useEffect, useState } from 'react'
import { Dialog, FormError } from './Dialog'
import type { Clipped } from './ClipboardNotice'
import { CheckIcon, CopyIcon, EyeIcon, EyeOffIcon, HistoryIcon } from '../lib/icons'
import {
  copyRevisionPassword,
  entryHistory,
  revealRevision,
  type Revision,
} from '../lib/commands'

/**
 * What an entry used to be.
 *
 * The list itself decrypts nothing — it is commit messages and dates — so
 * opening this costs no passphrase prompt and no security-key touch (§4.1
 * principle 1). Reading one of the versions does, and that is a separate press
 * on a specific row.
 *
 * **Reading a version hands over a whole body** (ADR-10), which is the same
 * exception the edit form is: what a past version *said* is the entire reason
 * to look, and its shape is only knowable by decrypting it. The discipline is
 * therefore the edit form's discipline —
 *
 * - the dialog is mounted only while open, so closing it takes the string with
 *   it rather than leaving it in a hidden component;
 * - at most one version is open at a time, because opening a second closes the
 *   first, so there is never more than one old body in the page;
 * - the shown body carries the `bg-exposed` wash every revealed value does. The
 *   colour rule holds: warm means something is showing.
 *
 * Copying the old password needs none of that. `copy_revision_password`
 * decrypts in the core and puts the first line straight on the clipboard, so
 * the ordinary recovery — "the new one does not work, give me the old one" —
 * never renders a password at all.
 */
type Props = {
  name: string
  /** What the window believes is on the clipboard, so a row can say "Copied". */
  clipped: Clipped | null
  onCopied: (next: Clipped) => void
  onClose: () => void
}

export function HistoryDialog({ name, clipped, onCopied, onClose }: Props) {
  const [revisions, setRevisions] = useState<Revision[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  /** The one version currently on screen: its id, and its whole plaintext. */
  const [shown, setShown] = useState<{ id: string; body: string } | null>(null)
  const [loading, setLoading] = useState<string | null>(null)
  /**
   * Which version's password was copied, so one row says "Copied" rather than
   * all of them. Held here because the window's clipboard notice describes
   * *what* is on the clipboard, not which of several versions it came from —
   * and it is checked against that notice below, so the row stops claiming it
   * the moment the clipboard clears.
   */
  const [copiedId, setCopiedId] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    entryHistory(name)
      .then((next) => {
        if (!cancelled) setRevisions(next)
      })
      .catch((e: unknown) => {
        if (!cancelled) setError(String(e))
      })
    return () => {
      cancelled = true
    }
  }, [name])

  async function show(id: string) {
    setError(null)
    setLoading(id)
    try {
      // Assigned rather than merged: one slot means opening a version closes
      // whichever was open, so the page holds one old body at most.
      setShown({ id, body: await revealRevision(name, id) })
    } catch (e: unknown) {
      setError(String(e))
    } finally {
      setLoading(null)
    }
  }

  async function copy(revision: Revision) {
    setError(null)
    try {
      const receipt = await copyRevisionPassword(name, revision.id)
      setCopiedId(revision.id)
      const windowMs = receipt.clearsInSecs * 1000
      onCopied({
        entry: name,
        slot: 'password',
        // The window's notice reads "<label> from <entry> copied", so the
        // label has to be a noun phrase — "Password from <date>" would put
        // two "from"s in one sentence.
        label: `Earlier password (${when(revision.committedAt)})`,
        clearsAt: Date.now() + windowMs,
        windowMs,
      })
    } catch (e: unknown) {
      setError(String(e))
    }
  }

  return (
    <Dialog
      title={`History of ${name}`}
      description="Every version your store's history holds. Nothing here is decrypted until you open one."
      onClose={onClose}
    >
      <div className="max-h-[26rem] overflow-y-auto px-5 py-4">
        {error && (
          <div className="mb-3">
            <FormError message={error} />
          </div>
        )}

        {!revisions && !error && <p className="text-xs text-ink-muted">Reading the history…</p>}

        {revisions?.length === 0 && (
          // Distinguished from "no history at all" by the window: this dialog
          // only opens on a versioned store, so an empty list means the entry
          // predates the history or was never committed.
          <p className="text-xs leading-relaxed text-ink-muted">
            Your store's history holds no versions of this entry.
          </p>
        )}

        {revisions && revisions.length > 0 && (
          <ol className="space-y-1">
            {revisions.map((revision) => (
              <RevisionRow
                key={revision.id}
                revision={revision}
                body={shown?.id === revision.id ? shown.body : undefined}
                loading={loading === revision.id}
                copied={copiedId === revision.id && clipped?.entry === name}
                onShow={() => void show(revision.id)}
                onHide={() => setShown(null)}
                onCopy={() => void copy(revision)}
              />
            ))}
          </ol>
        )}
      </div>

      <div className="flex justify-end border-t border-line px-5 py-3.5">
        <button
          type="button"
          className="rounded-row border border-line-strong/45 px-3 py-1.5 text-xs font-medium text-ink-muted transition-colors hover:border-line-strong hover:bg-raised hover:text-ink"
          onClick={onClose}
        >
          Done
        </button>
      </div>
    </Dialog>
  )
}

function RevisionRow({
  revision,
  body,
  loading,
  copied,
  onShow,
  onHide,
  onCopy,
}: {
  revision: Revision
  /** The decrypted version, or `undefined` while it is closed. */
  body: string | undefined
  loading: boolean
  copied: boolean
  onShow: () => void
  onHide: () => void
  onCopy: () => void
}) {
  const shown = body !== undefined
  // A removal holds no version to open: it is the commit *before* it that has
  // the last one, which is why a removal is listed rather than hidden.
  const removed = revision.change === 'removed'

  return (
    <li
      className={`rounded-row border border-transparent px-2.5 py-2 transition-colors duration-150 ${
        shown ? 'border-accent-line bg-exposed' : 'hover:bg-raised'
      }`}
    >
      <div className="flex items-start gap-2.5">
        <HistoryIcon className="mt-0.5 size-3.5 shrink-0 text-ink-faint" />

        <div className="min-w-0 flex-1">
          <p className="text-xs leading-snug break-words text-ink">{revision.summary}</p>
          <p className="mt-0.5 text-xs text-ink-faint">
            <ChangeLabel kind={revision.change} /> · {revision.author} ·{' '}
            <time dateTime={new Date(revision.committedAt * 1000).toISOString()}>
              {when(revision.committedAt)}
            </time>
          </p>
        </div>

        <div className="flex shrink-0 gap-1.5">
          {!removed && (
            <>
              <SmallButton
                onClick={onCopy}
                label={`Copy the password this version held, from ${when(revision.committedAt)}`}
                warm={copied}
              >
                {copied ? <CheckIcon className="size-3.5" /> : <CopyIcon className="size-3.5" />}
                Copy
              </SmallButton>
              <SmallButton
                onClick={shown ? onHide : onShow}
                label={
                  shown
                    ? 'Hide this version'
                    : 'Open this version, which decrypts it and may ask for your passphrase'
                }
              >
                {shown ? <EyeOffIcon className="size-3.5" /> : <EyeIcon className="size-3.5" />}
                {loading ? 'Opening…' : shown ? 'Hide' : 'Open'}
              </SmallButton>
            </>
          )}
        </div>
      </div>

      {shown && (
        // The whole body, as the editor shows it and for the same reason
        // (ADR-10). `select-text` opts back in past the global rule, so the one
        // line the user came for can be lifted out.
        <pre className="mt-2 max-h-48 overflow-auto rounded-row border border-accent-line/60 px-2.5 py-2 font-mono text-xs leading-relaxed break-all whitespace-pre-wrap select-text text-accent-ink">
          {body}
        </pre>
      )}
    </li>
  )
}

/** What the commit did, in a word the user does not have to know git for. */
function ChangeLabel({ kind }: { kind: Revision['change'] }) {
  const label = kind === 'added' ? 'Created' : kind === 'removed' ? 'Deleted' : 'Changed'
  return <span>{label}</span>
}

function SmallButton({
  onClick,
  label,
  warm,
  children,
}: {
  onClick: () => void
  /** The accessible name: the visible words repeat on every row and name nothing. */
  label: string
  warm?: boolean
  children: React.ReactNode
}) {
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      className={`inline-flex items-center gap-1.5 rounded-row border px-2 py-1 text-xs font-medium transition-colors duration-100 ${
        warm
          ? 'border-accent-line bg-accent-soft text-accent-ink'
          : 'border-line-strong/45 text-ink-muted hover:border-line-strong hover:bg-raised hover:text-ink'
      }`}
      onClick={onClick}
    >
      {children}
    </button>
  )
}

/**
 * When a version was written, in the reader's own locale.
 *
 * The core sends Unix seconds precisely so this decision is made here, where
 * the time zone and the language are known and it does not.
 */
function when(unixSeconds: number): string {
  return new Date(unixSeconds * 1000).toLocaleString(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  })
}
