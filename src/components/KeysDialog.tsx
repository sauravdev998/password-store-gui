import { useCallback, useEffect, useState } from 'react'
import { Actions, Dialog, FormError, inputClass } from './Dialog'
import { AlertIcon, CheckIcon, PlusIcon, TrashIcon } from '../lib/icons'
import {
  folderKeys,
  planRecipients,
  setRecipients,
  type FolderKeys,
  type KeyInfo,
  type RecipientPlan,
  type WriteReceipt,
} from '../lib/commands'

/**
 * Which keys can open a folder's entries, and changing them.
 *
 * Invariant 8's second half: changing the keys means every entry they govern is
 * decrypted and encrypted again, which is the most expensive thing this app
 * does and the only one that can lock a user out of their own store. So the
 * dialog is built around saying what will happen *before* it happens — the
 * count comes from the core, which works it out without decrypting anything, so
 * showing it costs nothing (§4.1 principle 1).
 *
 * **Vocabulary** (Open Decision 6): the format's words do not appear. There are
 * no "recipients" and no `.gpg-id` here — there are keys, and folders they
 * apply to. The one thing shown verbatim is the key id itself, because that is
 * the string the user needs if they go looking outside the app, which is the
 * test that decision sets.
 */
type Props = {
  /** The folder whose keys these are. `null` is the store root. */
  folder: string | null
  /** Whether the store keeps a history, for the caveat on removing a key. */
  versioned: boolean
  onCancel: () => void
  onSaved: (receipt: WriteReceipt, summary: string) => void
}

/** How the folder is named in prose. */
function label(folder: string | null): string {
  return folder ? `the ${folder} folder` : 'this store'
}

/** Fold newly resolved keys into what is already known about them. */
function remember(seen: Record<string, KeyInfo>, keys: KeyInfo[]): Record<string, KeyInfo> {
  const next = { ...seen }
  for (const key of keys) next[key.id] = key
  return next
}

export function KeysDialog({ folder, versioned, onCancel, onSaved }: Props) {
  const [current, setCurrent] = useState<FolderKeys | null>(null)
  const [ids, setIds] = useState<string[]>([])
  const [plan, setPlan] = useState<RecipientPlan | null>(null)
  /**
   * Every key description seen so far, kept once resolved.
   *
   * A plan is dropped when one key in the list cannot be resolved, and without
   * this the *other* keys would fall back to their bare ids at exactly the
   * moment the user is trying to work out which row to take back out.
   */
  const [known, setKnown] = useState<Record<string, KeyInfo>>({})
  const [draft, setDraft] = useState('')
  /** A failure of this dialog's own doing: loading, or saving. Always shown. */
  const [error, setError] = useState<string | null>(null)
  /**
   * Why the pending list cannot be saved. Shown only once saving is a thing the
   * user is actually trying to do.
   *
   * A store may already list a key this machine has never seen — the ordinary
   * state of one shared with someone else — and planning that list fails every
   * time. Showing it on open would greet a user who came to *look* with a red
   * error about a store that is working exactly as intended. The row itself
   * already says the key is not on the keyring, which is the true and calm
   * version of the same fact.
   */
  const [planError, setPlanError] = useState<string | null>(null)
  const [planning, setPlanning] = useState(false)
  const [busy, setBusy] = useState(false)

  // What is in force now. Decrypts nothing, so opening this costs no prompt.
  useEffect(() => {
    let live = true
    folderKeys(folder)
      .then((keys) => {
        if (!live) return
        setCurrent(keys)
        setIds(keys.keys.map((key) => key.id))
        setKnown((seen) => remember(seen, keys.keys))
      })
      .catch((e: unknown) => live && setError(String(e)))
    return () => {
      live = false
    }
  }, [folder])

  // What the pending list would cost. Recomputed on every add and remove
  // rather than on a timer: the list only changes when the user changes it.
  useEffect(() => {
    if (ids.length === 0) {
      setPlan(null)
      return
    }
    let live = true
    setPlanning(true)
    planRecipients(folder, ids)
      .then((next) => {
        if (!live) return
        setPlan(next)
        setPlanError(null)
        setKnown((seen) => remember(seen, next.keys))
      })
      // A key that cannot be resolved is a refusal, not a crash: it is shown
      // where the keys are so the user can take the bad one back out.
      .catch((e: unknown) => {
        if (!live) return
        setPlan(null)
        setPlanError(String(e))
      })
      .finally(() => live && setPlanning(false))
    return () => {
      live = false
    }
  }, [folder, ids])

  const add = useCallback(() => {
    const id = draft.trim()
    if (!id || ids.includes(id)) return
    setError(null)
    setIds((previous) => [...previous, id])
    setDraft('')
  }, [draft, ids])

  function remove(id: string) {
    setError(null)
    setIds((previous) => previous.filter((other) => other !== id))
  }

  async function submit(event: React.FormEvent) {
    event.preventDefault()
    if (busy || !plan) return
    setBusy(true)
    setError(null)
    try {
      const receipt = await setRecipients(folder, ids)
      onSaved(receipt, `The keys for ${label(folder)} were changed`)
    } catch (e: unknown) {
      setError(String(e))
      setBusy(false)
    }
  }

  const existing = current?.keys.map((key) => key.id) ?? []
  const changed = ids.join('\n') !== existing.join('\n')
  const removing = existing.filter((id) => !ids.includes(id))
  /**
   * Whether there is anything to save — and so whether the user is trying to
   * write rather than only looking.
   *
   * Pinning inherited keys to this folder counts even when the list is
   * identical: it stops the folder following the one above it. It is also what
   * decides whether a refused plan is worth showing, since a store that already
   * lists a key this machine does not have is not a problem until someone tries
   * to write to it.
   */
  const attempting = changed || (current?.inherited ?? false)
  const savable = plan !== null && attempting

  return (
    <Dialog
      title={folder ? `Keys for ${folder}` : 'Keys for this store'}
      description="Entries here are encrypted so that only these keys can open them. Changing the list rewrites every entry it covers."
      onClose={onCancel}
    >
      <form onSubmit={submit}>
        <div className="max-h-[min(28rem,60vh)] space-y-3.5 overflow-y-auto px-5 py-4">
          {current?.inherited && (
            <Note>
              These keys come from {current.source ? `the ${current.source} folder` : 'this store'},
              and {folder} follows it. Saving here sets keys for {folder} on its own, so it stops
              following.
            </Note>
          )}

          {current && current.keys.length === 0 && (
            <Note>
              No keys are set for this store yet, so nothing here can be encrypted. Add the key you
              want your entries protected by.
            </Note>
          )}

          <ul className="space-y-1.5">
            {ids.map((id) => (
              <KeyRow
                key={id}
                id={id}
                info={known[id]}
                isNew={!existing.includes(id)}
                // The last key cannot be taken away: a store with no keys can
                // encrypt nothing, and the core refuses it anyway.
                onRemove={ids.length > 1 ? () => remove(id) : undefined}
              />
            ))}
          </ul>

          <div className="flex gap-2">
            <input
              value={draft}
              onChange={(event) => setDraft(event.target.value)}
              // Enter adds a key rather than submitting the form, which would
              // otherwise apply a change the user was still assembling.
              onKeyDown={(event) => {
                if (event.key === 'Enter') {
                  event.preventDefault()
                  add()
                }
              }}
              placeholder="Email address, key id, or fingerprint"
              aria-label="Add a key"
              className={inputClass}
            />
            <button
              type="button"
              onClick={add}
              disabled={!draft.trim()}
              className="flex shrink-0 items-center gap-1 rounded-row border border-line-strong/45 px-2.5 text-xs font-medium text-ink-muted transition-colors hover:border-line-strong hover:bg-raised hover:text-ink disabled:cursor-not-allowed disabled:opacity-55"
            >
              <PlusIcon className="size-3.5" />
              Add
            </button>
          </div>

          {plan?.locksYouOut && (
            <Warning>
              <strong className="font-semibold">None of these keys is yours.</strong> Saving this
              would leave you unable to open{' '}
              {plan.reencrypts.length + plan.unchanged === 1
                ? 'the entry'
                : `all ${plan.reencrypts.length + plan.unchanged} entries`}{' '}
              here, and there would be no way back from inside this app.
            </Warning>
          )}

          {removing.length > 0 && versioned && (
            <Warning>
              Removing a key does not take away what it could already read. Your store's history
              still holds earlier copies of these entries encrypted to it, and so does any copy of
              the store someone already has. Treat those passwords as known and change them.
            </Warning>
          )}

          {/* Shown whenever there is something to save, not only when the list
              changed: pinning inherited keys to this folder rewrites nothing
              but does split it off from the folder above, and that is the one
              sentence explaining it. */}
          {plan && savable && <Cost plan={plan} busy={planning} />}

          {error && <FormError message={error} />}
          {planError && attempting && <FormError message={planError} />}
        </div>

        <Actions
          busy={busy}
          disabled={!savable || planning || plan?.locksYouOut}
          submitLabel={
            plan && plan.reencrypts.length > 0
              ? `Change keys and rewrite ${plan.reencrypts.length}`
              : 'Change keys'
          }
          onCancel={onCancel}
        />
      </form>
    </Dialog>
  )
}

/**
 * One key: what it is, and whether it is the user's own.
 *
 * The id is shown verbatim under the label because it is the string the store
 * holds and the one that identifies the key anywhere else. The label is a
 * convenience on top of it, not a replacement for it.
 */
function KeyRow({
  id,
  info,
  isNew,
  onRemove,
}: {
  id: string
  info: KeyInfo | undefined
  isNew: boolean
  onRemove?: () => void
}) {
  return (
    <li className="flex items-start gap-2.5 rounded-row border border-line bg-raised/60 px-2.5 py-2">
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-1.5">
          <span className="truncate text-xs font-medium text-ink">{info?.label ?? id}</span>
          {info?.usableHere && (
            <span className="flex shrink-0 items-center gap-0.5 rounded-full bg-accent/12 px-1.5 py-px text-[10px] font-medium text-accent">
              <CheckIcon className="size-2.5" />
              Yours
            </span>
          )}
          {isNew && (
            <span className="shrink-0 rounded-full border border-line-strong/45 px-1.5 py-px text-[10px] font-medium text-ink-faint">
              Adding
            </span>
          )}
        </div>
        {/* The id as the store spells it, always — a label that happens to
            match is not the same string, and this is the one the user needs
            outside the app. */}
        <p className="mt-0.5 truncate font-mono text-[11px] text-ink-faint" title={id}>
          {id}
        </p>
        {info && !info.usableHere && !info.label && (
          <p className="mt-1 text-[11px] leading-relaxed text-ink-muted">
            This key is not on your keyring, so entries cannot be encrypted to it until you import
            it.
          </p>
        )}
      </div>
      {onRemove && (
        <button
          type="button"
          aria-label={`Remove ${id}`}
          title="Remove"
          className="-mr-0.5 shrink-0 rounded-row p-1 text-ink-faint transition-colors hover:bg-danger-soft hover:text-danger-ink"
          onClick={onRemove}
        >
          <TrashIcon className="size-3.5" />
        </button>
      )}
    </li>
  )
}

/**
 * What the change will actually cost, before it is agreed to.
 *
 * The number is exact rather than an estimate: the core reads which keys each
 * entry is already encrypted to out of the file's headers, which needs no key
 * and decrypts nothing. Entries already readable by exactly these keys are left
 * alone, so adding a key that is already there says so instead of rewriting the
 * store.
 */
function Cost({ plan, busy }: { plan: RecipientPlan; busy: boolean }) {
  const count = plan.reencrypts.length

  return (
    <div
      aria-live="polite"
      className={`rounded-panel border border-line bg-raised/60 px-3 py-2.5 text-xs leading-relaxed text-ink-muted ${
        busy ? 'opacity-60' : ''
      }`}
    >
      {count === 0 ? (
        <p>
          Nothing needs rewriting — {plan.unchanged === 1 ? 'the entry' : 'every entry'} here can
          already be opened by exactly these keys.
        </p>
      ) : (
        <>
          <p>
            <strong className="font-semibold text-ink">
              {count === 1 ? '1 entry' : `${count} entries`}
            </strong>{' '}
            will be opened and encrypted again.
            {plan.unchanged > 0 && ` ${plan.unchanged} already match and will be left alone.`}
          </p>
          {/* Said before the button is pressed, not after: this is exactly the
              prompt §4.1 principle 1 says must never be a surprise. */}
          <p className="mt-1.5">
            Your system may ask for your passphrase, or your security key may need a touch.
          </p>
          <ul className="mt-1.5 space-y-0.5 font-mono text-[11px] text-ink-faint">
            {plan.reencrypts.slice(0, 6).map((name) => (
              <li key={name} className="truncate">
                {name}
              </li>
            ))}
            {count > 6 && <li className="font-sans">and {count - 6} more</li>}
          </ul>
        </>
      )}
      {plan.createsBoundary && (
        <p className="mt-1.5">
          This folder will keep its own keys from now on, instead of following the one above it.
        </p>
      )}
    </div>
  )
}

/** A neutral aside: something true about the situation, not a problem. */
function Note({ children }: { children: React.ReactNode }) {
  return (
    <p className="rounded-panel border border-line bg-raised/60 px-3 py-2.5 text-xs leading-relaxed text-ink-muted">
      {children}
    </p>
  )
}

/** Something the user would regret not reading. */
function Warning({ children }: { children: React.ReactNode }) {
  return (
    <div
      role="alert"
      className="flex items-start gap-2.5 rounded-panel border border-danger-line bg-danger-soft px-3 py-2.5 text-xs leading-relaxed text-danger-ink"
    >
      <AlertIcon className="mt-px size-3.5 shrink-0" />
      <span className="min-w-0">{children}</span>
    </div>
  )
}
