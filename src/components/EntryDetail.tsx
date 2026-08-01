import { useCallback, useEffect, useRef, useState } from 'react'
import { useNow } from '../hooks/useNow'
import type { Clipped, CopySlot } from './ClipboardNotice'
import {
  AlertIcon,
  CheckIcon,
  CopyIcon,
  DuplicateIcon,
  EyeIcon,
  EyeOffIcon,
  HistoryIcon,
  LockIcon,
  MoveIcon,
  PencilIcon,
  TrashIcon,
} from '../lib/icons'
import {
  copyField,
  copyNotes,
  copyOtp,
  copyPassword,
  otpCode,
  revealField,
  revealNotes,
  revealPassword,
  showEntry,
  type CopyReceipt,
  type EntryMetadata,
} from '../lib/commands'

/**
 * One entry: its shape only once asked for, its values one at a time.
 *
 * The secret hygiene rule for this component (CLAUDE.md, Frontend): a revealed
 * value lives in `revealed` for as long as it is on screen and no longer. Two
 * things enforce that — hiding deletes the slot, and the parent mounts this
 * with a key that includes the entry name, so selecting another entry unmounts
 * the component and takes every revealed value with it rather than carrying it
 * across.
 *
 * Copying is the path that avoids all of that: `copy*` puts the value on the
 * clipboard from inside the core, so a copied password is never in this
 * component at all. That is why every row has a Copy next to its Reveal, and
 * why copying an OTP works without ever showing one. What is on the clipboard
 * is the window's business rather than this pane's, so the notice for it lives
 * in `App`; this component only reports what it copied.
 *
 * **Nothing decrypts on arrival.** `show_entry` returns shape rather than
 * content, but it still has to run GnuPG to learn it — which can put a
 * passphrase dialog on screen or set a security key blinking. Doing that
 * because someone clicked a row would be the app spending the user's attention
 * on a question they did not ask. So the pane arrives locked and the first
 * decrypt is a deliberate act, unless the user has said otherwise.
 *
 * Each reveal and each copy is its own decrypt in the core. Nothing is cached,
 * so there is no plaintext here between renders and none in the core between
 * commands.
 */
type Props = {
  name: string
  /** Skip the locked state: the user has said selecting is enough. */
  autoOpen: boolean
  onAutoOpenChange: (next: boolean) => void
  /** What the window believes is on the clipboard, so a row can say "Copied". */
  clipped: Clipped | null
  onCopied: (next: Clipped) => void
  onEdit: () => void
  /** Absent when the store keeps no history, so there is nothing to show. */
  onHistory?: () => void
  onRename: () => void
  onDuplicate: () => void
  onDelete: () => void
}

/** Which value a revealed string belongs to. */
type Slot = 'password' | 'notes' | `field:${number}`

export function EntryDetail({
  name,
  autoOpen,
  onAutoOpenChange,
  clipped,
  onCopied,
  onEdit,
  onHistory,
  onRename,
  onDuplicate,
  onDelete,
}: Props) {
  const [opened, setOpened] = useState(autoOpen)
  const [metadata, setMetadata] = useState<EntryMetadata | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [revealed, setRevealed] = useState<Partial<Record<Slot, string>>>({})

  useEffect(() => {
    if (!opened) return
    let cancelled = false
    setError(null)
    showEntry(name)
      .then((next) => {
        if (!cancelled) setMetadata(next)
      })
      .catch((e: unknown) => {
        if (!cancelled) setError(String(e))
      })
    return () => {
      cancelled = true
    }
  }, [name, opened])

  async function reveal(slot: Slot, load: () => Promise<string>) {
    setError(null)
    try {
      const value = await load()
      setRevealed((prev) => ({ ...prev, [slot]: value }))
    } catch (e: unknown) {
      setError(String(e))
    }
  }

  function hide(slot: Slot) {
    setRevealed((prev) => {
      const next = { ...prev }
      delete next[slot]
      return next
    })
  }

  async function copy(slot: CopySlot, label: string, run: () => Promise<CopyReceipt>) {
    setError(null)
    try {
      const receipt = await run()
      // The receipt carries the window, never the value — there is nothing
      // here to hold onto but a deadline.
      const windowMs = receipt.clearsInSecs * 1000
      onCopied({ entry: name, slot, label, clearsAt: Date.now() + windowMs, windowMs })
    } catch (e: unknown) {
      setError(String(e))
    }
  }

  /** Whether `slot` of *this* entry is what the clipboard holds. */
  const isCopied = (slot: CopySlot) => clipped?.entry === name && clipped.slot === slot

  const loading = opened && !metadata && !error

  return (
    <section className="@container flex h-full flex-col">
      <EntryHeading
        name={name}
        onEdit={onEdit}
        onHistory={onHistory}
        onRename={onRename}
        onDuplicate={onDuplicate}
        onDelete={onDelete}
      />

      <div className="flex-1 overflow-y-auto px-6 pt-2 pb-6">
        {error && (
          <div
            role="alert"
            className="mb-5 flex items-start gap-2.5 rounded-panel border border-danger-line bg-danger-soft px-3.5 py-3 text-sm text-danger-ink"
          >
            <AlertIcon className="mt-px size-4 shrink-0" />
            <div className="min-w-0 flex-1">
              <p className="leading-relaxed break-words">{error}</p>
              <button
                type="button"
                className="mt-2 rounded-row border border-danger-line px-2 py-0.5 text-xs font-medium transition-colors hover:bg-danger-line/30"
                onClick={() => {
                  setError(null)
                  setOpened(true)
                  setMetadata(null)
                }}
              >
                Try again
              </button>
            </div>
          </div>
        )}

        {!opened && !error && (
          <LockedPanel
            autoOpen={autoOpen}
            onAutoOpenChange={onAutoOpenChange}
            onUnlock={() => setOpened(true)}
          />
        )}

        {loading && <Decrypting />}

        {metadata && (
          <dl>
            <SecretRow
              label="Password"
              value={revealed.password}
              empty={!metadata.hasPassword}
              copied={isCopied('password')}
              onReveal={() => reveal('password', () => revealPassword(name))}
              onHide={() => hide('password')}
              onCopy={() => copy('password', 'Password', () => copyPassword(name))}
            />

            {metadata.fields.map((key, index) => {
              const slot: Slot = `field:${index}`
              return (
                // Keys may repeat, so the index is the field's identity — both
                // for React and for the reveal and copy commands.
                <SecretRow
                  key={slot}
                  label={key}
                  value={revealed[slot]}
                  copied={isCopied(slot)}
                  onReveal={() => reveal(slot, () => revealField(name, index))}
                  onHide={() => hide(slot)}
                  onCopy={() => copy(slot, key, () => copyField(name, index))}
                />
              )
            })}

            {metadata.hasNotes && (
              <SecretRow
                label="Notes"
                value={revealed.notes}
                multiline
                copied={isCopied('notes')}
                onReveal={() => reveal('notes', () => revealNotes(name))}
                onHide={() => hide('notes')}
                onCopy={() => copy('notes', 'Notes', () => copyNotes(name))}
              />
            )}

            {metadata.hasOtp && (
              <OtpRow
                name={name}
                copied={isCopied('otp')}
                onError={setError}
                onCopy={() => copy('otp', 'One-time password', () => copyOtp(name))}
              />
            )}
          </dl>
        )}
      </div>
    </section>
  )
}

/**
 * The entry's name, split at the separators, and what can be done to it.
 *
 * A store name like `Email/work/fastmail.com` is a path, and the leaf is what
 * the user came for — so the folders recede and the last segment carries the
 * weight. It also tells them where they are without a second breadcrumb.
 *
 * The actions sit here, beside the name, rather than at the foot of the values:
 * they act on the entry as a whole, and none of them needs the pane to have
 * been unlocked first. Editing decrypts, but it decrypts when it is chosen —
 * which is a request, not a side effect of looking.
 */
function EntryHeading({
  name,
  onEdit,
  onHistory,
  onRename,
  onDuplicate,
  onDelete,
}: {
  name: string
  onEdit: () => void
  onHistory?: () => void
  onRename: () => void
  onDuplicate: () => void
  onDelete: () => void
}) {
  const segments = name.split('/')
  const leaf = segments.pop() ?? name

  return (
    <header className="shrink-0 border-b border-line px-6 pt-5 pb-4">
      <div className="flex items-start gap-4">
        <div className="min-w-0 flex-1">
          {segments.length > 0 && (
            <p className="mb-1 truncate font-mono text-xs text-ink-faint" title={name}>
              {segments.join(' / ')}
            </p>
          )}
          <h2 className="font-mono text-xl leading-tight font-semibold tracking-tight break-all">
            {leaf}
          </h2>
        </div>

        <div className="flex shrink-0 gap-1">
          <HeaderButton label="Edit entry" icon={<PencilIcon className="size-4" />} onClick={onEdit} />
          {onHistory && (
            // Beside the destructive actions on purpose: the history is what
            // makes deleting recoverable, and this is where the user is
            // standing when that matters.
            <HeaderButton
              label="Earlier versions of this entry"
              icon={<HistoryIcon className="size-4" />}
              onClick={onHistory}
            />
          )}
          <HeaderButton label="Rename entry" icon={<MoveIcon className="size-4" />} onClick={onRename} />
          <HeaderButton
            label="Duplicate entry"
            icon={<DuplicateIcon className="size-4" />}
            onClick={onDuplicate}
          />
          <HeaderButton
            label="Delete entry"
            icon={<TrashIcon className="size-4" />}
            danger
            onClick={onDelete}
          />
        </div>
      </div>
    </header>
  )
}

function HeaderButton({
  label,
  icon,
  danger,
  onClick,
}: {
  /** The accessible name; the buttons are icon-only, so this is the only one. */
  label: string
  icon: React.ReactNode
  danger?: boolean
  onClick: () => void
}) {
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      className={`rounded-row p-1.5 transition-colors duration-100 ${
        danger
          ? 'text-ink-faint hover:bg-danger-soft hover:text-danger-ink'
          : 'text-ink-faint hover:bg-raised hover:text-ink'
      }`}
      onClick={onClick}
    >
      {icon}
    </button>
  )
}

/**
 * What the user sees before anything has been decrypted.
 *
 * It says plainly what the next click costs, because the cost is not obvious:
 * the prompt that may appear belongs to the operating system, not to this
 * window, and a security key that starts blinking has no explanation attached
 * to it at all.
 */
function LockedPanel({
  autoOpen,
  onAutoOpenChange,
  onUnlock,
}: {
  autoOpen: boolean
  onAutoOpenChange: (next: boolean) => void
  onUnlock: () => void
}) {
  return (
    <div className="mx-auto mt-10 max-w-md text-center">
      <LockIcon className="mx-auto size-9 text-ink-faint" />
      <h3 className="mt-4 text-base font-semibold text-ink">This entry is locked</h3>
      <p className="mx-auto mt-2 max-w-sm text-sm leading-relaxed text-ink-muted">
        Opening it decrypts the file with GnuPG. Your system may ask for your passphrase, or your
        security key may need a touch.
      </p>

      <div className="mt-6">
        <button
          type="button"
          className="inline-flex items-center gap-2 rounded-row bg-accent px-4 py-2 text-sm font-semibold text-accent-on shadow-lift transition-[filter] duration-150 hover:brightness-105 active:brightness-95"
          onClick={onUnlock}
        >
          <LockIcon className="size-4" open />
          Unlock entry
        </button>
      </div>

      {/* Its own line: turning the lock off for good is a different decision
          from opening this one entry, and should not read as part of the
          button. */}
      <div className="mt-5">
        <label className="inline-flex cursor-pointer items-center gap-2 text-xs text-ink-muted select-none hover:text-ink">
          <input
            type="checkbox"
            checked={autoOpen}
            className="size-3.5 accent-[var(--c-accent)]"
            onChange={(event) => {
              onAutoOpenChange(event.target.checked)
              if (event.target.checked) onUnlock()
            }}
          />
          Open entries as soon as I select them
        </label>
      </div>
    </div>
  )
}

/** The wait. Named honestly, because the prompt may be outside this window. */
function Decrypting() {
  return (
    <div className="mx-auto mt-10 max-w-md text-center">
      <LockIcon className="animate-waiting mx-auto size-9 text-accent" open />
      <p className="mt-4 text-sm font-medium text-ink">Decrypting…</p>
      <p className="mx-auto mt-1 max-w-xs text-xs leading-relaxed text-ink-muted">
        If your key needs a passphrase or a touch, look for a system prompt.
      </p>
    </div>
  )
}

type SecretRowProps = {
  label: string
  /** The revealed plaintext, or `undefined` while it is hidden. */
  value: string | undefined
  /** The core says this value exists but is empty; there is nothing to show. */
  empty?: boolean
  multiline?: boolean
  /** This row's value is the one currently on the clipboard. */
  copied?: boolean
  onReveal: () => void
  onHide: () => void
  onCopy: () => void
}

/**
 * One label/value pair.
 *
 * `dt` plus two `dd`s inside a `div`, which is the shape a definition list
 * allows — the actions belong to the term as much as the value does, and a
 * `div` full of buttons is not a legal child of a `dl`.
 *
 * The row goes warm when its value is on screen. That is the whole colour
 * system in one place: amber is only ever "this is exposed right now".
 */
function SecretRow({
  label,
  value,
  empty,
  multiline,
  copied,
  onReveal,
  onHide,
  onCopy,
}: SecretRowProps) {
  const shown = value !== undefined

  return (
    <div
      className={`grid grid-cols-1 gap-x-4 gap-y-1.5 rounded-row border-t border-line px-3 py-3 transition-colors duration-150 first:border-t-0 @[34rem]:grid-cols-[minmax(6rem,11rem)_1fr_auto] @[34rem]:items-baseline ${
        shown ? 'bg-exposed' : ''
      }`}
    >
      <dt className="flex min-w-0 items-center gap-1.5 text-sm text-ink-muted">
        {shown && (
          <span aria-hidden="true" className="size-1.5 shrink-0 rounded-full bg-accent-ink" />
        )}
        <span className="truncate" title={label}>
          {label}
        </span>
      </dt>

      <dd className="min-w-0 font-mono text-sm">
        {empty ? (
          <span className="text-ink-faint italic">empty</span>
        ) : shown ? (
          // `select-text` opts back in: the global rule turns selection off so
          // a stray drag cannot lift a secret out of the window.
          <span
            className={`select-text break-all text-accent-ink ${multiline ? 'whitespace-pre-wrap' : ''}`}
          >
            {value}
          </span>
        ) : (
          // A fixed run of dots. The count is constant on purpose: a mask that
          // matched the value's length would leak it.
          <span className="tracking-[0.15em] text-ink-faint">
            <span className="sr-only">Hidden</span>
            <span aria-hidden="true">••••••••••••</span>
          </span>
        )}
      </dd>

      <dd className="flex gap-1.5 @[34rem]:justify-end">
        {!empty && (
          <>
            {/* Copy before Reveal: copying never puts the value on screen or in
                this component, so it is the safer of the two to reach for. */}
            <RowButton
              onClick={onCopy}
              label={copied ? `${label} is on the clipboard` : `Copy ${label}`}
              icon={copied ? <CheckIcon className="size-3.5" /> : <CopyIcon className="size-3.5" />}
              warm={copied}
            >
              {copied ? 'Copied' : 'Copy'}
            </RowButton>
            <RowButton
              onClick={shown ? onHide : onReveal}
              label={shown ? `Hide ${label}` : `Reveal ${label}`}
              icon={shown ? <EyeOffIcon className="size-3.5" /> : <EyeIcon className="size-3.5" />}
            >
              {shown ? 'Hide' : 'Reveal'}
            </RowButton>
          </>
        )}
      </dd>
    </div>
  )
}

type OtpRowProps = {
  name: string
  copied?: boolean
  onError: (message: string) => void
  onCopy: () => void
}

/**
 * The one-time password row.
 *
 * Hidden until asked for, like every other value, and for a second reason
 * besides symmetry: showing a code means decrypting the entry, and doing that
 * on selection would pop a pinentry prompt at a user who only clicked an entry
 * to look at it — then again every period, for as long as they left it open.
 *
 * Copy works without showing: `copy_otp` computes the code in the core and puts
 * it straight on the clipboard, so the common case never renders a code at all.
 */
function OtpRow({ name, copied, onError, onCopy }: OtpRowProps) {
  const [code, setCode] = useState<{
    digits: string
    expiresAt: number
    periodSecs: number
  } | null>(null)
  // Guards the refresh below against firing again on every tick while the next
  // code is still in flight.
  const loading = useRef(false)

  const now = useNow(code ? 500 : null)
  const secondsLeft = code ? Math.max(0, Math.ceil((code.expiresAt - now) / 1000)) : 0

  const load = useCallback(async () => {
    if (loading.current) return
    loading.current = true
    try {
      const next = await otpCode(name)
      setCode({
        digits: next.code,
        expiresAt: Date.now() + next.validForSecs * 1000,
        periodSecs: next.periodSecs,
      })
    } catch (e: unknown) {
      onError(String(e))
    } finally {
      loading.current = false
    }
  }, [name, onError])

  // The core reported how long its code lasts; when that runs out, ask it for
  // the next one rather than computing anything here.
  useEffect(() => {
    if (code && now >= code.expiresAt) void load()
  }, [code, now, load])

  return (
    <div
      className={`grid grid-cols-1 gap-x-4 gap-y-1.5 rounded-row border-t border-line px-3 py-3 transition-colors duration-150 first:border-t-0 @[34rem]:grid-cols-[minmax(6rem,11rem)_1fr_auto] @[34rem]:items-baseline ${
        code ? 'bg-exposed' : ''
      }`}
    >
      <dt className="flex min-w-0 items-center gap-1.5 text-sm text-ink-muted">
        {code && (
          <span aria-hidden="true" className="size-1.5 shrink-0 rounded-full bg-accent-ink" />
        )}
        <span className="truncate">One-time password</span>
      </dt>

      <dd className="flex min-w-0 items-center gap-2.5 font-mono text-sm">
        {code ? (
          <>
            <span className="select-text tracking-[0.2em] text-accent-ink tabular-nums">
              {code.digits}
            </span>
            <ExpiryDial secondsLeft={secondsLeft} periodSecs={code.periodSecs} />
          </>
        ) : (
          <span className="tracking-[0.15em] text-ink-faint">
            <span className="sr-only">Hidden</span>
            <span aria-hidden="true">••••••</span>
          </span>
        )}
      </dd>

      <dd className="flex gap-1.5 @[34rem]:justify-end">
        <RowButton
          onClick={onCopy}
          label={copied ? 'The one-time password is on the clipboard' : 'Copy one-time password'}
          icon={copied ? <CheckIcon className="size-3.5" /> : <CopyIcon className="size-3.5" />}
          warm={copied}
        >
          {copied ? 'Copied' : 'Copy'}
        </RowButton>
        <RowButton
          onClick={code ? () => setCode(null) : () => void load()}
          label={code ? 'Hide one-time password' : 'Reveal one-time password'}
          icon={code ? <EyeOffIcon className="size-3.5" /> : <EyeIcon className="size-3.5" />}
        >
          {code ? 'Hide' : 'Reveal'}
        </RowButton>
      </dd>
    </div>
  )
}

/**
 * How much life the current code has left, drawn to scale.
 *
 * `periodSecs` comes back from the core for exactly this — the dial is the
 * period, so a 30-second code and a 60-second one do not deplete at the same
 * apparent rate. The seconds are written out beside it, because a shrinking arc
 * answers "soon?" but not "how long?".
 */
function ExpiryDial({ secondsLeft, periodSecs }: { secondsLeft: number; periodSecs: number }) {
  const radius = 6
  const circumference = 2 * Math.PI * radius
  const fraction = periodSecs > 0 ? Math.max(0, Math.min(1, secondsLeft / periodSecs)) : 0

  return (
    <span className="flex items-center gap-1.5 text-xs text-ink-muted">
      <svg viewBox="0 0 16 16" className="size-3.5 shrink-0 -rotate-90" aria-hidden="true">
        <circle
          cx="8"
          cy="8"
          r={radius}
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          opacity="0.25"
        />
        <circle
          cx="8"
          cy="8"
          r={radius}
          fill="none"
          stroke="var(--c-accent-ink)"
          strokeWidth="2"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={circumference * (1 - fraction)}
        />
      </svg>
      <span className="tabular-nums">
        <span className="sr-only">Expires in </span>
        {secondsLeft}s
      </span>
    </span>
  )
}

function RowButton({
  onClick,
  label,
  icon,
  warm,
  children,
}: {
  onClick: () => void
  /** The accessible name. "Copy" alone repeats on every row and names nothing. */
  label: string
  icon: React.ReactNode
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
      {icon}
      {children}
    </button>
  )
}
