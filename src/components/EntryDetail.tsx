import { useCallback, useEffect, useRef, useState } from 'react'
import { useNow } from '../hooks/useNow'
import {
  clearClipboard,
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
 * One entry: its shape by default, its values only when asked for.
 *
 * The secret hygiene rule for this component (CLAUDE.md, Frontend): a revealed
 * value lives in `revealed` for as long as it is on screen and no longer. Two
 * things enforce that — hiding deletes the slot, and the parent mounts this
 * with `key={name}`, so selecting another entry unmounts the component and
 * takes every revealed value with it rather than carrying it across.
 *
 * Copying is the path that avoids all of that: `copy*` puts the value on the
 * clipboard from inside the core, so a copied password is never in this
 * component at all. That is why every row has a Copy next to its Reveal, and
 * why copying an OTP works without ever showing one.
 *
 * Each reveal and each copy is its own decrypt in the core. Nothing is cached,
 * so there is no plaintext here between renders and none in the core between
 * commands.
 */
type Props = {
  name: string
}

/** Which value a revealed string belongs to. */
type Slot = 'password' | 'notes' | `field:${number}`

/** What can be on the clipboard. The OTP has no reveal, but it does copy. */
type CopySlot = Slot | 'otp'

/** What we put on the clipboard, and when the core will wipe it. */
type Clipped = {
  slot: CopySlot
  label: string
  clearsAt: number
}

export function EntryDetail({ name }: Props) {
  const [metadata, setMetadata] = useState<EntryMetadata | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [revealed, setRevealed] = useState<Partial<Record<Slot, string>>>({})
  const [clipped, setClipped] = useState<Clipped | null>(null)

  // Only ticks while there is a clipboard window to count down.
  const now = useNow(clipped ? 500 : null)
  const pending = clipped && now < clipped.clearsAt ? clipped : null

  useEffect(() => {
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
  }, [name])

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
      setClipped({ slot, label, clearsAt: Date.now() + receipt.clearsInSecs * 1000 })
    } catch (e: unknown) {
      setError(String(e))
    }
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
    <section className="flex h-full flex-col overflow-y-auto p-6">
      <header className="mb-4">
        <h2 className="font-mono text-lg font-semibold break-all">{name}</h2>
      </header>

      {error && (
        <p className="mb-4 rounded border border-red-300 bg-red-50 px-3 py-2 text-xs text-red-700 dark:border-red-900 dark:bg-red-950 dark:text-red-300">
          {error}
        </p>
      )}

      {!metadata && !error && <p className="text-xs text-neutral-500">Decrypting…</p>}

      {metadata && (
        <dl className="space-y-1">
          <SecretRow
            label="Password"
            value={revealed.password}
            empty={!metadata.hasPassword}
            copied={pending?.slot === 'password'}
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
                copied={pending?.slot === slot}
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
              copied={pending?.slot === 'notes'}
              onReveal={() => reveal('notes', () => revealNotes(name))}
              onHide={() => hide('notes')}
              onCopy={() => copy('notes', 'Notes', () => copyNotes(name))}
            />
          )}

          {metadata.hasOtp && (
            <OtpRow
              name={name}
              copied={pending?.slot === 'otp'}
              onError={setError}
              onCopy={() => copy('otp', 'One-time password', () => copyOtp(name))}
            />
          )}
        </dl>
      )}

      {pending && (
        <ClipboardNotice
          label={pending.label}
          secondsLeft={Math.max(0, Math.ceil((pending.clearsAt - now) / 1000))}
          onClear={clearNow}
        />
      )}
    </section>
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
    <div className="grid grid-cols-[10rem_1fr_auto] items-start gap-3 border-t border-neutral-200 py-2 dark:border-neutral-800">
      <dt className="truncate pt-0.5 text-sm text-neutral-500" title={label}>
        {label}
      </dt>
      <dd className="min-w-0 font-mono text-sm">
        {empty ? (
          <span className="text-neutral-400 italic">empty</span>
        ) : shown ? (
          // `select-text` opts back in: the global rule turns selection off so
          // a stray drag cannot lift a secret out of the window.
          <span className={`select-text break-all ${multiline ? 'whitespace-pre-wrap' : ''}`}>
            {value}
          </span>
        ) : (
          <span aria-label="hidden" className="text-neutral-400">
            ••••••••••••
          </span>
        )}
      </dd>
      {!empty && (
        <div className="flex gap-1">
          {/* Copy before Reveal: copying never puts the value on screen or in
              this component, so it is the safer of the two to reach for. */}
          <RowButton onClick={onCopy}>{copied ? 'Copied' : 'Copy'}</RowButton>
          <RowButton onClick={shown ? onHide : onReveal}>{shown ? 'Hide' : 'Reveal'}</RowButton>
        </div>
      )}
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
  const [code, setCode] = useState<{ digits: string; expiresAt: number } | null>(null)
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
      setCode({ digits: next.code, expiresAt: Date.now() + next.validForSecs * 1000 })
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
    <div className="grid grid-cols-[10rem_1fr_auto] items-start gap-3 border-t border-neutral-200 py-2 dark:border-neutral-800">
      <dt className="truncate pt-0.5 text-sm text-neutral-500">One-time password</dt>
      <dd className="flex min-w-0 items-center gap-2 font-mono text-sm">
        {code ? (
          <>
            <span className="select-text tracking-[0.2em]">{code.digits}</span>
            <span
              className="text-xs text-neutral-500 tabular-nums"
              title="Seconds until this code expires"
            >
              {secondsLeft}s
            </span>
          </>
        ) : (
          <span aria-label="hidden" className="text-neutral-400">
            ••••••
          </span>
        )}
      </dd>
      <div className="flex gap-1">
        <RowButton onClick={onCopy}>{copied ? 'Copied' : 'Copy'}</RowButton>
        <RowButton onClick={code ? () => setCode(null) : () => void load()}>
          {code ? 'Hide' : 'Show'}
        </RowButton>
      </div>
    </div>
  )
}

type ClipboardNoticeProps = {
  label: string
  secondsLeft: number
  onClear: () => void
}

/** What is on the clipboard and how long the core will leave it there. */
function ClipboardNotice({ label, secondsLeft, onClear }: ClipboardNoticeProps) {
  return (
    <p className="mt-4 flex items-center gap-3 rounded border border-neutral-200 bg-neutral-50 px-3 py-2 text-xs text-neutral-600 dark:border-neutral-800 dark:bg-neutral-800/40 dark:text-neutral-400">
      <span className="flex-1">
        {label} copied — clipboard clears in <span className="tabular-nums">{secondsLeft}s</span>
      </span>
      <RowButton onClick={onClear}>Clear now</RowButton>
    </p>
  )
}

function RowButton({ onClick, children }: { onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      type="button"
      className="rounded border border-neutral-300 px-2 py-0.5 text-xs hover:bg-neutral-100 dark:border-neutral-700 dark:hover:bg-neutral-800"
      onClick={onClick}
    >
      {children}
    </button>
  )
}
