import { useEffect, useState } from 'react'
import {
  revealField,
  revealNotes,
  revealPassword,
  showEntry,
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
 * Each reveal is its own decrypt in the core. Phase 1 caches nothing, so there
 * is no plaintext here between renders and none in the core between commands.
 */
type Props = {
  name: string
}

/** Which value a revealed string belongs to. */
type Slot = 'password' | 'notes' | `field:${number}`

export function EntryDetail({ name }: Props) {
  const [metadata, setMetadata] = useState<EntryMetadata | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [revealed, setRevealed] = useState<Partial<Record<Slot, string>>>({})

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
            onReveal={() => reveal('password', () => revealPassword(name))}
            onHide={() => hide('password')}
          />

          {metadata.fields.map((key, index) => {
            const slot: Slot = `field:${index}`
            return (
              // Keys may repeat, so the index is the field's identity — both
              // for React and for the reveal command.
              <SecretRow
                key={slot}
                label={key}
                value={revealed[slot]}
                onReveal={() => reveal(slot, () => revealField(name, index))}
                onHide={() => hide(slot)}
              />
            )
          })}

          {metadata.hasNotes && (
            <SecretRow
              label="Notes"
              value={revealed.notes}
              multiline
              onReveal={() => reveal('notes', () => revealNotes(name))}
              onHide={() => hide('notes')}
            />
          )}

          {metadata.hasOtp && (
            <div className="flex items-center gap-2 border-t border-neutral-200 pt-2 text-xs text-neutral-500 dark:border-neutral-800">
              <span className="rounded bg-neutral-200 px-1.5 py-0.5 font-medium dark:bg-neutral-800">
                TOTP
              </span>
              {/* The URI embeds the shared seed, so it has no reveal. Phase 2
                  computes the code in the core and sends only the code. */}
              <span>This entry has a one-time-password source (Phase 2).</span>
            </div>
          )}
        </dl>
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
  onReveal: () => void
  onHide: () => void
}

function SecretRow({ label, value, empty, multiline, onReveal, onHide }: SecretRowProps) {
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
          <span
            className={`select-text break-all ${multiline ? 'whitespace-pre-wrap' : ''}`}
          >
            {value}
          </span>
        ) : (
          <span aria-label="hidden" className="text-neutral-400">
            ••••••••••••
          </span>
        )}
      </dd>
      {!empty && (
        <button
          type="button"
          className="rounded border border-neutral-300 px-2 py-0.5 text-xs hover:bg-neutral-100 dark:border-neutral-700 dark:hover:bg-neutral-800"
          onClick={shown ? onHide : onReveal}
        >
          {shown ? 'Hide' : 'Reveal'}
        </button>
      )}
    </div>
  )
}
