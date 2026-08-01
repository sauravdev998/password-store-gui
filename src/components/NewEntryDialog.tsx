import { useEffect, useState } from 'react'
import { Actions, Dialog, Field, FormError, inputClass } from './Dialog'
import { EyeIcon, EyeOffIcon } from '../lib/icons'
import {
  generateDefaults,
  generateEntry,
  insertEntry,
  type Recipe,
  type WriteReceipt,
} from '../lib/commands'

/**
 * Creating an entry.
 *
 * The default is a generated password, and that default is the recommendation:
 * the core makes it, writes it, and puts it on the clipboard without it ever
 * being rendered or crossing into this component. Typing one is the other
 * branch, and the value the user types lives in this component's state for as
 * long as the form is open and no longer — the dialog is unmounted on close,
 * which is what takes it away.
 *
 * The vocabulary here is deliberately not `pass`'s. The primary user chose this
 * format but does not use the CLI (`PLAN.md` §1), so the form says what a line
 * *does* rather than what the format calls it.
 */
type Props = {
  /** Prefilled folder, so adding beside the selected entry needs no typing. */
  folder: string
  onCancel: () => void
  onCreated: (name: string, receipt: WriteReceipt, generated: boolean) => void
}

/** Where the password comes from. */
type Source = 'generate' | 'typed'

export function NewEntryDialog({ folder, onCancel, onCreated }: Props) {
  const [name, setName] = useState(folder)
  const [source, setSource] = useState<Source>('generate')
  const [password, setPassword] = useState('')
  const [shown, setShown] = useState(false)
  const [recipe, setRecipe] = useState<Recipe>({ length: 25, symbols: true })
  const [rest, setRest] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  // The core owns the defaults, including `PASSWORD_STORE_GENERATED_LENGTH` —
  // a store's settings should not be re-guessed here.
  useEffect(() => {
    let cancelled = false
    generateDefaults()
      .then((defaults) => {
        if (!cancelled) setRecipe(defaults)
      })
      .catch(() => {
        // The fallback above is `pass`'s own default; a failed probe is not
        // worth an error in front of someone who has not typed anything yet.
      })
    return () => {
      cancelled = true
    }
  }, [])

  const trimmedName = name.trim()
  const ready = trimmedName !== '' && !trimmedName.endsWith('/') && (source === 'generate' || password !== '')

  async function submit(event: React.FormEvent) {
    event.preventDefault()
    if (!ready || busy) return
    setBusy(true)
    setError(null)
    try {
      const extra = body(rest)
      // The password is the first line; whatever `body` kept follows it, and it
      // already ends in the newline `pass` would have written.
      const typed = extra === null ? `${password}\n` : `${password}\n${extra}`
      const receipt =
        source === 'generate'
          ? await generateEntry(trimmedName, recipe, extra)
          : await insertEntry(trimmedName, typed)
      onCreated(trimmedName, receipt, source === 'generate')
    } catch (e: unknown) {
      setError(String(e))
      setBusy(false)
    }
  }

  return (
    <Dialog
      title="New entry"
      description="It is encrypted with the same keys as everything else in its folder."
      onClose={onCancel}
    >
      <form onSubmit={submit}>
        <div className="max-h-[60vh] space-y-4 overflow-y-auto px-5 py-4">
          <Field
            label="Name"
            hint={
              <>
                Slashes make folders — <code className="font-mono">Email/gmail.com</code> goes in
                an Email folder.
              </>
            }
          >
            {({ id, describedBy }) => (
              <input
                id={id}
                aria-describedby={describedBy}
                autoFocus
                value={name}
                spellCheck={false}
                autoCapitalize="off"
                autoCorrect="off"
                placeholder="Email/gmail.com"
                className={`${inputClass} font-mono`}
                onChange={(event) => setName(event.target.value)}
              />
            )}
          </Field>

          <fieldset>
            <legend className="text-xs font-medium text-ink">Password</legend>
            <div className="mt-1.5 flex gap-1.5">
              <SourceTab
                active={source === 'generate'}
                onSelect={() => setSource('generate')}
                label="Generate one"
              />
              <SourceTab
                active={source === 'typed'}
                onSelect={() => setSource('typed')}
                label="Type my own"
              />
            </div>

            {source === 'generate' ? (
              <div className="mt-3 space-y-2.5">
                <div className="flex items-center gap-3">
                  <label htmlFor="new-length" className="text-xs text-ink-muted">
                    Length
                  </label>
                  <input
                    id="new-length"
                    type="number"
                    min={8}
                    max={256}
                    value={recipe.length}
                    className={`${inputClass} w-24 tabular-nums`}
                    onChange={(event) =>
                      setRecipe((prev) => ({ ...prev, length: Number(event.target.value) }))
                    }
                  />
                  <label className="flex cursor-pointer items-center gap-2 text-xs text-ink-muted select-none">
                    <input
                      type="checkbox"
                      checked={recipe.symbols}
                      className="size-3.5 accent-[var(--c-accent)]"
                      onChange={(event) =>
                        setRecipe((prev) => ({ ...prev, symbols: event.target.checked }))
                      }
                    />
                    Include punctuation
                  </label>
                </div>
                {/* Said before the fact, because a password that is never shown
                    and lands silently on the clipboard is surprising otherwise. */}
                <p className="text-xs leading-relaxed text-ink-muted">
                  The password is made and copied to your clipboard without being shown. Reveal it
                  from the entry afterwards if you need to see it.
                </p>
              </div>
            ) : (
              <div className="mt-3">
                <div className="flex gap-1.5">
                  <input
                    type={shown ? 'text' : 'password'}
                    value={password}
                    spellCheck={false}
                    autoComplete="off"
                    aria-label="Password"
                    className={`${inputClass} font-mono`}
                    onChange={(event) => setPassword(event.target.value)}
                  />
                  <button
                    type="button"
                    aria-label={shown ? 'Hide password' : 'Show password'}
                    title={shown ? 'Hide password' : 'Show password'}
                    className="shrink-0 rounded-row border border-line-strong/45 px-2 text-ink-muted transition-colors hover:border-line-strong hover:bg-raised hover:text-ink"
                    onClick={() => setShown((prev) => !prev)}
                  >
                    {shown ? <EyeOffIcon className="size-3.5" /> : <EyeIcon className="size-3.5" />}
                  </button>
                </div>
              </div>
            )}
          </fieldset>

          <Field
            label="Anything else"
            hint={
              <>
                Optional. A line like <code className="font-mono">user: alice</code> becomes a
                field; an <code className="font-mono">otpauth://</code> line becomes a one-time
                password. Everything else is kept as notes.
              </>
            }
          >
            {({ id, describedBy }) => (
              <textarea
                id={id}
                aria-describedby={describedBy}
                rows={4}
                value={rest}
                spellCheck={false}
                className={`${inputClass} resize-y font-mono`}
                onChange={(event) => setRest(event.target.value)}
              />
            )}
          </Field>

          {error && <FormError message={error} />}
        </div>

        <Actions busy={busy} disabled={!ready} submitLabel="Create entry" onCancel={onCancel} />
      </form>
    </Dialog>
  )
}

function SourceTab({
  active,
  label,
  onSelect,
}: {
  active: boolean
  label: string
  onSelect: () => void
}) {
  return (
    <button
      type="button"
      aria-pressed={active}
      className={`rounded-row border px-2.5 py-1 text-xs font-medium transition-colors duration-100 ${
        active
          ? 'border-line-strong bg-raised text-ink'
          : 'border-transparent text-ink-muted hover:bg-raised hover:text-ink'
      }`}
      onClick={onSelect}
    >
      {label}
    </button>
  )
}

/**
 * Normalise the free-text half of the form.
 *
 * A trailing newline is what `pass` writes and what every other client expects
 * to read, so the file we produce should not be distinguishable from theirs by
 * its last byte. Empty stays empty rather than becoming a blank line.
 */
function body(text: string): string | null {
  const trimmed = text.replace(/\s+$/, '')
  return trimmed === '' ? null : `${trimmed}\n`
}
