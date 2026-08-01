import { useEffect, useState } from 'react'
import { Actions, Dialog, FormError, inputClass } from './Dialog'
import { LockIcon } from '../lib/icons'
import { editEntry, revealEntry, type WriteReceipt } from '../lib/commands'

/**
 * Editing an entry's whole contents.
 *
 * This is the one place in the app that puts an entire decrypted entry on
 * screen, and the only one that can show an `otpauth://` line — everywhere else
 * a value is revealed singly and a one-time password is computed in the core so
 * its seed never travels. Editing is what earns it: the core replaces the whole
 * body on write, so writing one means having read one. `pass edit` does exactly
 * the same thing by opening the plaintext in `$EDITOR`.
 *
 * The obligation that comes with it is the one this component is built around:
 * the text lives in local state, the dialog is mounted only while open, and
 * closing it unmounts the component and takes the plaintext with it. It is
 * never lifted to a parent, never stored, never put in `localStorage`.
 *
 * Nothing is loaded until the dialog opens, so choosing "Edit" is the decrypt —
 * a pinentry prompt here is one the user asked for (§4.1 principle 1).
 */
type Props = {
  name: string
  onCancel: () => void
  onSaved: (receipt: WriteReceipt) => void
}

export function EditEntryDialog({ name, onCancel, onSaved }: Props) {
  const [body, setBody] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    let cancelled = false
    revealEntry(name)
      .then((text) => {
        if (!cancelled) setBody(text)
      })
      .catch((e: unknown) => {
        if (!cancelled) setError(String(e))
      })
    return () => {
      cancelled = true
    }
  }, [name])

  async function submit(event: React.FormEvent) {
    event.preventDefault()
    if (body === null || busy) return
    setBusy(true)
    setError(null)
    try {
      // A trailing newline is what `pass` writes, so the file stays
      // indistinguishable from one the CLI produced.
      onSaved(await editEntry(name, body.endsWith('\n') ? body : `${body}\n`))
    } catch (e: unknown) {
      setError(String(e))
      setBusy(false)
    }
  }

  return (
    <Dialog
      title={`Edit ${name}`}
      description="Everything this entry holds is shown while the editor is open, including any one-time-password key."
      onClose={onCancel}
    >
      <form onSubmit={submit}>
        <div className="px-5 py-4">
          {body === null && !error && (
            <div className="py-8 text-center">
              <LockIcon className="animate-waiting mx-auto size-8 text-accent" open />
              <p className="mt-3 text-sm font-medium text-ink">Decrypting…</p>
              <p className="mx-auto mt-1 max-w-xs text-xs leading-relaxed text-ink-muted">
                If your key needs a passphrase or a touch, look for a system prompt.
              </p>
            </div>
          )}

          {body !== null && (
            <>
              <label htmlFor="entry-body" className="block text-xs font-medium text-ink">
                Contents
              </label>
              <p id="entry-body-hint" className="mt-1 text-xs leading-relaxed text-ink-muted">
                The first line is the password. A line like{' '}
                <code className="font-mono">user: alice</code> is a field; everything else is kept
                as notes.
              </p>
              {/* The one editable surface holding a whole plaintext. `bg-exposed`
                  is the same wash a revealed row gets: warm means something is
                  showing, and this is the most of it anywhere in the app.
                  Marked important because `inputClass` also sets a background:
                  the two utilities have equal specificity, so without it the
                  winner is decided by their order in the generated stylesheet
                  rather than by the order here, and `bg-raised` takes it. */}
              <textarea
                id="entry-body"
                aria-describedby="entry-body-hint"
                autoFocus
                rows={12}
                value={body}
                spellCheck={false}
                autoCapitalize="off"
                autoCorrect="off"
                className={`${inputClass} mt-1.5 resize-y bg-exposed! font-mono leading-relaxed`}
                onChange={(event) => setBody(event.target.value)}
              />
            </>
          )}

          {error && (
            <div className={body === null ? '' : 'mt-4'}>
              <FormError message={error} />
            </div>
          )}
        </div>

        <Actions busy={busy} disabled={body === null} submitLabel="Save" onCancel={onCancel} />
      </form>
    </Dialog>
  )
}
