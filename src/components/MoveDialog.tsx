import { useState } from 'react'
import { Actions, Dialog, Field, FormError, inputClass } from './Dialog'
import { copyEntry, renameEntry, type WriteReceipt } from '../lib/commands'

/**
 * Renaming an entry, or duplicating it under a second name.
 *
 * One component for both because they differ in a single call and a single
 * word: a rename leaves nothing behind, a duplicate leaves the original. The
 * core decides the rest — moving inside one set of keys just moves the
 * encrypted file, and moving across them decrypts and re-encrypts (Invariant 8)
 * — which is why the description warns about a prompt that may or may not
 * appear rather than promising it will not.
 *
 * "The keys that can open it" is the plain-language form of the store's
 * recipients. The word `.gpg-id` does not appear: the user does not have to
 * know `pass` to use it (§4.1 principle 4), and nothing here asks them to go
 * look at that file.
 */
type Props = {
  mode: 'rename' | 'duplicate'
  from: string
  onCancel: () => void
  onDone: (to: string, receipt: WriteReceipt) => void
}

export function MoveDialog({ mode, from, onCancel, onDone }: Props) {
  const [to, setTo] = useState(from)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const renaming = mode === 'rename'
  const trimmed = to.trim()
  const ready = trimmed !== '' && trimmed !== from && !trimmed.endsWith('/')

  async function submit(event: React.FormEvent) {
    event.preventDefault()
    if (!ready || busy) return
    setBusy(true)
    setError(null)
    try {
      const receipt = renaming ? await renameEntry(from, trimmed) : await copyEntry(from, trimmed)
      onDone(trimmed, receipt)
    } catch (e: unknown) {
      setError(String(e))
      setBusy(false)
    }
  }

  return (
    <Dialog
      title={renaming ? `Rename ${from}` : `Duplicate ${from}`}
      description="If the new folder is protected by different keys, the entry is decrypted and encrypted again for them — so your system may ask for your passphrase."
      onClose={onCancel}
    >
      <form onSubmit={submit}>
        <div className="space-y-4 px-5 py-4">
          <Field
            label={renaming ? 'New name' : 'Name for the copy'}
            hint={
              <>
                Slashes make folders. Moving to <code className="font-mono">Old/{from}</code> files
                it away without deleting it.
              </>
            }
          >
            {({ id, describedBy }) => (
              <input
                id={id}
                aria-describedby={describedBy}
                autoFocus
                value={to}
                spellCheck={false}
                autoCapitalize="off"
                autoCorrect="off"
                className={`${inputClass} font-mono`}
                onChange={(event) => setTo(event.target.value)}
              />
            )}
          </Field>

          {error && <FormError message={error} />}
        </div>

        <Actions
          busy={busy}
          disabled={!ready}
          submitLabel={renaming ? 'Rename' : 'Duplicate'}
          onCancel={onCancel}
        />
      </form>
    </Dialog>
  )
}
