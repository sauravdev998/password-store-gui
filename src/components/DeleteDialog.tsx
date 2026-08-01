import { useState } from 'react'
import { Actions, Dialog, FormError } from './Dialog'
import { removeEntry, type WriteReceipt } from '../lib/commands'

/**
 * Confirming a deletion.
 *
 * A confirm step exists here and nowhere else in the app because this is the
 * only action that destroys something the user cannot get back from the
 * interface. What it says is the truth rather than a scare: an unversioned
 * store loses the entry outright, and a versioned one keeps it in the history —
 * which is a materially different situation and worth one sentence.
 *
 * The destructive button is last and is the only red one in the app, so the
 * cancelling action is the one under the cursor's resting position.
 */
type Props = {
  name: string
  /** Whether the store keeps a history, so the copy can say which case this is. */
  versioned: boolean
  onCancel: () => void
  onDeleted: (receipt: WriteReceipt) => void
}

export function DeleteDialog({ name, versioned, onCancel, onDeleted }: Props) {
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  async function submit(event: React.FormEvent) {
    event.preventDefault()
    if (busy) return
    setBusy(true)
    setError(null)
    try {
      onDeleted(await removeEntry(name))
    } catch (e: unknown) {
      setError(String(e))
      setBusy(false)
    }
  }

  return (
    <Dialog title={`Delete ${name}?`} onClose={onCancel}>
      <form onSubmit={submit}>
        <div className="space-y-3 px-5 py-4">
          <p className="text-sm leading-relaxed text-ink-muted">
            The encrypted file is removed from your store, and any folder it leaves empty goes with
            it.
          </p>
          <p className="text-sm leading-relaxed text-ink-muted">
            {versioned
              ? 'Your store keeps a history, so the deletion is recorded there and the entry can still be recovered from it.'
              : 'Your store keeps no history, so this cannot be undone from here.'}
          </p>

          {error && <FormError message={error} />}
        </div>

        <Actions busy={busy} tone="danger" submitLabel="Delete entry" onCancel={onCancel} />
      </form>
    </Dialog>
  )
}
