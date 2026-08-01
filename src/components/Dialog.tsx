import { useEffect, useId, useRef } from 'react'
import { AlertIcon, CloseIcon } from '../lib/icons'

/**
 * The shared parts of every dialog in the app.
 *
 * Built on the platform's own `<dialog>` rather than a div with a high
 * `z-index`, which buys three things a hand-rolled modal has to reimplement
 * badly: Escape closes it, focus is trapped inside it, and everything behind it
 * goes inert. On a password manager the keyboard is not a nicety — a credential
 * is fetched in the middle of some other task — so the free correctness is
 * worth more than the styling control it costs.
 *
 * Dialogs here are mounted only while open and unmounted when they close. That
 * is not an implementation detail: the edit form holds a whole decrypted entry,
 * and unmounting is what guarantees the string goes with the form rather than
 * lingering in a hidden component (CLAUDE.md, Frontend).
 */
type DialogProps = {
  title: string
  /** A line under the title: what this dialog will do, or what it costs. */
  description?: React.ReactNode
  onClose: () => void
  children: React.ReactNode
}

export function Dialog({ title, description, onClose, children }: DialogProps) {
  const ref = useRef<HTMLDialogElement>(null)
  const titleId = useId()

  useEffect(() => {
    const dialog = ref.current
    // `showModal` rather than `show`: only the modal form is inert-behind and
    // focus-trapping, and only it gets a `::backdrop`.
    if (dialog && !dialog.open) dialog.showModal()
  }, [])

  return (
    <dialog
      ref={ref}
      aria-labelledby={titleId}
      onClose={onClose}
      // A click that lands on the element itself rather than on its contents is
      // a click on the backdrop; the panel below catches everything inside.
      onClick={(event) => {
        if (event.target === ref.current) ref.current?.close()
      }}
      className="m-auto w-[min(36rem,calc(100vw-2rem))] rounded-panel border border-line bg-panel p-0 text-ink shadow-lift"
    >
      <div className="flex items-start gap-3 border-b border-line px-5 pt-4 pb-3.5">
        <div className="min-w-0 flex-1">
          <h2 id={titleId} className="text-sm font-semibold tracking-tight">
            {title}
          </h2>
          {description && (
            <p className="mt-1 text-xs leading-relaxed text-ink-muted">{description}</p>
          )}
        </div>
        <button
          type="button"
          aria-label="Close"
          className="-mt-0.5 -mr-1 shrink-0 rounded-row p-1 text-ink-faint transition-colors hover:bg-raised hover:text-ink"
          onClick={() => ref.current?.close()}
        >
          <CloseIcon className="size-4" />
        </button>
      </div>
      {children}
    </dialog>
  )
}

/**
 * One labelled control.
 *
 * The hint sits under the label rather than under the input, so it is read
 * before the field is filled rather than after — and it is wired up with
 * `aria-describedby` so a screen reader gets it in the same order.
 */
export function Field({
  label,
  hint,
  children,
}: {
  label: string
  hint?: React.ReactNode
  children: (props: { id: string; describedBy: string | undefined }) => React.ReactNode
}) {
  const id = useId()
  const hintId = `${id}-hint`

  return (
    <div>
      <label htmlFor={id} className="block text-xs font-medium text-ink">
        {label}
      </label>
      {hint && (
        <p id={hintId} className="mt-1 text-xs leading-relaxed text-ink-muted">
          {hint}
        </p>
      )}
      <div className="mt-1.5">{children({ id, describedBy: hint ? hintId : undefined })}</div>
    </div>
  )
}

/** The one input treatment, so a form does not drift control by control. */
export const inputClass =
  'w-full rounded-row border border-line-strong/50 bg-raised px-2.5 py-1.5 text-sm text-ink transition-colors placeholder:text-ink-faint hover:border-line-strong focus:border-line-strong'

/** The footer of a dialog: the cancelling action first, the committing one last. */
export function Actions({
  busy,
  submitLabel,
  onCancel,
  tone = 'accent',
  disabled,
}: {
  busy?: boolean
  submitLabel: string
  onCancel: () => void
  /** `danger` for an action that destroys something. */
  tone?: 'accent' | 'danger'
  disabled?: boolean
}) {
  return (
    <div className="flex items-center justify-end gap-2 border-t border-line px-5 py-3.5">
      <button
        type="button"
        className="rounded-row border border-line-strong/45 px-3 py-1.5 text-xs font-medium text-ink-muted transition-colors hover:border-line-strong hover:bg-raised hover:text-ink"
        onClick={onCancel}
      >
        Cancel
      </button>
      <button
        type="submit"
        disabled={busy || disabled}
        className={`rounded-row px-3.5 py-1.5 text-xs font-semibold shadow-lift transition-[filter,opacity] duration-150 hover:brightness-105 active:brightness-95 disabled:cursor-not-allowed disabled:opacity-55 disabled:shadow-none ${
          tone === 'danger'
            ? 'bg-[var(--c-danger-ink)] text-[var(--c-canvas)]'
            : 'bg-accent text-accent-on'
        }`}
      >
        {busy ? 'Working…' : submitLabel}
      </button>
    </div>
  )
}

/**
 * What went wrong, said plainly.
 *
 * Errors from the core name the actual problem and the actual fix (§4.1
 * principle 5), so they are shown verbatim rather than replaced with a generic
 * line — the whole point of typing them carefully is lost if the UI flattens
 * them back to "could not save".
 */
export function FormError({ message }: { message: string }) {
  return (
    <div
      role="alert"
      className="flex items-start gap-2.5 rounded-panel border border-danger-line bg-danger-soft px-3 py-2.5 text-xs leading-relaxed text-danger-ink"
    >
      <AlertIcon className="mt-px size-3.5 shrink-0" />
      <span className="min-w-0 break-words">{message}</span>
    </div>
  )
}
