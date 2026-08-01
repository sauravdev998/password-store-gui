/**
 * What is on the clipboard and how long the core will leave it there.
 *
 * Lives at the window level rather than inside the entry it came from, and the
 * reason is not layout: a password sitting on the system clipboard is a fact
 * about the whole machine. It stays true after the user selects a different
 * entry, and it is what makes a generated password — created from the sidebar,
 * never shown, never returned — visible as having happened at all.
 */
import { CheckIcon } from '../lib/icons'

/** Which of an entry's values a copy took. The OTP has no reveal, but it copies. */
export type CopySlot = 'password' | 'notes' | 'otp' | `field:${number}`

/** What we put on the clipboard, and when the core will wipe it. */
export type Clipped = {
  /** The entry it came from, so only that entry's row reads as copied. */
  entry: string
  slot: CopySlot
  /** What to call it in the notice. */
  label: string
  clearsAt: number
  /** The full window, so the countdown can be drawn to scale. */
  windowMs: number
}

type Props = {
  clipped: Clipped
  now: number
  onClear: () => void
}

export function ClipboardNotice({ clipped, now, onClear }: Props) {
  const secondsLeft = Math.max(0, Math.ceil((clipped.clearsAt - now) / 1000))
  const fraction = Math.max(0, Math.min(1, (clipped.clearsAt - now) / clipped.windowMs))

  return (
    <div
      role="status"
      aria-live="polite"
      className="shrink-0 border-t border-accent-line bg-accent-soft"
    >
      {/* The window, draining. It is the same number as the text, at a glance. */}
      <div
        aria-hidden="true"
        className="h-0.5 origin-left bg-accent transition-transform duration-500 ease-linear"
        style={{ transform: `scaleX(${fraction})` }}
      />
      <p className="flex items-center gap-3 px-6 py-3 text-xs text-accent-ink">
        <CheckIcon className="size-3.5 shrink-0" />
        <span className="min-w-0 flex-1 leading-relaxed">
          <span className="font-medium">{clipped.label}</span> from{' '}
          <span className="font-mono">{clipped.entry}</span> copied — the clipboard clears in{' '}
          <span className="tabular-nums">{secondsLeft}s</span>
        </span>
        <button
          type="button"
          className="shrink-0 rounded-row border border-accent-line px-2 py-1 font-medium transition-colors hover:bg-accent-line/40"
          onClick={onClear}
        >
          Clear now
        </button>
      </p>
    </div>
  )
}
