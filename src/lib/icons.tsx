/**
 * The icon set.
 *
 * Drawn here rather than pulled from a library: the webview runs under a strict
 * CSP with no external anything (PLAN.md ADR-5), and a whole icon package would
 * be weight against the one thing this app claims to be — a small binary.
 *
 * One geometry for all of them: 24×24 box, 1.5 stroke, round caps and joins,
 * `currentColor`. They are decorative by default (`aria-hidden`), because in
 * every place they appear the adjacent text or the control's own label already
 * carries the meaning.
 */
type IconProps = {
  className?: string
}

function Svg({ className, children }: IconProps & { children: React.ReactNode }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.5}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      className={className}
    >
      {children}
    </svg>
  )
}

/** Folder disclosure. Rotated by the caller rather than swapped for a second glyph. */
export function ChevronIcon({ className }: IconProps) {
  return (
    <Svg className={className}>
      <path d="m9 6 6 6-6 6" />
    </Svg>
  )
}

export function FolderIcon({ className }: IconProps) {
  return (
    <Svg className={className}>
      <path d="M3 7.5A1.5 1.5 0 0 1 4.5 6h4.06a1.5 1.5 0 0 1 1.06.44l1.32 1.32H19.5A1.5 1.5 0 0 1 21 9.26v8.24a1.5 1.5 0 0 1-1.5 1.5h-15A1.5 1.5 0 0 1 3 17.5Z" />
    </Svg>
  )
}

/** An entry. A key, because that is what the file is encrypted to. */
export function EntryIcon({ className }: IconProps) {
  return (
    <Svg className={className}>
      <circle cx="8" cy="12" r="3.25" />
      <path d="M11.25 12H21" />
      <path d="M18 12v3" />
      <path d="M14.75 12v2.25" />
    </Svg>
  )
}

/**
 * The padlock, in both states.
 *
 * `open` lifts and unhooks the shackle instead of switching to a different
 * drawing, so the transition between locked and unlocking is a movement of the
 * same object rather than a swap.
 */
export function LockIcon({ className, open }: IconProps & { open?: boolean }) {
  return (
    <Svg className={className}>
      <rect x="4" y="10.5" width="16" height="10.5" rx="2" />
      <path
        d={open ? 'M8 10.5V7a4 4 0 0 1 7.8-1.3' : 'M8 10.5V7a4 4 0 0 1 8 0v3.5'}
        style={{ transition: 'd 240ms cubic-bezier(0.33, 1, 0.68, 1)' }}
      />
      <path d="M12 14.5v2.5" />
    </Svg>
  )
}

export function CopyIcon({ className }: IconProps) {
  return (
    <Svg className={className}>
      <rect x="9" y="9" width="11" height="11" rx="2" />
      <path d="M5.5 15H5a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1h9a1 1 0 0 1 1 1v.5" />
    </Svg>
  )
}

export function CheckIcon({ className }: IconProps) {
  return (
    <Svg className={className}>
      <path d="m5 12.5 4.5 4.5L19 7" />
    </Svg>
  )
}

export function EyeIcon({ className }: IconProps) {
  return (
    <Svg className={className}>
      <path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12Z" />
      <circle cx="12" cy="12" r="2.75" />
    </Svg>
  )
}

export function EyeOffIcon({ className }: IconProps) {
  return (
    <Svg className={className}>
      <path d="M4 7.5C2.9 8.9 2.5 12 2.5 12s3.5 6.5 9.5 6.5c1.6 0 3-.45 4.2-1.1" />
      <path d="M19.4 15.4c1.5-1.6 2.1-3.4 2.1-3.4S18 5.5 12 5.5c-.9 0-1.75.15-2.5.4" />
      <path d="M10.1 10.1a2.75 2.75 0 0 0 3.8 3.8" />
      <path d="m3.5 3.5 17 17" />
    </Svg>
  )
}

export function AlertIcon({ className }: IconProps) {
  return (
    <Svg className={className}>
      <path d="M12 4.5 21 20H3Z" />
      <path d="M12 10v4" />
      <path d="M12 17h.01" />
    </Svg>
  )
}

/** The store itself, in the sidebar heading. */
export function StoreIcon({ className }: IconProps) {
  return (
    <Svg className={className}>
      <path d="M4 9.5 12 4l8 5.5V19a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1Z" />
      <circle cx="12" cy="12.5" r="2.25" />
      <path d="M12 14.75V17" />
    </Svg>
  )
}
