import { invoke } from '@tauri-apps/api/core'

/**
 * Typed wrappers over the Rust command surface. Components call these, never
 * `invoke` directly (CLAUDE.md, Frontend).
 *
 * Everything that touches a decrypted secret stays on the Rust side. The only
 * plaintext that crosses this boundary is what a user explicitly asked to see,
 * one value at a time, through a `reveal*` call — and the value that comes back
 * belongs in component state for as long as it is on screen and no longer.
 * Never put one in a store, in `localStorage`, or in a URL.
 *
 * A `copy*` call is the alternative that never crosses at all: the core puts
 * the value on the clipboard itself and returns only a {@link CopyReceipt}.
 * Prefer it — a copy button should never be a reveal followed by a
 * `navigator.clipboard.writeText`, which would route the password through JS.
 *
 * These types mirror the `serde` representation of the Rust ones; the Rust side
 * is the source of truth for the shape.
 */

/** A folder or an entry. A folder and an entry may share a `path`. */
export type Node =
  | { kind: 'dir'; name: string; path: string; children: Node[] }
  | { kind: 'entry'; name: string; path: string }

export type Tree = {
  nodes: Node[]
  /**
   * Files present on disk whose names the core refuses to handle. Shown rather
   * than dropped: an entry that exists but is invisible is worse than one shown
   * as unusable.
   */
  unsupported: string[]
}

/** What an entry contains, without what it contains. Carries no values. */
export type EntryMetadata = {
  hasPassword: boolean
  /** Field keys in file order. The index addresses a reveal. */
  fields: string[]
  hasOtp: boolean
  hasNotes: boolean
}

/**
 * What a copy tells the caller: when the clipboard will be wiped, and nothing
 * about the value that went onto it.
 */
export type CopyReceipt = {
  clearsInSecs: number
}

/** A one-time password and the life left in it. */
export type OtpCode = {
  /** The digits. Treat it like a revealed value: on screen or gone. */
  code: string
  /** Seconds until `code` is replaced. */
  validForSecs: number
  /** The URI's period, so a countdown can be drawn to scale. */
  periodSecs: number
}

/** Liveness/version probe for the Rust core. */
export function coreVersion(): Promise<string> {
  return invoke<string>('core_version')
}

/** The store's folders and entries. Names only — nothing is decrypted. */
export function listTree(): Promise<Tree> {
  return invoke<Tree>('list_tree')
}

/** An entry's shape. Decrypts in the core, but returns no values. */
export function showEntry(name: string): Promise<EntryMetadata> {
  return invoke<EntryMetadata>('show_entry', { name })
}

/** Reveal a password. Call only from an explicit user action. */
export function revealPassword(name: string): Promise<string> {
  return invoke<string>('reveal_password', { name })
}

/**
 * Reveal one field's value. Call only from an explicit user action.
 *
 * `index` is the position in {@link EntryMetadata.fields} — keys may repeat, so
 * the order is a field's identity.
 */
export function revealField(name: string, index: number): Promise<string> {
  return invoke<string>('reveal_field', { name, index })
}

/** Reveal an entry's free text. Call only from an explicit user action. */
export function revealNotes(name: string): Promise<string> {
  return invoke<string>('reveal_notes', { name })
}

/** Copy the password to the clipboard, in the core. The value never comes here. */
export function copyPassword(name: string): Promise<CopyReceipt> {
  return invoke<CopyReceipt>('copy_password', { name })
}

/** Copy one field's value, addressed like {@link revealField}. */
export function copyField(name: string, index: number): Promise<CopyReceipt> {
  return invoke<CopyReceipt>('copy_field', { name, index })
}

/** Copy an entry's free text. */
export function copyNotes(name: string): Promise<CopyReceipt> {
  return invoke<CopyReceipt>('copy_notes', { name })
}

/** Copy the current one-time password — the code, never the URI behind it. */
export function copyOtp(name: string): Promise<CopyReceipt> {
  return invoke<CopyReceipt>('copy_otp', { name })
}

/**
 * The current one-time password.
 *
 * There is no `revealOtp` to go with the other reveals: the `otpauth://` URI
 * embeds the shared seed, so it never leaves the core. This returns the code
 * the URI generates, which is all the UI has any use for.
 */
export function otpCode(name: string): Promise<OtpCode> {
  return invoke<OtpCode>('otp_code', { name })
}

/** Wipe the clipboard now, ahead of its timer. */
export function clearClipboard(): Promise<void> {
  return invoke<void>('clear_clipboard')
}
