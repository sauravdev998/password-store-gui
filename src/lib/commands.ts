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
