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

/** How a generated password should be built. Mirrors `generate::Recipe`. */
export type Recipe = {
  length: number
  /** Whether punctuation may appear. `pass generate --no-symbols` inverts it. */
  symbols: boolean
}

/** Whether a change reached the store's git history. */
export type Commit = { status: 'committed' } | { status: 'failed'; reason: string }

/**
 * What a mutation reports: what happened *around* the write.
 *
 * Nothing about what was written — the write itself is reported by the call
 * resolving at all. A failed commit is not a failed write: by the time git runs
 * the entry is already encrypted on disk, so `commit.status === 'failed'` means
 * the password is saved and the history is not.
 */
export type WriteReceipt = {
  /** `null` when the store is not a git repository, which is the usual case. */
  commit: Commit | null
  /**
   * Only a generate fills this: the password it made went straight to the
   * clipboard from inside the core and never came through here.
   */
  clipboard: CopyReceipt | null
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

/**
 * Whether the store keeps a git history.
 *
 * Asked so the interface can say what deleting an entry actually costs — a
 * versioned store keeps it, an unversioned one does not — rather than guessing
 * at one of the two.
 */
export function storeHasHistory(): Promise<boolean> {
  return invoke<boolean>('store_has_history')
}

/**
 * An entry's whole plaintext, for the edit form and nothing else.
 *
 * The one call that returns more than a single value, and the only one that can
 * hand over an `otpauth://` URI — which is why {@link otpCode} exists and there
 * is no `revealOtp`. Editing an entry is asking for its whole text: the core
 * replaces the entire body on write, so writing one means having read one.
 *
 * The obligation on this side is the same as any reveal, only larger: the
 * string belongs in the open form's state and nowhere else, and goes when the
 * form closes.
 */
export function revealEntry(name: string): Promise<string> {
  return invoke<string>('reveal_entry', { name })
}

/**
 * Create an entry. Rejects rather than overwriting an existing one.
 *
 * `content` is the whole file: the first line is the password, `key: value`
 * lines become fields, and the rest is kept as notes. This is the one direction
 * plaintext travels *into* the core, which is not a hole in the reveal rules —
 * the user typed it, so it is already here.
 */
export function insertEntry(name: string, content: string): Promise<WriteReceipt> {
  return invoke<WriteReceipt>('insert_entry', { name, content })
}

/** Replace an existing entry's contents. Rejects if it does not exist. */
export function editEntry(name: string, content: string): Promise<WriteReceipt> {
  return invoke<WriteReceipt>('edit_entry', { name, content })
}

/**
 * Create an entry whose password the core generates.
 *
 * The password is never returned: it is written and put on the clipboard from
 * inside the core, so the usual flow — generate, paste into the site that asked
 * — happens without it being rendered anywhere. `receipt.clipboard` is `null`
 * on a machine with no display server, where the entry is still created.
 *
 * `content` is everything *after* the password line, or `null` for a bare one.
 */
export function generateEntry(
  name: string,
  recipe: Recipe,
  content: string | null,
): Promise<WriteReceipt> {
  return invoke<WriteReceipt>('generate_entry', { name, recipe, content })
}

/** Delete an entry, and any folder its removal empties. */
export function removeEntry(name: string): Promise<WriteReceipt> {
  return invoke<WriteReceipt>('remove_entry', { name })
}

/**
 * Move an entry to a new name.
 *
 * Within one set of keys the encrypted file simply moves, so a rename inside a
 * folder costs no passphrase prompt. Across folders protected by different keys
 * the core decrypts and re-encrypts, which can.
 */
export function renameEntry(from: string, to: string): Promise<WriteReceipt> {
  return invoke<WriteReceipt>('rename_entry', { from, to })
}

/** Copy an entry to a new name, leaving the original. Moves like a rename. */
export function copyEntry(from: string, to: string): Promise<WriteReceipt> {
  return invoke<WriteReceipt>('copy_entry', { from, to })
}

/** The generation defaults, so the dialog opens on what `pass` would do. */
export function generateDefaults(): Promise<Recipe> {
  return invoke<Recipe>('generate_defaults')
}
