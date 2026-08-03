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

/** A branch's relationship to the one it tracks, as of the last sync. */
export type Tracking = {
  /** The remote branch, as git names it: `origin/main`. */
  upstream: string
  /** Commits this store has that the remote does not. */
  ahead: number
  /** Commits the remote has that this store does not. */
  behind: number
}

/**
 * Where the store stands relative to its remote.
 *
 * Computed locally: it reports the distance as of the last sync and never goes
 * and looks, so reading it cannot hang or ask for a credential.
 */
export type SyncStatus = {
  /** `null` on a store with no commits yet, or a detached checkout. */
  branch: string | null
  /** `null` when the store is not shared with a remote at all. */
  tracking: Tracking | null
  /**
   * Files under the store that its history does not have. Normally zero, since
   * every change commits itself.
   */
  uncommitted: number
}

/** What a sync did. Mirrors `git::SyncOutcome`. */
export type SyncOutcome =
  | { status: 'noRemote' }
  | { status: 'upToDate' }
  | { status: 'synced'; pulled: number; pushed: number }
  /** The same entries changed in both places. **Nothing on disk was changed.** */
  | { status: 'conflicted'; entries: string[] }

/** What a commit did to the entry it is being listed for. */
export type RevisionKind = 'added' | 'modified' | 'removed'

/** One past version of an entry. Carries no content — see {@link revealRevision}. */
export type Revision = {
  /** The commit id, which is how a version is asked for. */
  id: string
  /** The first line of the commit message. */
  summary: string
  author: string
  /** Unix seconds. Formatting belongs here, where the locale is known. */
  committedAt: number
  change: RevisionKind
}

/**
 * What decided a setting's current value.
 *
 * `environment` means a `pass` variable is in charge and this app cannot
 * override it (ADR-11) — the control for it is shown fixed, with the reason,
 * rather than offered and quietly ignored.
 */
export type SettingSource = 'environment' | 'configured' | 'default'

/** A resolved setting, with what decided it. */
export type Decided<T> = { value: T; source: SettingSource }

/**
 * Every setting as it currently stands.
 *
 * Carries no store content: a path, four numbers and two booleans.
 */
export type EffectiveSettings = {
  storeDir: Decided<string>
  clipTimeSecs: Decided<number>
  generatedLength: Decided<number>
  /** Idle seconds before the window locks. `0` never locks. */
  lockAfterSecs: Decided<number>
  /** Whether leaving the window hides what is revealed in it. */
  lockOnBlur: Decided<boolean>
  /** Whether selecting an entry decrypts it. */
  openOnSelect: Decided<boolean>
  /**
   * What the user has actually configured, underneath the resolved values.
   *
   * The settings form edits this rather than the values above, so that a
   * setting the environment is currently overriding keeps the value behind it
   * instead of being erased by the next unrelated save.
   */
  configured: Settings
  /** Where settings are written, to name in the interface. */
  path: string | null
  /** Why the settings file was not used, when it exists and could not be read. */
  problem: string | null
}

/**
 * What the user has configured, and only that.
 *
 * `null` means *not set here*, which is what lets the environment or the
 * built-in default show through. Sent whole: a field omitted is a field the
 * user cleared.
 */
export type Settings = {
  storeDir: string | null
  clipTimeSecs: number | null
  generatedLength: number | null
  lockAfterSecs: number | null
  lockOnBlur: boolean | null
  openOnSelect: boolean | null
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
 * Where the store stands relative to its remote. `null` when it keeps no
 * history at all.
 *
 * Safe to call on arrival and after any change: it reads only what is already
 * on disk, so it never reaches the network, never prompts, and never decrypts.
 */
export function syncStatus(): Promise<SyncStatus | null> {
  return invoke<SyncStatus | null>('sync_status')
}

/**
 * Fetch, merge and push — the one call in the app that reaches the network.
 *
 * It needs the `git` command line tool, which nothing else here does: the store
 * itself is read and written without it. A conflict is reported rather than
 * left on disk, and in that case nothing was changed.
 */
export function syncStore(): Promise<SyncOutcome> {
  return invoke<SyncOutcome>('sync_store')
}

/**
 * The versions of an entry its history holds, newest first.
 *
 * Decrypts nothing, so opening a history costs no passphrase prompt and no
 * security-key touch. Reading one of the versions does — see
 * {@link revealRevision}.
 */
export function entryHistory(name: string): Promise<Revision[]> {
  return invoke<Revision[]>('entry_history', { name })
}

/**
 * A past version of an entry, whole.
 *
 * The history counterpart to {@link revealEntry}, and the same exception: there
 * is no smaller request, since the point of asking is to see what the version
 * said and its shape is only knowable by decrypting it. The obligation on this
 * side is the same — the string belongs to the open view and goes when it
 * closes.
 */
export function revealRevision(name: string, revision: string): Promise<string> {
  return invoke<string>('reveal_revision', { name, revision })
}

/**
 * Copy the password a past version held, without showing it.
 *
 * The recovery case in its usual shape, served like every other copy: the value
 * goes to the clipboard from inside the core and never comes through here.
 */
export function copyRevisionPassword(name: string, revision: string): Promise<CopyReceipt> {
  return invoke<CopyReceipt>('copy_revision_password', { name, revision })
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

/**
 * One key that can open a folder's entries.
 *
 * Nothing here is secret: a public key's user id and fingerprint are metadata,
 * which is why they may cross this boundary when a decrypted field may not.
 */
export type KeyInfo = {
  /**
   * The id exactly as the store spells it — an email, a key id, a fingerprint.
   *
   * Kept verbatim rather than normalized, because it is the string the store
   * holds and the one the user needs if they go looking outside the app.
   */
  id: string
  /** A readable name for the key, or `null` when it is not on this keyring. */
  label: string | null
  /** The key's fingerprint, for an id that spells something shorter. */
  fingerprint: string | null
  /**
   * Whether this machine can decrypt with it — that is, whether it is *yours*.
   *
   * What makes removing the last one of these a warning rather than a click.
   */
  usableHere: boolean
}

/** Which keys can open a folder's entries, and where that was decided. */
export type FolderKeys = {
  /** The folder asked about. `null` is the store root. */
  folder: string | null
  /** The keys in force. Empty means no keys are set for this store at all. */
  keys: KeyInfo[]
  /** The folder whose setting decided this. `null` is the store root's. */
  source: string | null
  /** Whether that decision was made in a folder above this one. */
  inherited: boolean
  /** How many entries that decision covers. */
  entries: number
}

/**
 * What changing a folder's keys would do, worked out before it is done.
 *
 * Costs nothing to ask: no entry is decrypted to answer it, so this can be
 * shown while the user is still deciding.
 */
export type RecipientPlan = {
  folder: string | null
  /** The proposed keys, each resolved. */
  keys: KeyInfo[]
  /**
   * Entries that would have to be decrypted and encrypted again, by name.
   *
   * The real cost of the change, and what the interface must show before
   * asking: each one is a decrypt, which on a machine with a security key is a
   * touch.
   */
  reencrypts: string[]
  /** Entries already readable by exactly these keys, which are left alone. */
  unchanged: number
  /**
   * Whether none of the proposed keys is one this machine can decrypt with.
   *
   * The irreversible mistake: it would leave the user unable to open their own
   * entries, with no way back.
   */
  locksYouOut: boolean
  /** Whether this would split the folder off from the keys it inherits now. */
  createsBoundary: boolean
}

/**
 * Which keys can open a folder's entries. Decrypts nothing, so it is free to
 * call while browsing.
 */
export function folderKeys(folder: string | null): Promise<FolderKeys> {
  return invoke<FolderKeys>('folder_keys', { folder })
}

/**
 * What changing a folder's keys would cost, without changing anything.
 *
 * Decrypts nothing — it reads which keys each entry is *already* encrypted to
 * out of the file's headers, which needs no key of any kind.
 */
export function planRecipients(folder: string | null, ids: string[]): Promise<RecipientPlan> {
  return invoke<RecipientPlan>('plan_recipients', { folder, ids })
}

/**
 * Change which keys can open a folder's entries, re-encrypting them.
 *
 * All or nothing: if any entry cannot be re-encrypted, nothing is changed and
 * the store is left exactly as it was. A key that cannot be found is refused
 * before anything is written.
 */
export function setRecipients(folder: string | null, ids: string[]): Promise<WriteReceipt> {
  return invoke<WriteReceipt>('set_recipients', { folder, ids })
}

/** Every setting as it stands, with what decided each one. */
export function getSettings(): Promise<EffectiveSettings> {
  return invoke<EffectiveSettings>('get_settings')
}

/**
 * Replace the configured settings.
 *
 * What comes back is not necessarily what was sent: a `pass` environment
 * variable still outranks anything set here, so the result is the settings as
 * they now stand rather than an echo.
 */
export function setSettings(settings: Settings): Promise<EffectiveSettings> {
  return invoke<EffectiveSettings>('set_settings', { settings })
}

/**
 * What the app found on this machine when it started up (ADR-7).
 *
 * Three independent facts rather than one verdict, because the three states
 * onboarding covers — no GnuPG, no key, no store — are independent and have
 * different remedies. Costs nothing to ask: nothing here is decrypted, so it
 * cannot raise a passphrase prompt.
 */
export type SetupStatus = {
  /** Where the store is, or would be. Worth showing before one is created. */
  storePath: string
  store: StoreState
  /**
   * Why GnuPG is unusable, or `null` when it is fine. When this is set there is
   * nothing the app can do until it is fixed outside the app.
   */
  gpgProblem: string | null
  /**
   * Keys already on this machine that could hold a store.
   *
   * Offered before making a new one is: a second key for somebody who already
   * has one is how a store ends up locked to a key they never backed up.
   */
  keys: KeyInfo[]
  /**
   * Whether git could record anything if asked. What defaults the offer to keep
   * a history — without it, every later save would report a failed commit.
   */
  gitIdentity: boolean
}

export type StoreState =
  /** Nothing at that path yet. */
  | 'missing'
  /** A directory with nothing in it — including one made by hand. */
  | 'empty'
  /** A store to open rather than one to create. */
  | 'ready'

/** What the app found on this machine. Decrypts nothing. */
export function setupStatus(): Promise<SetupStatus> {
  return invoke<SetupStatus>('setup_status')
}

/**
 * Make a new key pair.
 *
 * **The passphrase is never ours.** GnuPG's own prompt asks for it, in a
 * separate window outside this app, and this call does not return until that
 * window is answered. Dismissing it creates nothing and is not a failure to
 * report as one — it comes back as a refusal that can simply be tried again.
 */
export function createKey(name: string, email: string): Promise<KeyInfo> {
  return invoke<KeyInfo>('create_key', { name, email })
}

/**
 * Create the store: the folder, and the record of which keys can open it.
 *
 * `versioned` also starts a history for it. A key that cannot be found is
 * refused before anything is written, so a refused setup leaves nothing behind.
 */
export function initStore(ids: string[], versioned: boolean): Promise<WriteReceipt> {
  return invoke<WriteReceipt>('init_store', { ids, versioned })
}
