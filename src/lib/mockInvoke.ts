/**
 * A stand-in for `@tauri-apps/api/core`'s `invoke`, for driving the frontend in
 * a plain browser with no Rust core behind it.
 *
 * **Development only.** Nothing imports this: it is reached solely through the
 * alias in `vite.config.mock.ts`, so it is not part of the shipped bundle. Do
 * not import it from a component — a build that resolves this file for real
 * would be an app with no core.
 *
 * Run it with `pnpm dev:mock`.
 *
 * ## What it is for
 *
 * `PLAN.md` records that the GUI has never been click-tested. This closes the
 * webview half of that: every component is exercised through the same typed
 * wrappers in `commands.ts` that the real app uses, so the tree, the detail
 * pane, and the four mutation dialogs can be driven end to end.
 *
 * ## What it is not
 *
 * It is not evidence about the core, and a passing run here says nothing about
 * §4's invariants — those are properties of the Rust side, which is absent.
 * Nothing here decrypts, no GnuPG runs, no file is written, and the "clipboard"
 * is a variable. The Rust behaviour is *mirrored* rather than shared, so the two
 * can drift; when they do, the Rust side is right. Specifically:
 *
 * - the field separator rule follows `store/entry.rs`
 * - name validation follows `store/name.rs` (F-6)
 * - the refusal rules follow `Core` in `commands.rs`
 * - the rejection strings follow `error.rs`
 * - the settings precedence follows `settings.rs` (ADR-11)
 *
 * Keep those five in step when the core changes, or this stops testing the app
 * and starts testing a fiction.
 */

// --- fixture ------------------------------------------------------------

/**
 * The starting store, mirroring `scripts/make-fixture-store.sh` so that driving
 * the stub and driving the real app show the same entries.
 *
 * The `otpauth://` seed is the RFC 6238 test vector, so a code shown here can
 * be checked against any other TOTP implementation.
 */
const INITIAL: Record<string, string> = {
  'Email/gmail.com': `correct-horse-battery-staple
username: me@example.invalid
url: https://mail.google.com
otpauth://totp/Google:me@example.invalid?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Google
Recovery codes are in the safe.
Second line of notes.
`,
  'Email/work.example': `just-a-password
`,
  'Banking/chase': `tr0ub4dour&3
username: saurav
token: first-token
token: second-token
Call the branch before travelling.
`,
  'Servers/prod/db': `deep-nested-secret
username: postgres
`,
  wifi: `hunter2hunter2
Guest network, rotates monthly.
`,
}

const store: Record<string, string> = { ...INITIAL }

/** Files on disk whose names the core refuses — `weird$name.gpg` trips `$`. */
const UNSUPPORTED = ['weird$name.gpg']

// --- switches -----------------------------------------------------------

const flags = new URLSearchParams(location.search)

/** `?commitFails=1` — every commit fails, for the one notice that must not fade. */
const COMMIT_FAILS = flags.has('commitFails')
/** `?noGit=1` — the store is not a repository, which is the ordinary case. */
const NO_GIT = flags.has('noGit')
/** `?latency=800` — milliseconds per command, so loading states are observable. */
const LATENCY = Number(flags.get('latency') ?? 120)
/** `?clip=10` — the clip window in seconds, to watch a countdown end to end. */
const CLIP_SECS = Number(flags.get('clip') ?? 45)
/** `?noRemote=1` — versioned, but never pushed anywhere: the sync button is off. */
const NO_REMOTE = flags.has('noRemote')
/** `?sync=conflicted` — what a sync reports. `synced` is the default. */
const SYNC_RESULT = flags.get('sync') ?? 'synced'
/** `?syncFails=1` — the sync itself errors, e.g. no `git` installed. */
const SYNC_FAILS = flags.has('syncFails')
/** `?uncommitted=2` — files the history does not have, for the warning line. */
const UNCOMMITTED = Number(flags.get('uncommitted') ?? 0)
/**
 * `?env=storeDir,clipTimeSecs` — pretend these are pinned by a `PASSWORD_STORE_*`
 * variable, so the settings panel's fixed-and-explained state can be driven
 * without setting anything in the developer's own shell.
 */
const PINNED = new Set((flags.get('env') ?? '').split(',').filter(Boolean))
/** `?lockAfter=60` — a short idle timeout, so the lock screen is reachable. */
const LOCK_AFTER = Number(flags.get('lockAfter') ?? 15 * 60)
/** `?settingsBroken=1` — the settings file exists and will not parse. */
const SETTINGS_BROKEN = flags.has('settingsBroken')
/** `?noKeys=1` — no folder pins any keys, i.e. a store that was never set up. */
const NO_KEYS = flags.has('noKeys')
/**
 * `?strangerKey=1` — the store lists a key that is not on this keyring.
 *
 * The ordinary state of a store shared with someone whose public key was never
 * imported, and the case that separates the two ways a key is described: the
 * panel must still *show* it (`commands::describe`), while a change that would
 * encrypt to it is refused (`Core::plan`).
 */
const STRANGER_KEY = flags.has('strangerKey')

// --- keys, per store/gpg_id.rs and crypto/gnupg.rs ----------------------

/**
 * The public keyring this fake `gpg` can see.
 *
 * `yours` is whether a secret key is held, which is what decides the lockout
 * warning. The colleague's is deliberately not — a store shared with someone
 * whose key you cannot decrypt with is the ordinary case, not an edge one.
 */
const KEYRING: Record<string, { label: string; fingerprint: string; yours: boolean }> = {
  'me@example.invalid': {
    label: 'Me <me@example.invalid>',
    fingerprint: '5669E864B1BBDD28ACC242F7A927E66374D6E7FE',
    yours: true,
  },
  'colleague@example.invalid': {
    label: 'A Colleague <colleague@example.invalid>',
    fingerprint: '29BC19FC9B00E35FDEE640CA82C1CC4A844CD7E5',
    yours: false,
  },
  'ops@example.invalid': {
    label: 'Ops Rotation <ops@example.invalid>',
    fingerprint: 'B4D9C7A1E5F30268BC1149E7D5C8A0B34F62E917',
    yours: true,
  },
}

const ME = 'me@example.invalid'
const OPS = 'ops@example.invalid'

/**
 * Which keys each folder pins — one `.gpg-id` per directory, `''` for the root.
 *
 * `Servers` has its own so the subtree rule is drivable: a change at the root
 * must not reach through it.
 */
const gpgIds: Record<string, string[]> = NO_KEYS
  ? {}
  : { '': STRANGER_KEY ? [ME, 'archivist@example.invalid'] : [ME], Servers: [ME, OPS] }

/**
 * Which keys each entry is currently encrypted to.
 *
 * Stands in for reading the recipient packets out of a ciphertext, which the
 * core does without decrypting. Every entry starts encrypted to exactly what
 * governs it, which is the state a store nobody has changed the keys of is in.
 */
const encryptedTo: Record<string, string[]> = {}

// --- entry parsing, per store/entry.rs ----------------------------------

type Field = { key: string; value: string }
type Entry = { password: string; fields: Field[]; otp: string | null; notes: string | null }

const OTPAUTH = 'otpauth://'

/**
 * Split a `key: value` line.
 *
 * The separator is a colon **followed by whitespace or end of line**, which is
 * what keeps a bare `https://…` line free text instead of an `https` field.
 */
function splitField(line: string): Field | null {
  const at = line.indexOf(':')
  if (at === -1) return null
  const rest = line.slice(at + 1)
  if (rest !== '' && !/^\s/.test(rest)) return null
  return { key: line.slice(0, at), value: rest.trimStart() }
}

function parseEntry(raw: string): Entry {
  const lines = raw.split('\n')
  const password = lines.shift() ?? ''
  // The trailing newline is what `pass` writes; it is not a note.
  while (lines.length > 0 && lines[lines.length - 1] === '') lines.pop()

  const fields: Field[] = []
  const notes: string[] = []
  let otp: string | null = null

  for (const line of lines) {
    const field = splitField(line)
    const uri = line.startsWith(OTPAUTH)
      ? line
      : field?.value.startsWith(OTPAUTH)
        ? field.value
        : null
    // First one wins; a second otpauth:// line is kept as a note.
    if (uri !== null && otp === null) {
      otp = uri
      continue
    }
    if (field !== null) fields.push(field)
    else notes.push(line)
  }

  while (notes.length > 0 && notes[notes.length - 1] === '') notes.pop()
  return { password, fields, otp, notes: notes.length > 0 ? notes.join('\n') : null }
}

// --- name validation, per store/name.rs ---------------------------------

/** The reason `name` is unusable, or `null` if it is fine. */
function invalidBecause(name: string): string | null {
  if (name === '') return 'name is empty'
  if (name.length > 4096) return 'name is too long'

  for (const ch of name) {
    const code = ch.codePointAt(0) ?? 0
    // Rust's `char::is_control`: the C0 and C1 ranges, which covers NUL.
    if (code < 0x20 || (code >= 0x7f && code <= 0x9f)) {
      return 'name contains a control character'
    }
    if (ch === '\\') return 'name contains a backslash'
    // `shellexpand` would read this as `$VAR` (ADR-4a, F-6).
    if (ch === '$') return "name contains '$'"
  }
  if (name.startsWith('~')) return "name starts with '~'"

  for (const part of name.split('/')) {
    if (part === '') return 'name contains an empty path component'
    if (part === '.') return "name contains a '.' component"
    if (part === '..') return "name contains a '..' component"
    if (part.length >= 2 && part[1] === ':' && /[a-zA-Z]/.test(part[0])) {
      return 'name contains a drive prefix'
    }
  }
  return null
}

function checkName(name: string): void {
  const reason = invalidBecause(name)
  if (reason !== null) throw `invalid entry name: ${reason}`
}

// --- tree ---------------------------------------------------------------

type Node =
  | { kind: 'dir'; name: string; path: string; children: Node[] }
  | { kind: 'entry'; name: string; path: string }

type Dir = Extract<Node, { kind: 'dir' }>

/** Folders before entries, each alphabetical. */
function order(nodes: Node[]): Node[] {
  nodes.sort((a, b) =>
    a.kind === b.kind ? a.name.localeCompare(b.name) : a.kind === 'dir' ? -1 : 1,
  )
  for (const node of nodes) if (node.kind === 'dir') order(node.children)
  return nodes
}

function buildTree(): Node[] {
  const roots: Node[] = []

  for (const full of Object.keys(store)) {
    const parts = full.split('/')
    let level = roots
    let prefix = ''

    parts.forEach((part, index) => {
      prefix = prefix === '' ? part : `${prefix}/${part}`
      if (index === parts.length - 1) {
        level.push({ kind: 'entry', name: part, path: prefix })
        return
      }
      let dir = level.find((n): n is Dir => n.kind === 'dir' && n.path === prefix)
      if (!dir) {
        dir = { kind: 'dir', name: part, path: prefix, children: [] }
        level.push(dir)
      }
      level = dir.children
    })
  }

  return order(roots)
}

// --- TOTP, computed rather than faked -----------------------------------

function base32Decode(input: string): Uint8Array {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  let bits = 0
  let value = 0
  const out: number[] = []

  for (const ch of input.replace(/=+$/, '').toUpperCase()) {
    const index = alphabet.indexOf(ch)
    if (index === -1) continue
    value = (value << 5) | index
    bits += 5
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff)
      bits -= 8
    }
  }
  return new Uint8Array(out)
}

/** RFC 6238, so a code here can be checked against any other implementation. */
async function totp(uri: string, atSec: number): Promise<{ code: string; period: number }> {
  const url = new URL(uri.replace('otpauth://', 'https://'))
  const secret = url.searchParams.get('secret')
  if (secret === null) throw "the entry's otpauth:// URI is not a usable TOTP source"

  const period = Number(url.searchParams.get('period') ?? 30)
  const digits = Number(url.searchParams.get('digits') ?? 6)

  const counter = Math.floor(atSec / period)
  const message = new ArrayBuffer(8)
  const view = new DataView(message)
  view.setUint32(0, Math.floor(counter / 2 ** 32))
  view.setUint32(4, counter >>> 0)

  const key = await crypto.subtle.importKey(
    'raw',
    base32Decode(secret) as BufferSource,
    { name: 'HMAC', hash: 'SHA-1' },
    false,
    ['sign'],
  )
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, message))
  const offset = mac[mac.length - 1] & 0x0f
  const binary =
    ((mac[offset] & 0x7f) << 24) |
    (mac[offset + 1] << 16) |
    (mac[offset + 2] << 8) |
    mac[offset + 3]

  return { code: String(binary % 10 ** digits).padStart(digits, '0'), period }
}

// --- clipboard ----------------------------------------------------------

let clipboard: string | null = null
let clipTimer: number | null = null

function copyToClipboard(value: string): { clearsInSecs: number } {
  clipboard = value
  if (clipTimer !== null) window.clearTimeout(clipTimer)
  clipTimer = window.setTimeout(() => {
    clipboard = null
    clipTimer = null
  }, CLIP_SECS * 1000)
  return { clearsInSecs: CLIP_SECS }
}

// --- generation ---------------------------------------------------------

const ALPHANUM = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
const SYMBOLS = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"

/** Rejection sampling, as `generate.rs` does: a modulo would bias the head. */
function generatePassword(length: number, symbols: boolean): string {
  const alphabet = symbols ? ALPHANUM + SYMBOLS : ALPHANUM
  const limit = 256 - (256 % alphabet.length)
  const out: string[] = []
  const byte = new Uint8Array(1)

  while (out.length < length) {
    crypto.getRandomValues(byte)
    if (byte[0] >= limit) continue
    out.push(alphabet[byte[0] % alphabet.length])
  }
  return out.join('')
}

// --- receipts -----------------------------------------------------------

type Commit = { status: 'committed' } | { status: 'failed'; reason: string }
type CopyReceipt = { clearsInSecs: number }
type WriteReceipt = { commit: Commit | null; clipboard: CopyReceipt | null }

function receipt(): WriteReceipt {
  if (NO_GIT) return { commit: null, clipboard: null }
  return {
    commit: COMMIT_FAILS
      ? { status: 'failed', reason: 'cannot sign commit: secret key not available' }
      : { status: 'committed' },
    clipboard: null,
  }
}

// --- history ------------------------------------------------------------

/**
 * A fabricated past for every entry, so the history dialog can be driven.
 *
 * Mirrors `git/mod.rs` only in shape: the ids are made up, the bodies are
 * invented, and no repository exists. What it does reproduce faithfully is the
 * rule the dialog is built around — listing costs nothing, and opening one
 * version is a separate request that returns a whole body.
 */
type Past = { id: string; summary: string; author: string; committedAt: number; change: string }

/** `id -> the body that version held`, for the reveal. */
const pastBodies: Record<string, string> = {}

function pastOf(name: string): Past[] {
  if (NO_GIT) return []
  const day = 24 * 60 * 60
  const now = Math.floor(Date.now() / 1000)
  const current = store[name]
  if (current === undefined) return []

  const versions: Past[] = [
    {
      id: `${name}@2`,
      summary: `Edit password for ${name} using Password Store.`,
      author: 'Saurav Mohanta',
      committedAt: now - 2 * day,
      change: 'modified',
    },
    {
      id: `${name}@1`,
      summary: `Add given password for ${name} to store.`,
      author: 'Saurav Mohanta',
      committedAt: now - 40 * day,
      change: 'added',
    },
  ]

  pastBodies[`${name}@2`] = current
  // An older body that visibly differs, so "open a version" shows something
  // other than what the detail pane already says.
  pastBodies[`${name}@1`] = current.replace(/^.*$/m, 'an-older-password')
  return versions
}

function pastBody(name: string, revision: string): string {
  pastOf(name)
  const body = pastBodies[revision]
  if (body === undefined) throw 'not a valid revision of the store\'s history'
  return body
}

// --- argument helpers ---------------------------------------------------

type Args = Record<string, unknown>

const str = (args: Args, key: string): string => String(args[key])
const num = (args: Args, key: string): number => Number(args[key])

function bodyOf(name: string): string {
  checkName(name)
  const raw = store[name]
  if (raw === undefined) throw `no entry named ${name}`
  return raw
}

const entryOf = (name: string): Entry => parseEntry(bodyOf(name))

/** Reject a write onto a name that is already taken. */
function mustBeFree(name: string): void {
  checkName(name)
  if (store[name] !== undefined) throw `an entry named ${name} already exists`
}

// --- settings, per settings.rs ------------------------------------------

/**
 * What the "user" has configured. Starts empty, as a fresh install would.
 *
 * Held in memory only: the stub has no file, which is also why saving here
 * proves nothing about the atomic write in `settings::write`.
 */
const configured: Record<string, unknown> = {
  storeDir: null,
  clipTimeSecs: null,
  generatedLength: null,
  lockAfterSecs: LOCK_AFTER === 15 * 60 ? null : LOCK_AFTER,
  lockOnBlur: null,
  openOnSelect: null,
}

/** What the environment claims, for whichever keys `?env=` named. */
const ENV: Record<string, unknown> = {
  storeDir: '/mnt/shared/store',
  clipTimeSecs: 90,
  generatedLength: 40,
}

/** The precedence rule from `settings::resolve`: environment, then configured, then default. */
function decide(key: string, fallback: unknown) {
  if (PINNED.has(key)) return { value: ENV[key], source: 'environment' }
  const set = configured[key]
  if (set !== null && set !== undefined) return { value: set, source: 'configured' }
  return { value: fallback, source: 'default' }
}

function effective() {
  return {
    storeDir: decide('storeDir', '/home/you/.password-store'),
    clipTimeSecs: decide('clipTimeSecs', CLIP_SECS),
    generatedLength: decide('generatedLength', 25),
    lockAfterSecs: decide('lockAfterSecs', 15 * 60),
    lockOnBlur: decide('lockOnBlur', true),
    openOnSelect: decide('openOnSelect', false),
    configured: { ...configured },
    path: '/home/you/.config/password-store-gui/settings.json',
    problem: SETTINGS_BROKEN
      ? '/home/you/.config/password-store-gui/settings.json is not readable as settings: ' +
        'expected value at line 1 column 3'
      : null,
  }
}

// --- the command surface ------------------------------------------------

const handlers: Record<string, (args: Args) => unknown> = {
  core_version: () => '0.1.0-mock',

  list_tree: () => ({ nodes: buildTree(), unsupported: UNSUPPORTED }),

  store_has_history: () => !NO_GIT,

  sync_status: () => {
    if (NO_GIT) return null
    return {
      branch: 'main',
      tracking: NO_REMOTE ? null : { upstream: 'origin/main', ahead: 1, behind: 2 },
      uncommitted: UNCOMMITTED,
    }
  },

  sync_store: () => {
    if (SYNC_FAILS) throw 'syncing needs the git command line tool, which is not installed'
    if (NO_GIT || NO_REMOTE) return { status: 'noRemote' }
    switch (SYNC_RESULT) {
      case 'upToDate':
        return { status: 'upToDate' }
      case 'conflicted':
        return { status: 'conflicted', entries: ['Email/gmail.com', 'wifi'] }
      default:
        return { status: 'synced', pulled: 2, pushed: 1 }
    }
  },

  entry_history: (args) => {
    const name = str(args, 'name')
    bodyOf(name)
    return pastOf(name)
  },

  reveal_revision: (args) => pastBody(str(args, 'name'), str(args, 'revision')),

  copy_revision_password: (args) => {
    const body = pastBody(str(args, 'name'), str(args, 'revision'))
    return copyToClipboard(parseEntry(body).password)
  },

  generate_defaults: () => ({ length: effective().generatedLength.value, symbols: true }),

  get_settings: () => effective(),

  set_settings: (args) => {
    const next = args.settings as Record<string, unknown>
    // The refusals mirror `settings::validate`. Only the two that a user can
    // actually reach through the form are worth mirroring; the rest of the
    // bounds are the core's to enforce.
    const length = next.generatedLength as number | null
    if (length !== null && (length < 8 || length > 256))
      throw 'password length must be between 8 and 256'
    const clip = next.clipTimeSecs as number | null
    if (clip !== null && clip > 3600)
      throw 'the time before the clipboard is cleared cannot be more than 3600 seconds'

    Object.assign(configured, next)
    return effective()
  },

  show_entry: (args) => {
    const entry = entryOf(str(args, 'name'))
    return {
      hasPassword: entry.password !== '',
      fields: entry.fields.map((field) => field.key),
      hasOtp: entry.otp !== null,
      hasNotes: entry.notes !== null,
    }
  },

  reveal_password: (args) => entryOf(str(args, 'name')).password,

  reveal_field: (args) => fieldAt(str(args, 'name'), num(args, 'index')).value,

  reveal_notes: (args) => notesOf(str(args, 'name')),

  reveal_entry: (args) => bodyOf(str(args, 'name')),

  copy_password: (args) => copyToClipboard(entryOf(str(args, 'name')).password),

  copy_field: (args) => copyToClipboard(fieldAt(str(args, 'name'), num(args, 'index')).value),

  copy_notes: (args) => copyToClipboard(notesOf(str(args, 'name'))),

  copy_otp: async (args) => {
    const { code } = await currentOtp(str(args, 'name'))
    return copyToClipboard(code)
  },

  otp_code: async (args) => {
    const nowSec = Math.floor(Date.now() / 1000)
    const { code, period } = await currentOtp(str(args, 'name'), nowSec)
    return { code, validForSecs: period - (nowSec % period), periodSecs: period }
  },

  clear_clipboard: () => {
    clipboard = null
    if (clipTimer !== null) window.clearTimeout(clipTimer)
    clipTimer = null
  },

  // Refuses to overwrite: replacing an entry is `edit_entry`, and keeping the
  // two apart is what stops a mistyped name from destroying a password.
  insert_entry: (args) => {
    const name = str(args, 'name')
    mustBeFree(name)
    store[name] = str(args, 'content')
    return receipt()
  },

  // ...and refuses to create, the other half of that rule.
  edit_entry: (args) => {
    const name = str(args, 'name')
    bodyOf(name)
    store[name] = str(args, 'content')
    return receipt()
  },

  generate_entry: (args) => {
    const name = str(args, 'name')
    mustBeFree(name)
    const { length, symbols } = args.recipe as { length: number; symbols: boolean }
    const password = generatePassword(length, symbols)
    const rest = args.content === null || args.content === undefined ? null : str(args, 'content')
    store[name] = rest === null ? `${password}\n` : `${password}\n${rest}`
    // The password goes to the clipboard from inside the "core" and is never
    // returned — the whole point of the generate path.
    return { ...receipt(), clipboard: copyToClipboard(password) }
  },

  remove_entry: (args) => {
    const name = str(args, 'name')
    bodyOf(name)
    delete store[name]
    return receipt()
  },

  rename_entry: (args) => {
    const from = str(args, 'from')
    const to = str(args, 'to')
    const body = bodyOf(from)
    mustBeFree(to)
    store[to] = body
    delete store[from]
    return receipt()
  },

  copy_entry: (args) => {
    const from = str(args, 'from')
    const to = str(args, 'to')
    const body = bodyOf(from)
    mustBeFree(to)
    store[to] = body
    return receipt()
  },

  folder_keys: (args) => {
    const folder = folderArg(args)
    const source = nearestKeysFolder(folder)
    if (source === null) {
      return { folder, keys: [], source: null, inherited: false, entries: 0 }
    }
    return {
      folder,
      // Described leniently, unlike a plan: a folder listing a key that is not
      // on the keyring must still show the key rather than refusing to open.
      keys: gpgIds[source].map(describeKeyLoosely),
      source: source === '' ? null : source,
      inherited: source !== (folder ?? ''),
      entries: governedBy(source === '' ? null : source).length,
    }
  },

  plan_recipients: (args) => planRecipients(folderArg(args), idsArg(args)),

  set_recipients: (args) => {
    const folder = folderArg(args)
    const ids = idsArg(args)
    // Refuses an unresolvable key before anything changes, as `Core` does.
    const plan = planRecipients(folder, ids)
    gpgIds[folder ?? ''] = [...ids]
    for (const name of plan.reencrypts) encryptedTo[name] = [...ids]
    return receipt()
  },
}

/** `folder` crosses as `null` for the store root, never as `''`. */
function folderArg(args: Args): string | null {
  const folder = args.folder
  return folder === null || folder === undefined ? null : String(folder)
}

function idsArg(args: Args): string[] {
  return (args.ids as string[]) ?? []
}

/** Mirrors `crypto::gnupg::describe_key`: an unresolvable id is a refusal. */
function describeKey(id: string) {
  const known = KEYRING[id]
  if (!known) throw `no public key for ${id}`
  return { id, label: known.label, fingerprint: known.fingerprint, usableHere: known.yours }
}

/** Mirrors `commands::describe`: for display, an unknown key is still shown. */
function describeKeyLoosely(id: string) {
  const known = KEYRING[id]
  return known
    ? { id, label: known.label, fingerprint: known.fingerprint, usableHere: known.yours }
    : { id, label: null, fingerprint: null, usableHere: false }
}

/** Mirrors `gpg_id::nearest_gpg_id_in`. `''` is the root; `null` is nothing set. */
function nearestKeysFolder(folder: string | null): string | null {
  const parts = folder ? folder.split('/') : []
  for (let depth = parts.length; depth >= 0; depth--) {
    const candidate = parts.slice(0, depth).join('/')
    if (gpgIds[candidate]) return candidate
  }
  return null
}

/**
 * Mirrors `gpg_id::governed_by`: entries inside `folder` that nothing nearer
 * claims first, whether or not `folder` pins keys yet.
 */
function governedBy(folder: string | null): string[] {
  const prefix = folder ?? ''
  const depth = prefix ? prefix.split('/').length : 0

  return Object.keys(store)
    .filter((name) => {
      const dirs = name.split('/').slice(0, -1)
      const dir = dirs.join('/')
      if (prefix && dir !== prefix && !dir.startsWith(`${prefix}/`)) return false
      // Anything between the folder and the entry is nearer, and takes it.
      for (let i = depth + 1; i <= dirs.length; i++) {
        if (gpgIds[dirs.slice(0, i).join('/')]) return false
      }
      return true
    })
    .sort()
}

/** What an entry is encrypted to now, defaulting to whatever governs it. */
function keysOn(name: string): string[] {
  if (!encryptedTo[name]) {
    const source = nearestKeysFolder(name.split('/').slice(0, -1).join('/'))
    encryptedTo[name] = source === null ? [] : [...gpgIds[source]]
  }
  return encryptedTo[name]
}

/**
 * Mirrors `commands::is_current` — Invariant 8 in both directions: everyone
 * listed can read it, and nobody else can.
 */
function isCurrent(name: string, ids: string[]): boolean {
  const actual = new Set(keysOn(name))
  return ids.every((id) => actual.has(id)) && [...actual].every((id) => ids.includes(id))
}

/** Mirrors `Core::plan`. Decrypts nothing, which here means it reads no body. */
function planRecipients(folder: string | null, ids: string[]) {
  if (ids.length === 0) throw 'the .gpg-id file lists no recipients'
  const keys = ids.map(describeKey)
  const governed = governedBy(folder)
  const reencrypts = governed.filter((name) => !isCurrent(name, ids))

  return {
    folder,
    keys,
    reencrypts,
    unchanged: governed.length - reencrypts.length,
    locksYouOut: !keys.some((key) => key.usableHere),
    createsBoundary: !gpgIds[folder ?? ''],
  }
}

/** The field at `index`, which is a field's identity since keys may repeat. */
function fieldAt(name: string, index: number): Field {
  const field = entryOf(name).fields[index]
  if (field === undefined) throw `entry ${name} has no field at index ${index}`
  return field
}

function notesOf(name: string): string {
  const notes = entryOf(name).notes
  if (notes === null) throw `entry ${name} has no notes`
  return notes
}

function currentOtp(name: string, atSec = Math.floor(Date.now() / 1000)) {
  const uri = entryOf(name).otp
  if (uri === null) throw `entry ${name} has no one-time-password source`
  return totp(uri, atSec)
}

export async function invoke<T>(command: string, args?: Args): Promise<T> {
  const handler = handlers[command]
  if (handler === undefined) return Promise.reject(`unknown command ${command}`)

  // Latency on purpose: the loading states are part of what is being tested.
  await new Promise((resolve) => setTimeout(resolve, LATENCY))

  try {
    return (await handler(args ?? {})) as T
  } catch (e: unknown) {
    // Tauri rejects with the serialized error, which for this app is a plain
    // string — `error.rs`'s Serialize impl flattens every variant to one.
    return Promise.reject(typeof e === 'string' ? e : String(e))
  }
}

// --- driver handle ------------------------------------------------------

declare global {
  interface Window {
    /**
     * For an automated driver: what the "core" holds, so a test can assert on
     * values that are never supposed to reach the page. Reading the clipboard
     * here is how "the generated password was written but never rendered" is
     * checked from outside the app.
     */
    __mock: {
      clipboard: () => string | null
      store: () => Record<string, string>
      reset: () => void
    }
  }
}

window.__mock = {
  clipboard: () => clipboard,
  store: () => store,
  reset: () => {
    for (const key of Object.keys(store)) delete store[key]
    Object.assign(store, INITIAL)
  },
}
