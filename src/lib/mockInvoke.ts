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
 *
 * Keep those four in step when the core changes, or this stops testing the app
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

// --- the command surface ------------------------------------------------

const handlers: Record<string, (args: Args) => unknown> = {
  core_version: () => '0.1.0-mock',

  list_tree: () => ({ nodes: buildTree(), unsupported: UNSUPPORTED }),

  store_has_history: () => !NO_GIT,

  generate_defaults: () => ({ length: 25, symbols: true }),

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
