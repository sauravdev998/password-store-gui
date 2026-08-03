import { useState } from 'react'
import { AlertIcon, CheckIcon, KeyIcon, LockIcon, StoreIcon } from '../lib/icons'
import { inputClass } from './Dialog'
import {
  createKey,
  initStore,
  type KeyInfo,
  type SetupStatus,
  type WriteReceipt,
} from '../lib/commands'

/**
 * Nothing → a working store, without a terminal (Phase 7, ADR-7).
 *
 * **Full-window rather than a dialog**, unlike every other screen here. A
 * dialog is modal *over* something, and there is nothing behind this one: no
 * tree, no entry, no store. It is shown when the app finds a machine in one of
 * the three states onboarding covers, and it is the only thing on screen until
 * that stops being true.
 *
 * **The passphrase is never ours** (Invariant 3). Creating a key hands the job
 * to GnuPG, whose own window asks for it — so the button below says that will
 * happen *before* it is pressed, and a separate OS window appearing is the
 * design working rather than something to apologize for. There is no passphrase
 * field on this screen and there must never be one.
 *
 * **Vocabulary** (Open Decision 6): no `.gpg-id`, no "recipients", no
 * "pinentry". Two words stay untranslated because the user needs them to act
 * outside the app — **store**, which is what every other client calls it, and
 * **GnuPG**, which is what they must search for when it is missing — and both
 * appear beside an explanation.
 */
type Props = {
  status: SetupStatus
  /** Re-ask the core what it finds — after installing GnuPG, or on a retry. */
  onRecheck: () => void
  /** The store now exists. `receipt` says whether a history was started. */
  onCreated: (receipt: WriteReceipt) => void
}

/**
 * What to tell someone with no usable GnuPG, on the system they are on.
 *
 * The two branches say opposite things, and ADR-14 is why. Where GnuPG ships
 * inside the app, reaching this screen means our own copy would not start —
 * nothing the user can install fixes that, so telling them to go and install
 * something would send them to fix the wrong thing (§4.1 principle 5). Linux is
 * not bundled for, so there the old advice is still the true and useful one.
 */
function installHint(): { name: string; detail: string } {
  const platform = navigator.userAgent
  if (platform.includes('Win') || platform.includes('Mac')) {
    return {
      name: 'Reinstalling should fix this',
      detail:
        'This app comes with its own copy of GnuPG, and that copy could not be started — so it is probably damaged or incomplete rather than missing. Reinstalling the app replaces it.',
    }
  }
  return {
    name: 'GnuPG',
    detail:
      'Install the gnupg package with your system\'s package manager, along with a pinentry program, then come back to this window.',
  }
}

export function Onboarding({ status, onRecheck, onCreated }: Props) {
  if (status.gpgProblem !== null) {
    return <MissingGnupg problem={status.gpgProblem} onRecheck={onRecheck} />
  }
  return <Setup status={status} onCreated={onCreated} />
}

/**
 * The one state the app cannot do anything about.
 *
 * §4.1 principle 5's sharpest test — a named fix beats "gpg not found" — but
 * which fix is named now depends on the platform; see `installHint`. Rare since
 * ADR-14, and deliberately kept rather than deleted: Linux is not bundled for,
 * and a bundle can be damaged.
 *
 * The underlying message is kept as well, in small print. It is the only thing
 * that distinguishes "nothing was found" from "something was found and would
 * not run", and somebody will need it.
 */
function MissingGnupg({ problem, onRecheck }: { problem: string; onRecheck: () => void }) {
  const hint = installHint()

  return (
    <Frame
      icon={<AlertIcon className="size-8 text-danger-ink" />}
      title="GnuPG is not available"
      lead={
        <>
          Your passwords are protected by <strong className="font-medium text-ink">GnuPG</strong>,
          the encryption program this store is built on. Nothing can be read or written until a
          working copy of it is available.
        </>
      }
    >
      <div className="rounded-panel border border-line bg-raised/60 px-4 py-3.5 text-sm leading-relaxed text-ink-muted">
        <p>
          <strong className="font-semibold text-ink">{hint.name}</strong> — {hint.detail}
        </p>
        <p className="mt-2 font-mono text-[11px] break-words text-ink-faint">{problem}</p>
      </div>

      <button
        type="button"
        onClick={onRecheck}
        className="mt-5 self-start rounded-row bg-accent px-4 py-2 text-sm font-semibold text-accent-on shadow-lift transition-[filter] duration-150 hover:brightness-105 active:brightness-95"
      >
        Check again
      </button>
    </Frame>
  )
}

/** Choosing a key, then making the store. */
function Setup({ status, onCreated }: { status: SetupStatus; onCreated: Props['onCreated'] }) {
  const [keys, setKeys] = useState<KeyInfo[]>(status.keys)
  const [selected, setSelected] = useState<string | null>(status.keys[0]?.id ?? null)
  /** Whether the new-key form is showing. Open by default with nothing to pick. */
  const [making, setMaking] = useState(status.keys.length === 0)
  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
  /** Ids created in this session, which are the ones that need the backup note. */
  const [justMade, setJustMade] = useState<string[]>([])
  // Defaulted by whether git could actually record anything (ADR-7): without an
  // identity, every later save would report a failed commit.
  const [versioned, setVersioned] = useState(status.gitIdentity)
  const [creatingKey, setCreatingKey] = useState(false)
  const [busy, setBusy] = useState(false)
  /**
   * Why making a key was refused, shown **inside step 1**.
   *
   * Kept apart from {@link error} rather than sharing one slot with it. Found by
   * driving this: a single message at the foot of the page put the refusal for
   * a key next to the button that creates the *store*, so a dismissed
   * passphrase prompt read as though the store had failed — and on a short
   * window it was below the fold entirely. It is the same defect the settings
   * panel had in Phase 5, and the same fix: a refusal belongs beside the
   * control that caused it.
   */
  const [keyError, setKeyError] = useState<string | null>(null)
  /** Why creating the store was refused. Belongs by its own button. */
  const [error, setError] = useState<string | null>(null)

  async function makeKey(event: React.FormEvent) {
    event.preventDefault()
    if (creatingKey) return
    setCreatingKey(true)
    setKeyError(null)
    try {
      const key = await createKey(name, email)
      setKeys((previous) => [key, ...previous.filter((other) => other.id !== key.id)])
      setSelected(key.id)
      setJustMade((previous) => [...previous, key.id])
      setMaking(false)
      setName('')
      setEmail('')
    } catch (e: unknown) {
      // Includes dismissing GnuPG's own window, which creates nothing and is a
      // choice rather than a fault — the form stays exactly as it was and the
      // button can simply be pressed again.
      setKeyError(String(e))
    } finally {
      setCreatingKey(false)
    }
  }

  async function create() {
    if (busy || !selected) return
    setBusy(true)
    setError(null)
    try {
      onCreated(await initStore([selected], versioned))
    } catch (e: unknown) {
      setError(String(e))
      setBusy(false)
    }
  }

  return (
    <Frame
      icon={<StoreIcon className="size-8 text-ink-faint" />}
      title="Set up your password store"
      lead={
        <>
          A <strong className="font-medium text-ink">store</strong> is a folder of encrypted files on
          this computer — the same format the <code className="text-xs">pass</code> command line tool
          and other clients use. Two things are needed: a key to encrypt with, and somewhere to keep
          it.
        </>
      }
    >
      <Section
        step={1}
        icon={<KeyIcon className="size-4 text-ink-faint" />}
        title="The key that opens your passwords"
      >
        {keys.length > 0 && (
          <ul className="space-y-1.5" role="radiogroup" aria-label="Choose a key">
            {keys.map((key) => (
              <KeyChoice
                key={key.id}
                info={key}
                chosen={key.id === selected}
                fresh={justMade.includes(key.id)}
                onChoose={() => setSelected(key.id)}
              />
            ))}
          </ul>
        )}

        {justMade.length > 0 && (
          // ADR-7: key backup is deliberately out of scope, and the honest
          // consequence is said at the moment the key is made rather than
          // discovered later, when it cannot be acted on.
          <Warning>
            <strong className="font-semibold">This key is the only way in.</strong> If this computer
            is lost and the key with it, every password in the store becomes unreadable — a copy of
            the store does not help, and neither does its history. Back the key up somewhere safe.
          </Warning>
        )}

        {making ? (
          <form onSubmit={makeKey} className="space-y-2.5">
            {keys.length === 0 && (
              <p className="text-xs leading-relaxed text-ink-muted">
                There is no key on this computer yet, so one needs to be made. The name and address
                only label the key — they are what other people see if you ever share a store.
              </p>
            )}
            <div className="flex gap-2">
              <input
                value={name}
                onChange={(event) => setName(event.target.value)}
                placeholder="Your name"
                aria-label="Your name"
                autoFocus={keys.length === 0}
                className={inputClass}
              />
              <input
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                type="email"
                placeholder="you@example.com"
                aria-label="Your email address"
                className={inputClass}
              />
            </div>

            {/* Said before the button is pressed, never after (§4.1
                principle 1). The window is GnuPG's own and appears outside this
                app, which is surprising enough to be worth predicting. */}
            <p className="text-xs leading-relaxed text-ink-muted">
              GnuPG will open its own window to ask you for a passphrase for the new key. This app
              never sees it. Choosing a good one matters: it is what protects the key if someone
              gets hold of this computer.
            </p>

            {/* Directly above the button that raised it, and inside step 1 —
                a refusal shown beside the store's own button would read as the
                store having failed. */}
            {keyError && <Refusal message={keyError} />}

            <div className="flex items-center gap-2">
              <button
                type="submit"
                disabled={creatingKey || !name.trim() || !email.trim()}
                className="rounded-row bg-accent px-3.5 py-1.5 text-xs font-semibold text-accent-on shadow-lift transition-[filter] duration-150 hover:brightness-105 active:brightness-95 disabled:cursor-not-allowed disabled:opacity-55"
              >
                {creatingKey ? 'Waiting for GnuPG…' : 'Create key'}
              </button>
              {keys.length > 0 && !creatingKey && (
                <button
                  type="button"
                  onClick={() => setMaking(false)}
                  className="rounded-row px-2 py-1.5 text-xs font-medium text-ink-muted transition-colors hover:text-ink"
                >
                  Cancel
                </button>
              )}
              {creatingKey && (
                <span className="text-xs text-ink-faint">
                  Answer the GnuPG window to finish, or dismiss it to stop.
                </span>
              )}
            </div>
          </form>
        ) : (
          <button
            type="button"
            onClick={() => setMaking(true)}
            className="self-start rounded-row border border-line-strong/45 px-2.5 py-1.5 text-xs font-medium text-ink-muted transition-colors hover:border-line-strong hover:bg-raised hover:text-ink"
          >
            Make a new key instead
          </button>
        )}
      </Section>

      <Section
        step={2}
        icon={<StoreIcon className="size-4 text-ink-faint" />}
        title="Where the store will live"
      >
        <p className="rounded-row border border-line bg-raised/60 px-2.5 py-2 font-mono text-[11px] break-all text-ink-muted">
          {status.storePath}
        </p>
        <p className="text-xs leading-relaxed text-ink-muted">
          {status.store === 'missing'
            ? 'This folder will be created.'
            : 'This folder already exists and is empty, so it will be used as it is.'}{' '}
          You can move the store later from Settings.
        </p>

        <label className="flex items-start gap-2.5 text-xs leading-relaxed text-ink-muted">
          <input
            type="checkbox"
            checked={versioned}
            onChange={(event) => setVersioned(event.target.checked)}
            className="mt-0.5 size-3.5 shrink-0 accent-[var(--color-accent)]"
          />
          <span>
            <strong className="font-medium text-ink">Keep a history of changes.</strong> Every change
            is recorded, so a password you delete or overwrite can still be recovered — and the store
            can later be synced between computers.
            {!status.gitIdentity && (
              // The reason the box is off, said where the box is. Turning it on
              // is allowed: it is the user's machine and they may know
              // something we do not.
              <span className="mt-1 block text-ink-faint">
                Git is not set up with a name and email on this computer, so recording changes would
                fail until it is. That is why this is off.
              </span>
            )}
          </span>
        </label>
      </Section>

      {error && <Refusal message={error} />}

      <div className="flex items-center gap-3">
        <button
          type="button"
          onClick={create}
          disabled={busy || !selected}
          className="rounded-row bg-accent px-4 py-2 text-sm font-semibold text-accent-on shadow-lift transition-[filter] duration-150 hover:brightness-105 active:brightness-95 disabled:cursor-not-allowed disabled:opacity-55"
        >
          {busy ? 'Creating…' : 'Create my store'}
        </button>
        {!selected && (
          <span className="text-xs text-ink-faint">Choose or make a key to continue.</span>
        )}
      </div>
    </Frame>
  )
}

/** One key to pick, described the way the keys panel describes them. */
function KeyChoice({
  info,
  chosen,
  fresh,
  onChoose,
}: {
  info: KeyInfo
  chosen: boolean
  fresh: boolean
  onChoose: () => void
}) {
  return (
    <li>
      <label
        className={`flex cursor-pointer items-start gap-2.5 rounded-row border px-2.5 py-2 transition-colors ${
          chosen ? 'border-accent/60 bg-accent/8' : 'border-line bg-raised/60 hover:border-line-strong'
        }`}
      >
        <input
          type="radio"
          name="key"
          checked={chosen}
          onChange={onChoose}
          className="mt-0.5 size-3.5 shrink-0 accent-[var(--color-accent)]"
        />
        <span className="min-w-0 flex-1">
          <span className="flex items-center gap-1.5">
            <span className="truncate text-xs font-medium text-ink">{info.label ?? info.id}</span>
            {fresh && (
              <span className="flex shrink-0 items-center gap-0.5 rounded-full bg-accent/12 px-1.5 py-px text-[10px] font-medium text-accent">
                <CheckIcon className="size-2.5" />
                Just made
              </span>
            )}
          </span>
          {/* The id verbatim: it is the string that identifies this key
              anywhere else, which is the test Open Decision 6 sets for showing
              one at all. */}
          <span className="mt-0.5 block truncate font-mono text-[11px] text-ink-faint" title={info.id}>
            {info.id}
          </span>
        </span>
      </label>
    </li>
  )
}

/** The page: one column, centred, scrolling as a whole. */
function Frame({
  icon,
  title,
  lead,
  children,
}: {
  icon: React.ReactNode
  title: string
  lead: React.ReactNode
  children: React.ReactNode
}) {
  return (
    <div className="h-full overflow-y-auto bg-canvas text-ink">
      <div className="mx-auto flex min-h-full w-full max-w-xl flex-col justify-center px-8 py-12">
        <div className="flex flex-col">
          {icon}
          <h1 className="mt-4 text-lg font-semibold tracking-tight text-ink">{title}</h1>
          <p className="mt-2 text-sm leading-relaxed text-ink-muted">{lead}</p>
        </div>
        <div className="mt-7 flex flex-col gap-5">{children}</div>
      </div>
    </div>
  )
}

/** One numbered part of the setup. */
function Section({
  step,
  icon,
  title,
  children,
}: {
  step: number
  icon: React.ReactNode
  title: string
  children: React.ReactNode
}) {
  return (
    <section className="rounded-panel border border-line bg-panel px-4 py-3.5">
      <h2 className="flex items-center gap-2 text-xs font-semibold tracking-tight text-ink">
        <span className="flex size-4 shrink-0 items-center justify-center rounded-full bg-raised text-[10px] text-ink-faint tabular-nums">
          {step}
        </span>
        {icon}
        {title}
      </h2>
      <div className="mt-3 flex flex-col gap-3">{children}</div>
    </section>
  )
}

/**
 * Why something was refused, shown next to whatever was refused.
 *
 * There are two of these on this screen rather than one shared slot, and that
 * is the point: which button failed is half of what the message means.
 */
function Refusal({ message }: { message: string }) {
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

/** Something the user would regret not reading. */
function Warning({ children }: { children: React.ReactNode }) {
  return (
    <div
      role="alert"
      className="flex items-start gap-2.5 rounded-panel border border-danger-line bg-danger-soft px-3 py-2.5 text-xs leading-relaxed text-danger-ink"
    >
      <LockIcon className="mt-px size-3.5 shrink-0" />
      <span className="min-w-0">{children}</span>
    </div>
  )
}
