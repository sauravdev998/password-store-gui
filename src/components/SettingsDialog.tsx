import { useState } from 'react'
import { Actions, Dialog, Field, FormError, inputClass } from './Dialog'
import { AlertIcon } from '../lib/icons'
import type { Decided, EffectiveSettings, Settings } from '../lib/commands'

/**
 * Everything the user can decide, in one place.
 *
 * Two rules shape this form, and both come from the fact that `pass` already
 * lets three of these be set from the environment (ADR-11):
 *
 * - **A control that cannot work is not offered.** Where a `PASSWORD_STORE_*`
 *   variable is in charge the field is shown fixed, with the variable named and
 *   the instruction to change it there. Offering an editable box that silently
 *   loses to the environment would be the exact failure §4.1 principle 5 is
 *   about.
 * - **The form edits what was *configured*, not what is in force.** The
 *   placeholder shows the value that applies when a field is left empty, so
 *   "not set" stays a state the user can see and return to rather than being
 *   flattened into whatever happened to be resolved the first time this opened.
 *
 * The `pass` variable names are the one place this app spells the format's own
 * vocabulary out, and deliberately: a user has to type that exact string into a
 * shell profile to act on it, which is the same test that keeps *store* and
 * *GnuPG* untranslated (Open Decision 6).
 */
type Props = {
  settings: EffectiveSettings
  onSave: (next: Settings) => Promise<void>
  onClose: () => void
}

/** The idle timeouts on offer, in seconds. `0` is the honest way to say never. */
const LOCK_CHOICES: { secs: number; label: string }[] = [
  { secs: 60, label: 'After 1 minute' },
  { secs: 5 * 60, label: 'After 5 minutes' },
  { secs: 15 * 60, label: 'After 15 minutes' },
  { secs: 30 * 60, label: 'After 30 minutes' },
  { secs: 60 * 60, label: 'After 1 hour' },
  { secs: 0, label: 'Never' },
]

export function SettingsDialog({ settings, onSave, onClose }: Props) {
  // Seeded from what was configured, so an empty box means "not set here" and
  // keeps meaning that. The numbers are held as strings because a half-typed
  // number is a state the user passes through on the way to a whole one.
  const [storeDir, setStoreDir] = useState(settings.configured.storeDir ?? '')
  const [clipTime, setClipTime] = useState(numberText(settings.configured.clipTimeSecs))
  const [length, setLength] = useState(numberText(settings.configured.generatedLength))
  const [lockAfter, setLockAfter] = useState(settings.lockAfterSecs.value)
  const [lockOnBlur, setLockOnBlur] = useState(settings.lockOnBlur.value)
  const [openOnSelect, setOpenOnSelect] = useState(settings.openOnSelect.value)

  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function submit(event: React.FormEvent) {
    event.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await onSave({
        storeDir: blankToNull(storeDir),
        clipTimeSecs: parseNumber(clipTime),
        generatedLength: parseNumber(length),
        // No "unset" worth exposing for these three: a lock timeout is always
        // in force, and a checkbox has nowhere to draw a third state.
        lockAfterSecs: lockAfter,
        lockOnBlur,
        openOnSelect,
      })
      onClose()
    } catch (e: unknown) {
      // Shown verbatim: the core names the setting and the bounds, which is
      // more than this form knows.
      setError(String(e))
      setBusy(false)
    }
  }

  return (
    <Dialog
      title="Settings"
      description="These apply the next time each one is used — nothing here changes your store."
      onClose={onClose}
    >
      <form onSubmit={submit}>
        <div className="max-h-[60vh] space-y-5 overflow-y-auto px-5 py-4">
          {settings.problem && (
            <div
              role="alert"
              className="flex items-start gap-2.5 rounded-panel border border-danger-line bg-danger-soft px-3 py-2.5 text-xs leading-relaxed text-danger-ink"
            >
              <AlertIcon className="mt-px size-3.5 shrink-0" />
              <span className="min-w-0 break-words">
                Your saved settings could not be read, so the built-in ones are in use.{' '}
                {settings.problem}
              </span>
            </div>
          )}

          <Field
            label="Store location"
            hint={
              <Pinned by="PASSWORD_STORE_DIR" source={settings.storeDir.source}>
                The folder holding your encrypted entries. Leave it empty for the usual place.
              </Pinned>
            }
          >
            {({ id, describedBy }) => (
              <input
                id={id}
                aria-describedby={describedBy}
                type="text"
                spellCheck={false}
                className={`${inputClass} font-mono`}
                disabled={settings.storeDir.source === 'environment'}
                value={settings.storeDir.source === 'environment' ? settings.storeDir.value : storeDir}
                placeholder={settings.storeDir.value}
                onChange={(event) => setStoreDir(event.target.value)}
              />
            )}
          </Field>

          <Field
            label="Clear the clipboard after"
            hint={
              <Pinned by="PASSWORD_STORE_CLIP_TIME" source={settings.clipTimeSecs.source}>
                Seconds a copied password stays on the clipboard. It is cleared only if it still
                holds what this app put there.
              </Pinned>
            }
          >
            {({ id, describedBy }) => (
              <NumberInput
                id={id}
                describedBy={describedBy}
                suffix="seconds"
                decided={settings.clipTimeSecs}
                value={clipTime}
                onChange={setClipTime}
              />
            )}
          </Field>

          <Field
            label="Generated password length"
            hint={
              <Pinned by="PASSWORD_STORE_GENERATED_LENGTH" source={settings.generatedLength.source}>
                What the new-entry form starts at. You can still change it for one entry.
              </Pinned>
            }
          >
            {({ id, describedBy }) => (
              <NumberInput
                id={id}
                describedBy={describedBy}
                suffix="characters"
                decided={settings.generatedLength}
                value={length}
                onChange={setLength}
              />
            )}
          </Field>

          <Field
            label="Lock the window when left alone"
            hint="Locking hides everything on screen and closes anything you had open, including an entry you were editing. Nothing is lost from your store."
          >
            {({ id, describedBy }) => (
              <select
                id={id}
                aria-describedby={describedBy}
                className={inputClass}
                value={lockAfter}
                onChange={(event) => setLockAfter(Number(event.target.value))}
              >
                {choices(lockAfter).map((choice) => (
                  <option key={choice.secs} value={choice.secs}>
                    {choice.label}
                  </option>
                ))}
              </select>
            )}
          </Field>

          <Check
            checked={lockOnBlur}
            onChange={setLockOnBlur}
            label="Hide revealed values when I switch to another window"
            hint="Showing them again means decrypting again, so your system may ask for your passphrase or your security key may need another touch. Turn this off if that is a cost you would rather not pay each time."
          />

          <Check
            checked={openOnSelect}
            onChange={setOpenOnSelect}
            label="Open entries as soon as I select them"
            hint="Off by default: opening an entry decrypts it, and this makes that happen on every click rather than when you ask."
          />

          {settings.path && (
            <p className="border-t border-line pt-3.5 text-xs leading-relaxed text-ink-faint">
              Saved in <span className="font-mono break-all">{settings.path}</span>
            </p>
          )}
        </div>

        {/* Outside the scrolling area, deliberately. This form is long enough
            to scroll, and an error rendered at the end of it appears below the
            fold — so pressing Save on a value the core refuses looked like
            pressing Save and having nothing happen at all. A refusal has to
            land next to the button that caused it. */}
        {error && (
          <div className="border-t border-line px-5 pt-3.5">
            <FormError message={error} />
          </div>
        )}

        <Actions busy={busy} submitLabel="Save" onCancel={onClose} />
      </form>
    </Dialog>
  )
}

/**
 * A number box that shows what applies when it is left empty.
 *
 * Disabled outright when a variable owns the value: there is nothing useful to
 * type into it.
 */
function NumberInput({
  id,
  describedBy,
  suffix,
  decided,
  value,
  onChange,
}: {
  id: string
  describedBy: string | undefined
  suffix: string
  decided: Decided<number>
  value: string
  onChange: (next: string) => void
}) {
  const pinned = decided.source === 'environment'

  return (
    <div className="flex items-center gap-2.5">
      <input
        id={id}
        aria-describedby={describedBy}
        type="number"
        inputMode="numeric"
        className={`${inputClass} w-28 tabular-nums`}
        disabled={pinned}
        value={pinned ? String(decided.value) : value}
        placeholder={String(decided.value)}
        onChange={(event) => onChange(event.target.value)}
      />
      <span className="text-xs text-ink-muted">{suffix}</span>
    </div>
  )
}

/**
 * A hint that says who is in charge of the setting above it.
 *
 * When the answer is the environment it replaces the ordinary explanation
 * rather than joining it: what the field means matters less than the fact that
 * typing in it would do nothing, and where to go instead.
 */
function Pinned({
  by,
  source,
  children,
}: {
  by: string
  source: Decided<unknown>['source']
  children: React.ReactNode
}) {
  if (source !== 'environment') return <>{children}</>

  return (
    <>
      Set by <span className="font-mono">{by}</span> in your environment, which this app does not
      override. Change it there, or unset it to use the value below.
    </>
  )
}

/** A checkbox with the explanation the choice needs to be made honestly. */
function Check({
  checked,
  onChange,
  label,
  hint,
}: {
  checked: boolean
  onChange: (next: boolean) => void
  label: string
  hint: string
}) {
  return (
    <label className="flex cursor-pointer gap-2.5 select-none">
      <input
        type="checkbox"
        checked={checked}
        className="mt-0.5 size-3.5 shrink-0 accent-[var(--c-accent)]"
        onChange={(event) => onChange(event.target.checked)}
      />
      <span className="min-w-0">
        <span className="block text-xs font-medium text-ink">{label}</span>
        <span className="mt-1 block text-xs leading-relaxed text-ink-muted">{hint}</span>
      </span>
    </label>
  )
}

/**
 * The timeout choices, including whatever is currently in force.
 *
 * A settings file written by hand — or by a later version with a different
 * list — must not be silently rounded to the nearest option the moment this
 * dialog opens.
 */
function choices(current: number) {
  if (LOCK_CHOICES.some((choice) => choice.secs === current)) return LOCK_CHOICES
  return [...LOCK_CHOICES, { secs: current, label: `After ${current} seconds` }]
}

const numberText = (value: number | null) => (value === null ? '' : String(value))

const blankToNull = (value: string) => (value.trim() === '' ? null : value.trim())

/** An unparseable box reads as "not set" rather than as zero. */
function parseNumber(value: string): number | null {
  const trimmed = value.trim()
  if (trimmed === '') return null
  const parsed = Number(trimmed)
  return Number.isInteger(parsed) && parsed >= 0 ? parsed : null
}
