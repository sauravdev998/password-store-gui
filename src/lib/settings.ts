import { useCallback, useEffect, useState } from 'react'
import { getSettings, setSettings, type EffectiveSettings, type Settings } from './commands'

/**
 * The app's settings, held once at the top and read from the core.
 *
 * This replaces the `localStorage` preference `prefs.ts` carried: the store
 * path, the clipboard window and the generated length are things the *core*
 * has to know, and a preference living in the webview could never have told it
 * any of them. Keeping all six in one file, resolved in one place against
 * `pass`'s own environment variables (ADR-11), is what makes the settings panel
 * able to say why a control it is showing has no effect.
 *
 * Nothing here is a secret — a path, four numbers, two booleans — so unlike a
 * revealed value this is ordinary state and may live for the app's lifetime.
 */
export type SettingsState = {
  /** `null` until the core has answered. Nothing should assume either way. */
  settings: EffectiveSettings | null
  /** Why settings could not be read at all, as opposed to a bad file. */
  error: string | null
  /** Persist a new configured set. Rejects with the core's own message. */
  save: (next: Settings) => Promise<void>
}

export function useSettings(): SettingsState {
  const [settings, setLoaded] = useState<EffectiveSettings | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let live = true
    getSettings()
      .then((loaded) => {
        if (live) {
          setLoaded(loaded)
          setError(null)
        }
      })
      .catch((e: unknown) => {
        // The app still works on built-in defaults, so this is reported rather
        // than fatal — but it is reported, because settings silently not
        // applying is exactly the confusion §4.1 principle 5 is about.
        if (live) setError(String(e))
      })
    return () => {
      live = false
    }
  }, [])

  const save = useCallback(async (next: Settings) => {
    // The core validates, so a refusal arrives as a rejection with a message
    // naming the setting — which the dialog shows verbatim. Nothing is applied
    // locally until the core has accepted it.
    const applied = await setSettings(next)
    setLoaded(applied)
    setError(null)
  }, [])

  return { settings, error, save }
}

/**
 * The values the rest of the app runs on, before the core has answered.
 *
 * These mirror the constants in `settings.rs`. They exist so that the window
 * has coherent behaviour during the first paint rather than, say, no idle lock
 * for however long the first IPC round trip takes — the direction to be wrong
 * in is the locked one. Keep them in step with the Rust side; when the two
 * disagree, the Rust side is right.
 */
export const FALLBACK = {
  lockAfterSecs: 15 * 60,
  lockOnBlur: true,
  openOnSelect: false,
} as const

/** What the app should do right now, whether or not settings have loaded. */
export function behaviour(settings: EffectiveSettings | null) {
  return {
    lockAfterSecs: settings?.lockAfterSecs.value ?? FALLBACK.lockAfterSecs,
    lockOnBlur: settings?.lockOnBlur.value ?? FALLBACK.lockOnBlur,
    openOnSelect: settings?.openOnSelect.value ?? FALLBACK.openOnSelect,
  }
}
