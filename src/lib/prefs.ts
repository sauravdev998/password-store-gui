import { useCallback, useEffect, useState } from 'react'

/**
 * UI preferences that live in the webview.
 *
 * `localStorage` is off limits for anything decrypted (CLAUDE.md, Frontend) —
 * but this is a boolean about how a pane arrives, not a secret, and keeping it
 * here means the preference works today rather than waiting on the settings
 * plumbing Phase 5 will bring. When that lands, this module is the one place
 * that has to move.
 */
const AUTO_OPEN = 'pgui.autoOpenEntries'

/**
 * Whether selecting an entry should decrypt it immediately.
 *
 * Off by default, and that default is the point. Reading an entry's shape means
 * running GnuPG, which can put a passphrase prompt on screen or set a security
 * key blinking — so it happens when the user asks for it, not because they
 * clicked a row to see what was in it. Anyone whose key is a file with a cached
 * agent can turn the wait off; anyone holding a YubiKey should not have to.
 */
export function useAutoOpen(): [boolean, (next: boolean) => void] {
  const [autoOpen, setAutoOpen] = useState(() => {
    try {
      return window.localStorage.getItem(AUTO_OPEN) === 'true'
    } catch {
      // Private modes and locked-down webviews can throw on access rather than
      // return null. The safe answer is the cautious one.
      return false
    }
  })

  const set = useCallback((next: boolean) => {
    setAutoOpen(next)
    try {
      window.localStorage.setItem(AUTO_OPEN, String(next))
    } catch {
      // The preference still holds for this session; it just will not survive
      // a restart. Not worth an error in front of the user.
    }
  }, [])

  // Two windows of the same app should not disagree about this.
  useEffect(() => {
    function onStorage(event: StorageEvent) {
      if (event.key === AUTO_OPEN) setAutoOpen(event.newValue === 'true')
    }
    window.addEventListener('storage', onStorage)
    return () => window.removeEventListener('storage', onStorage)
  }, [])

  return [autoOpen, set]
}
