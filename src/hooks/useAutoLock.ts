import { useEffect, useRef } from 'react'

/**
 * Invariant 7, which in this app is entirely a webview concern.
 *
 * The core keeps no decrypted cache — a reveal is its own decrypt and nothing
 * survives the command that produced it — so there is nothing in Rust for an
 * auto-lock to clear. What *does* hold plaintext is this side: a revealed row,
 * the edit form's whole body (ADR-8), and an opened past version (ADR-10). Two
 * events act on them, and they act differently on purpose:
 *
 * - **Leaving the window** hides what is revealed and nothing else. It must not
 *   close a form the user is filling in, because switching windows to read
 *   something is a normal step in the middle of writing an entry — and it must
 *   not touch the clipboard, because pasting somewhere else is what a copy is
 *   *for*. The clipboard has its own timer (Invariant 6), which is the right
 *   mechanism for it.
 * - **Going idle** locks the window: everything on screen goes, dialogs
 *   included. Unsaved input is lost, which is defensible only because idle
 *   means the user has not typed for minutes — by definition they are not
 *   filling anything in.
 *
 * Neither one flushes `gpg-agent`. That cache belongs to the user's agent and
 * their `default-cache-ttl`, and reaching in to reset it would be us managing a
 * credential we deliberately do not handle (Invariant 3).
 */
type AutoLock = {
  /** Idle seconds before {@link onIdle}. `0` disables the idle lock. */
  idleSecs: number
  /** Whether leaving the window should call {@link onBlur}. */
  onBlurEnabled: boolean
  /** Stop watching — already locked, so there is nothing left to lock. */
  enabled: boolean
  onIdle: () => void
  onBlur: () => void
}

/** What counts as the user still being there. */
const ACTIVITY = ['pointerdown', 'keydown', 'wheel', 'mousemove', 'touchstart'] as const

/**
 * How often the idle check runs.
 *
 * A poll rather than a timer reset per event: `mousemove` fires continuously,
 * and tearing down and rebuilding a timeout on each one would be far more work
 * than comparing two numbers every few seconds. The cost is that the lock can
 * be late by up to this interval, which for a timeout measured in minutes is
 * not a meaningful difference.
 */
const TICK_MS = 5_000

export function useAutoLock({ idleSecs, onBlurEnabled, enabled, onIdle, onBlur }: AutoLock) {
  // Held in refs so that a changed callback does not tear down the listeners
  // and reset the idle clock — which would make a re-render count as activity.
  const idle = useRef(onIdle)
  const blur = useRef(onBlur)
  idle.current = onIdle
  blur.current = onBlur

  useEffect(() => {
    if (!enabled || idleSecs <= 0) return

    let last = Date.now()
    const touch = () => {
      last = Date.now()
    }
    for (const event of ACTIVITY) {
      window.addEventListener(event, touch, { passive: true })
    }

    const timer = window.setInterval(() => {
      if (Date.now() - last >= idleSecs * 1000) idle.current()
    }, TICK_MS)

    return () => {
      window.clearInterval(timer)
      for (const event of ACTIVITY) window.removeEventListener(event, touch)
    }
  }, [enabled, idleSecs])

  useEffect(() => {
    if (!enabled || !onBlurEnabled) return

    // The DOM event rather than Tauri's `onFocusChanged`, so the same code path
    // runs under `pnpm dev:mock` in a plain browser tab — which is the only way
    // this frontend has ever been driven. In the packaged app the webview fills
    // the window, so the two fire together.
    const onWindowBlur = () => blur.current()
    window.addEventListener('blur', onWindowBlur)
    return () => window.removeEventListener('blur', onWindowBlur)
  }, [enabled, onBlurEnabled])
}
