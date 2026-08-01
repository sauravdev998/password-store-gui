import { useEffect, useState } from 'react'

/**
 * The wall clock in milliseconds, re-read every `intervalMs`.
 *
 * Countdowns in this app store a *deadline* and subtract the clock from it,
 * rather than decrementing a counter on a timer. A decrementing counter drifts
 * whenever the machine sleeps, a frame is late, or the tab is throttled — and
 * the two things counting down here are a clipboard that is about to be wiped
 * and a one-time password that is about to expire, neither of which should be
 * shown as having more life left than it does.
 *
 * Pass `null` to stop ticking: a view with nothing to count down should not be
 * re-rendering twice a second.
 */
export function useNow(intervalMs: number | null): number {
  const [now, setNow] = useState(() => Date.now())

  useEffect(() => {
    if (intervalMs === null) return
    const timer = window.setInterval(() => setNow(Date.now()), intervalMs)
    return () => window.clearInterval(timer)
  }, [intervalMs])

  return now
}
