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
    // Re-read on the way in. While the interval was off, `now` was frozen at
    // whenever it last ran — so the first render after a countdown starts would
    // otherwise subtract a stale clock from a fresh deadline and claim a
    // 45-second clipboard window had 82 seconds left. Costs one render; buys a
    // countdown that is right from its first frame.
    setNow(Date.now())
    const timer = window.setInterval(() => setNow(Date.now()), intervalMs)
    return () => window.clearInterval(timer)
  }, [intervalMs])

  return now
}
