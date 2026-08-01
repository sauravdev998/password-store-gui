import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { ChevronIcon, EntryIcon, FolderIcon, PlusIcon } from '../lib/icons'
import type { Node } from '../lib/commands'

/**
 * The store browser.
 *
 * Renders names only — a node carries no decrypted content, so nothing here is
 * secret and nothing here decrypts. Expansion state is local because it is pure
 * UI: it survives a re-render and nothing else.
 *
 * It is a real ARIA tree, driven by the keyboard the way one is expected to be:
 * arrows move and open, Home/End jump, and typing letters seeks. That is not
 * decoration on a password manager — reaching for a credential happens in the
 * middle of some other task, usually with the hands already on the keys.
 *
 * The visible rows are flattened into one list rather than rendered as nested
 * `ul`s. `aria-level` / `aria-posinset` / `aria-setsize` carry the shape for
 * assistive technology, and a flat list is what makes "the next row down" a
 * single index step instead of a tree walk.
 */
type Props = {
  nodes: Node[]
  /** Path of the selected entry, or `null`. */
  selected: string | null
  onSelect: (path: string) => void
  /** Offered from the empty state, where there is nothing else to do. */
  onCreate: () => void
  /**
   * Narrow the tree to names containing this, matched against the whole path.
   *
   * Names only. Searching what entries *contain* would mean decrypting every
   * one of them to answer a keystroke — a pinentry prompt per character, or a
   * security key blinking through the alphabet — which is §4.1 principle 1's
   * central case, not an edge of it.
   */
  filter?: string
}

type FlatRow = {
  node: Node
  key: string
  /** 1-based, as `aria-level` counts. */
  level: number
  posInSet: number
  setSize: number
  parentKey: string | null
  open: boolean
}

/** A folder and an entry may share a path (`Email/` beside `Email.gpg`). */
const keyOf = (node: Node) => `${node.kind}:${node.path}`

function flatten(
  nodes: Node[],
  expanded: ReadonlySet<string>,
  level: number,
  parentKey: string | null,
  out: FlatRow[],
): FlatRow[] {
  nodes.forEach((node, index) => {
    const key = keyOf(node)
    const open = node.kind === 'dir' && expanded.has(node.path)
    out.push({ node, key, level, posInSet: index + 1, setSize: nodes.length, parentKey, open })
    if (node.kind === 'dir' && open) flatten(node.children, expanded, level + 1, key, out)
  })
  return out
}

/**
 * Keep the branches that lead to a match, and drop the rest.
 *
 * A folder whose own name matches is kept whole — searching `Email` should show
 * what is in `Email`, not an empty folder — while a folder that merely contains
 * a match keeps only the matching part of itself.
 */
function prune(nodes: Node[], needle: string): Node[] {
  const kept: Node[] = []
  for (const node of nodes) {
    const hit = node.path.toLowerCase().includes(needle)
    if (node.kind === 'entry') {
      if (hit) kept.push(node)
      continue
    }
    if (hit) {
      kept.push(node)
      continue
    }
    const children = prune(node.children, needle)
    if (children.length > 0) kept.push({ ...node, children })
  }
  return kept
}

/** Every folder path in a set of nodes, so a filtered tree opens itself. */
function allFolders(nodes: Node[], out: Set<string> = new Set()): Set<string> {
  for (const node of nodes) {
    if (node.kind === 'dir') {
      out.add(node.path)
      allFolders(node.children, out)
    }
  }
  return out
}

export function Tree({ nodes, selected, onSelect, onCreate, filter = '' }: Props) {
  const [expanded, setExpanded] = useState<ReadonlySet<string>>(new Set())

  const needle = filter.trim().toLowerCase()
  const shown = useMemo(() => (needle ? prune(nodes, needle) : nodes), [nodes, needle])

  // While filtering, every surviving folder is open: the point of the filter is
  // that a match is on screen, and a match hidden inside a collapsed folder is
  // a result the user cannot see.
  const openFolders = useMemo(
    () => (needle ? allFolders(shown) : expanded),
    [needle, shown, expanded],
  )
  const rows = useMemo(() => flatten(shown, openFolders, 1, null, []), [shown, openFolders])

  // Roving tabindex: the tree is one tab stop, and this is the row that owns
  // it. Falls back to the first row so the tree is always reachable.
  const [focusedKey, setFocusedKey] = useState<string | null>(null)
  const activeKey = rows.some((row) => row.key === focusedKey) ? focusedKey : (rows[0]?.key ?? null)

  const refs = useRef(new Map<string, HTMLButtonElement>())
  // Only move focus when this component caused the change, so re-rendering for
  // an unrelated reason never steals it from elsewhere in the window.
  const shouldFocus = useRef(false)

  useEffect(() => {
    if (!shouldFocus.current || !activeKey) return
    shouldFocus.current = false
    refs.current.get(activeKey)?.focus()
  }, [activeKey])

  const move = useCallback((key: string) => {
    shouldFocus.current = true
    setFocusedKey(key)
  }, [])

  const toggle = useCallback((path: string, next?: boolean) => {
    setExpanded((prev) => {
      const set = new Set(prev)
      const open = next ?? !set.has(path)
      if (open) set.add(path)
      else set.delete(path)
      return set
    })
  }, [])

  // Typeahead. Letters typed in quick succession seek the next row whose name
  // starts with them, wrapping — standard tree behaviour, and what the keyboard
  // is expected to do inside a tree. The search box above is the other half:
  // this one moves within what is shown, that one changes what is shown.
  const seek = useRef({ buffer: '', at: 0 })

  function typeahead(char: string, fromIndex: number) {
    const now = Date.now()
    const state = seek.current
    state.buffer = now - state.at > 700 ? char : state.buffer + char
    state.at = now

    const needle = state.buffer.toLowerCase()
    // A repeated single letter cycles through matches rather than sticking.
    const repeated = needle.length > 1 && [...needle].every((c) => c === needle[0])
    const probe = repeated ? needle[0] : needle
    const start = repeated || needle.length === 1 ? fromIndex + 1 : fromIndex

    for (let i = 0; i < rows.length; i += 1) {
      const row = rows[(start + i + rows.length) % rows.length]
      if (row.node.name.toLowerCase().startsWith(probe)) {
        move(row.key)
        return
      }
    }
  }

  function onKeyDown(event: React.KeyboardEvent, row: FlatRow, index: number) {
    const at = (next: number) => {
      const clamped = Math.max(0, Math.min(rows.length - 1, next))
      move(rows[clamped].key)
    }

    switch (event.key) {
      case 'ArrowDown':
        at(index + 1)
        break
      case 'ArrowUp':
        at(index - 1)
        break
      case 'ArrowRight':
        if (row.node.kind === 'dir' && !row.open) toggle(row.node.path, true)
        else if (row.node.kind === 'dir') at(index + 1)
        else return
        break
      case 'ArrowLeft':
        if (row.node.kind === 'dir' && row.open) toggle(row.node.path, false)
        else if (row.parentKey) move(row.parentKey)
        else return
        break
      case 'Home':
        at(0)
        break
      case 'End':
        at(rows.length - 1)
        break
      case 'Enter':
      case ' ':
        if (row.node.kind === 'dir') toggle(row.node.path)
        else onSelect(row.node.path)
        break
      default:
        // Single printable characters only: never swallow a modifier chord.
        if (event.key.length !== 1 || event.metaKey || event.ctrlKey || event.altKey) return
        typeahead(event.key, index)
        break
    }
    event.preventDefault()
  }

  if (needle && rows.length === 0) {
    return (
      <p className="px-3 py-6 text-center text-xs leading-relaxed text-ink-muted">
        No entry name contains <span className="font-medium text-ink">{filter.trim()}</span>.
      </p>
    )
  }

  if (nodes.length === 0) {
    return (
      <div className="px-3 py-6 text-center">
        <p className="text-sm font-medium text-ink">This store is empty</p>
        <p className="mt-1 text-xs leading-relaxed text-ink-muted">
          Add the first entry, or open one added with <code className="font-mono">pass</code> or
          another client.
        </p>
        <button
          type="button"
          className="mt-3 inline-flex items-center gap-1.5 rounded-row border border-line-strong/45 px-2.5 py-1 text-xs font-medium text-ink-muted transition-colors hover:border-line-strong hover:bg-raised hover:text-ink"
          onClick={onCreate}
        >
          <PlusIcon className="size-3.5" />
          New entry
        </button>
      </div>
    )
  }

  return (
    <ul role="tree" aria-label="Password store" className="py-1 text-sm">
      {rows.map((row, index) => {
        const { node } = row
        const isDir = node.kind === 'dir'
        const active = !isDir && node.path === selected

        return (
          <li
            key={row.key}
            role="treeitem"
            aria-level={row.level}
            aria-posinset={row.posInSet}
            aria-setsize={row.setSize}
            aria-expanded={isDir ? row.open : undefined}
            aria-selected={isDir ? undefined : active}
          >
            <button
              type="button"
              ref={(el) => {
                if (el) refs.current.set(row.key, el)
                else refs.current.delete(row.key)
              }}
              tabIndex={row.key === activeKey ? 0 : -1}
              // The indent is data, so it is computed rather than tokenised.
              // 0.6rem per level keeps a deep store legible in a 17rem sidebar.
              style={{ paddingLeft: `${0.5 + row.level * 0.6}rem` }}
              className={`flex w-full items-center gap-1.5 rounded-row py-1.5 pr-2 text-left transition-colors duration-100 ${
                active
                  ? 'bg-sel font-medium text-sel-ink'
                  : 'text-ink hover:bg-sel/60 focus-visible:bg-sel/60'
              }`}
              onFocus={() => setFocusedKey(row.key)}
              onKeyDown={(event) => onKeyDown(event, row, index)}
              onClick={() => {
                move(row.key)
                if (isDir) toggle(node.path)
                else onSelect(node.path)
              }}
            >
              {isDir ? (
                <ChevronIcon
                  className={`size-3.5 shrink-0 text-ink-faint transition-transform duration-150 ${
                    row.open ? 'rotate-90' : ''
                  }`}
                />
              ) : (
                <span className="size-3.5 shrink-0" />
              )}
              {isDir ? (
                <FolderIcon className="size-4 shrink-0 text-ink-faint" />
              ) : (
                <EntryIcon
                  className={`size-4 shrink-0 ${active ? 'text-ink-muted' : 'text-ink-faint'}`}
                />
              )}
              <span className="truncate">
                <Highlighted text={node.name} needle={needle} />
              </span>
            </button>
          </li>
        )
      })}
    </ul>
  )
}

/**
 * A name with the searched-for part picked out.
 *
 * The filter matches the whole path, so a row can be shown because its *folder*
 * matched and have nothing to mark in its own name — which is why this falls
 * through to plain text rather than assuming a hit.
 */
function Highlighted({ text, needle }: { text: string; needle: string }) {
  const at = needle ? text.toLowerCase().indexOf(needle) : -1
  if (at === -1) return <>{text}</>

  return (
    <>
      {text.slice(0, at)}
      <mark className="rounded-[2px] bg-accent/25 text-inherit">
        {text.slice(at, at + needle.length)}
      </mark>
      {text.slice(at + needle.length)}
    </>
  )
}
