import { useState } from 'react'
import type { Node } from '../lib/commands'

/**
 * The store browser.
 *
 * Renders names only — a node carries no decrypted content, so nothing here is
 * secret. Expansion state is local because it is pure UI: it survives a re-render
 * and nothing else.
 */
type Props = {
  nodes: Node[]
  /** Path of the selected entry, or `null`. */
  selected: string | null
  onSelect: (path: string) => void
}

export function Tree({ nodes, selected, onSelect }: Props) {
  const [expanded, setExpanded] = useState<ReadonlySet<string>>(new Set())

  function toggle(path: string) {
    setExpanded((prev) => {
      const next = new Set(prev)
      if (!next.delete(path)) next.add(path)
      return next
    })
  }

  if (nodes.length === 0) {
    return <p className="px-2 py-1 text-xs text-neutral-500">No entries.</p>
  }

  return (
    <ul className="text-sm">
      {nodes.map((node) => (
        // A folder and an entry may share a path (`Email/` beside `Email.gpg`),
        // so the kind is part of the identity.
        <Row
          key={`${node.kind}:${node.path}`}
          node={node}
          depth={0}
          expanded={expanded}
          selected={selected}
          onToggle={toggle}
          onSelect={onSelect}
        />
      ))}
    </ul>
  )
}

type RowProps = {
  node: Node
  depth: number
  expanded: ReadonlySet<string>
  selected: string | null
  onToggle: (path: string) => void
  onSelect: (path: string) => void
}

function Row({ node, depth, expanded, selected, onToggle, onSelect }: RowProps) {
  const indent = { paddingLeft: `${depth * 0.75 + 0.5}rem` }

  if (node.kind === 'dir') {
    const open = expanded.has(node.path)
    return (
      <li>
        <button
          type="button"
          style={indent}
          className="flex w-full items-center gap-1 rounded py-1 pr-2 text-left hover:bg-neutral-100 dark:hover:bg-neutral-800"
          aria-expanded={open}
          onClick={() => onToggle(node.path)}
        >
          <span className="w-3 shrink-0 text-xs text-neutral-400">{open ? '▾' : '▸'}</span>
          <span className="truncate font-medium">{node.name}</span>
        </button>
        {open && (
          <ul>
            {node.children.map((child) => (
              <Row
                key={`${child.kind}:${child.path}`}
                node={child}
                depth={depth + 1}
                expanded={expanded}
                selected={selected}
                onToggle={onToggle}
                onSelect={onSelect}
              />
            ))}
          </ul>
        )}
      </li>
    )
  }

  const active = node.path === selected
  return (
    <li>
      <button
        type="button"
        style={indent}
        className={`flex w-full items-center gap-1 rounded py-1 pr-2 text-left ${
          active
            ? 'bg-blue-600 text-white'
            : 'hover:bg-neutral-100 dark:hover:bg-neutral-800'
        }`}
        aria-current={active ? 'true' : undefined}
        onClick={() => onSelect(node.path)}
      >
        <span className="w-3 shrink-0" />
        <span className="truncate">{node.name}</span>
      </button>
    </li>
  )
}
