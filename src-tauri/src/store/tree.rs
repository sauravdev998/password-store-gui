//! The store tree.
//!
//! `prs-lib`'s `SecretIter` is flat — it yields every `.gpg` file with a
//! store-relative name and no directory nodes (ADR-4a), so the hierarchy the UI
//! browses is reconstructed here from those names.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use serde::Serialize;

use crate::store::EntryName;

/// A node in the store tree.
///
/// A directory and an entry may share a `path` (`Email/` alongside
/// `Email.gpg`); `pass` allows it, and `kind` is what disambiguates them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Node {
    Dir {
        /// Last path component — the label the UI renders.
        name: String,
        path: EntryName,
        children: Vec<Node>,
    },
    Entry {
        name: String,
        path: EntryName,
    },
}

impl Node {
    pub fn name(&self) -> &str {
        match self {
            Self::Dir { name, .. } | Self::Entry { name, .. } => name,
        }
    }

    pub fn path(&self) -> &EntryName {
        match self {
            Self::Dir { path, .. } | Self::Entry { path, .. } => path,
        }
    }

    fn is_dir(&self) -> bool {
        matches!(self, Self::Dir { .. })
    }
}

/// The whole store tree.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Tree {
    /// Top-level nodes, directories first, then case-insensitively by name.
    pub nodes: Vec<Node>,

    /// Files present on disk whose names we refuse to handle, as read from
    /// disk (lossily, since such a name may not be UTF-8).
    ///
    /// Surfaced rather than dropped: an entry that exists but is invisible in
    /// the GUI is worse than one shown as unusable.
    pub unsupported: Vec<String>,
}

/// Intermediate trie: directories keyed by component, entries by leaf name.
#[derive(Default)]
struct Branch<'a> {
    dirs: BTreeMap<&'a str, Branch<'a>>,
    entries: BTreeMap<&'a str, &'a EntryName>,
}

impl<'a> Branch<'a> {
    fn insert(&mut self, name: &'a EntryName) {
        let mut branch = self;
        let components: Vec<_> = name.components().collect();
        // `components` is never empty: `EntryName` rejects empty names.
        let Some((leaf, parents)) = components.split_last() else {
            return;
        };
        for component in parents {
            branch = branch.dirs.entry(component).or_default();
        }
        branch.entries.insert(leaf, name);
    }

    /// Flatten into sorted nodes. `prefix` is the branch's own path.
    fn into_nodes(self, prefix: &str) -> Vec<Node> {
        let join = |component: &str| {
            if prefix.is_empty() {
                component.to_owned()
            } else {
                format!("{prefix}/{component}")
            }
        };

        let mut nodes: Vec<Node> = Vec::with_capacity(self.dirs.len() + self.entries.len());

        for (component, branch) in self.dirs {
            let path = join(component);
            let children = branch.into_nodes(&path);
            // A directory's path is only ever built from components that
            // already passed validation, so it cannot fail to revalidate;
            // if it somehow did, dropping the subtree is the safe outcome.
            let Ok(path) = EntryName::new(path) else {
                continue;
            };
            nodes.push(Node::Dir {
                name: component.to_owned(),
                path,
                children,
            });
        }

        for (component, name) in self.entries {
            nodes.push(Node::Entry {
                name: component.to_owned(),
                path: name.clone(),
            });
        }

        nodes.sort_by(compare);
        nodes
    }
}

/// Directories first, then case-insensitive by name, with a case-sensitive
/// tiebreak so the order is total and stable.
fn compare(a: &Node, b: &Node) -> Ordering {
    b.is_dir()
        .cmp(&a.is_dir())
        .then_with(|| a.name().to_lowercase().cmp(&b.name().to_lowercase()))
        .then_with(|| a.name().cmp(b.name()))
}

/// Build the tree from a flat list of entry names.
pub fn build(names: &[EntryName]) -> Vec<Node> {
    let mut root = Branch::default();
    for name in names {
        root.insert(name);
    }
    root.into_nodes("")
}

#[cfg(test)]
// Test code handles fixtures, never real secrets.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn names(list: &[&str]) -> Vec<EntryName> {
        list.iter().map(|n| EntryName::new(*n).unwrap()).collect()
    }

    /// Render as `dir/` and `entry` lines for readable assertions.
    fn render(nodes: &[Node], depth: usize) -> Vec<String> {
        let mut out = Vec::new();
        for node in nodes {
            let indent = "  ".repeat(depth);
            match node {
                Node::Dir { name, children, .. } => {
                    out.push(format!("{indent}{name}/"));
                    out.extend(render(children, depth + 1));
                }
                Node::Entry { name, .. } => out.push(format!("{indent}{name}")),
            }
        }
        out
    }

    #[test]
    fn nests_by_component() {
        let tree = build(&names(&[
            "Email/work/gmail.com",
            "Email/personal",
            "wifi",
            "Bank/chase",
        ]));

        assert_eq!(
            render(&tree, 0),
            vec![
                "Bank/",
                "  chase",
                "Email/",
                "  work/",
                "    gmail.com",
                "  personal",
                "wifi",
            ]
        );
    }

    #[test]
    fn directory_paths_are_full_paths() {
        let tree = build(&names(&["a/b/c"]));
        let Node::Dir { path, children, .. } = &tree[0] else {
            panic!("expected a directory");
        };
        assert_eq!(path.as_str(), "a");
        let Node::Dir { path, .. } = &children[0] else {
            panic!("expected a directory");
        };
        assert_eq!(path.as_str(), "a/b");
    }

    #[test]
    fn sorts_case_insensitively_with_directories_first() {
        let tree = build(&names(&["zeta", "Alpha", "beta/x", "Beta2/y"]));
        assert_eq!(
            tree.iter().map(Node::name).collect::<Vec<_>>(),
            vec!["beta", "Beta2", "Alpha", "zeta"]
        );
    }

    #[test]
    fn a_directory_and_an_entry_may_share_a_name() {
        let tree = build(&names(&["Email", "Email/work"]));
        assert_eq!(tree.len(), 2);
        assert!(tree[0].is_dir());
        assert!(!tree[1].is_dir());
        assert_eq!(tree[0].path(), tree[1].path());
    }

    #[test]
    fn empty_store_is_an_empty_tree() {
        assert!(build(&[]).is_empty());
    }
}
