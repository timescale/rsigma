//! Depth limits for deserializing recursive trees.
//!
//! A deserializer recurses once per tree level before the outer value is
//! built, so a depth limit has to be enforced on the way down rather than by
//! walking the finished tree. Each recursive field is deserialized through a
//! function that holds a [`DepthGuard`] on a per-thread counter. Shared by the
//! recursive types of this crate and `rsigma-ir`.

use std::cell::Cell;
use std::thread::LocalKey;

use serde::{Deserialize, Deserializer};

use crate::condition::MAX_CONDITION_TREE_DEPTH;

/// One level below the root of a tree being deserialized on this thread.
pub struct DepthGuard(&'static LocalKey<Cell<usize>>);

impl DepthGuard {
    /// Enter a level below the root, failing when the tree would have more
    /// than `max` levels in all. `depth` counts the levels below the root.
    pub fn enter<E: serde::de::Error>(
        depth: &'static LocalKey<Cell<usize>>,
        max: usize,
        what: &str,
    ) -> Result<Self, E> {
        let next = depth.get() + 1;
        if next >= max {
            return Err(E::custom(format!("{what} exceeds maximum depth ({max})")));
        }
        depth.set(next);
        Ok(DepthGuard(depth))
    }
}

impl Drop for DepthGuard {
    fn drop(&mut self) {
        self.0.set(self.0.get() - 1);
    }
}

thread_local! {
    static CONDITION_DEPTH: Cell<usize> = const { Cell::new(0) };
}

/// Deserialize the children of a condition node, one level deeper.
pub(crate) fn nested_condition<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    let _guard = DepthGuard::enter(&CONDITION_DEPTH, MAX_CONDITION_TREE_DEPTH, "condition tree")?;
    T::deserialize(deserializer)
}
