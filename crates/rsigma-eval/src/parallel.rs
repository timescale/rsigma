//! Ordered batch maps that keep cheap batches on the calling thread.
//!
//! Forking a batch across the Rayon pool wakes idle workers, which spin and
//! go back to sleep once the batch is done. For a batch whose whole cost is
//! a few hundred microseconds, that wake-up costs more CPU and wall time than
//! the work itself.

#[cfg(feature = "parallel")]
use std::time::{Duration, Instant};

/// Projected batch cost at which the remaining items are mapped in parallel.
#[cfg(feature = "parallel")]
const PARALLEL_THRESHOLD: Duration = Duration::from_micros(500);

/// Map `items` in input order. Items are mapped on the calling thread until
/// the time spent so far projects the whole batch to cost at least
/// [`PARALLEL_THRESHOLD`]; the remaining items are then mapped across Rayon.
pub(crate) fn map_ordered<T, R, F>(items: &[T], f: F) -> Vec<R>
where
    T: Sync,
    R: Send,
    F: Fn(&T) -> R + Sync + Send,
{
    #[cfg(feature = "parallel")]
    {
        use rayon::prelude::*;

        let mut out = Vec::with_capacity(items.len());
        let start = Instant::now();
        for (index, item) in items.iter().enumerate() {
            out.push(f(item));
            let done = index + 1;
            if forks_after(start.elapsed(), done, items.len()) {
                out.par_extend(items[done..].par_iter().map(&f));
                break;
            }
        }
        out
    }
    #[cfg(not(feature = "parallel"))]
    {
        items.iter().map(f).collect()
    }
}

/// Whether the items left after `done` of `len` should go to Rayon, given
/// that the first `done` took `elapsed`.
#[cfg(feature = "parallel")]
fn forks_after(elapsed: Duration, done: usize, len: usize) -> bool {
    done < len && elapsed.as_nanos() * len as u128 >= PARALLEL_THRESHOLD.as_nanos() * done as u128
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cheap_items_keep_input_order() {
        let items: Vec<u32> = (0..1_000).collect();
        assert_eq!(
            map_ordered(&items, |i| i * 2),
            (0..1_000).map(|i| i * 2).collect::<Vec<_>>()
        );
    }

    #[test]
    fn expensive_items_keep_input_order() {
        let items: Vec<u32> = (0..64).collect();
        let out = map_ordered(&items, |i| {
            std::thread::sleep(std::time::Duration::from_micros(50));
            i + 1
        });
        assert_eq!(out, (1..=64).collect::<Vec<_>>());
    }

    #[test]
    fn empty_input_maps_to_nothing() {
        assert!(map_ordered(&[] as &[u8], |b| *b).is_empty());
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn a_cheap_batch_stays_on_the_calling_thread() {
        // A stall between two clock reads can fork a cheap batch, so one
        // attempt of several staying on the caller is enough.
        let stayed = (0..10).any(|_| {
            map_ordered(&[0u8; 4], |_| rayon::current_thread_index().is_some()) == [false; 4]
        });
        assert!(stayed);
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn an_expensive_batch_forks_after_its_first_item() {
        let items: Vec<u32> = (0..16).collect();
        let on_pool = map_ordered(&items, |_| {
            std::thread::sleep(Duration::from_micros(100));
            rayon::current_thread_index().is_some()
        });
        assert!(!on_pool[0], "the first item runs on the calling thread");
        assert!(on_pool[1..].iter().all(|pool| *pool), "{on_pool:?}");
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn the_fork_decision_projects_the_whole_batch() {
        let us = Duration::from_micros;
        // 128 items at 1 µs each project to 128 µs: stay on the caller.
        assert!(!forks_after(us(64), 64, 128));
        // 128 items at 4 µs each project to 512 µs: fork the rest.
        assert!(forks_after(us(16), 4, 128));
        // Exactly at the threshold forks.
        assert!(forks_after(us(250), 64, 128));
        assert!(!forks_after(us(250) - Duration::from_nanos(1), 64, 128));
        // One slow item in a large batch forks at once.
        assert!(forks_after(us(500), 1, 2));
        // Nothing is left to fork once every item is done.
        assert!(!forks_after(Duration::from_secs(1), 128, 128));
        assert!(!forks_after(Duration::from_secs(1), 1, 1));
        // Large inputs do not overflow the projection.
        assert!(forks_after(
            Duration::from_secs(365 * 24 * 3600),
            1,
            usize::MAX
        ));
        assert!(!forks_after(Duration::ZERO, usize::MAX - 1, usize::MAX));
    }
}
