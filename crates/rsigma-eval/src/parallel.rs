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
        let threshold = PARALLEL_THRESHOLD.as_nanos();
        let len = items.len() as u128;
        let start = Instant::now();
        for (index, item) in items.iter().enumerate() {
            out.push(f(item));
            let done = index + 1;
            if done < items.len() && start.elapsed().as_nanos() * len >= threshold * done as u128 {
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
}
