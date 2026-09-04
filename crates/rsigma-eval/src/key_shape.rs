//! Deterministic greedy clustering for event field-key shapes.

use std::collections::BTreeSet;

/// Cluster ordered items by Jaccard similarity to each cluster's first item.
///
/// The caller owns cluster state and may reject otherwise-similar merges with
/// `can_merge`. Cluster indexes are stable for a stable input order.
pub(crate) fn cluster_by_key_shape<I, C>(
    items: &[I],
    similarity: f64,
    keys: impl Fn(&I) -> &[String],
    seed_keys: impl Fn(&C) -> &[String],
    from_item: impl Fn(&I) -> C,
    can_merge: impl Fn(&C, &I) -> bool,
    merge: impl Fn(&mut C, &I),
) -> Vec<C> {
    let mut clusters = Vec::new();
    for item in items {
        let mut placed = false;
        for cluster in &mut clusters {
            if jaccard(keys(item), seed_keys(cluster)) >= similarity && can_merge(cluster, item) {
                merge(cluster, item);
                placed = true;
                break;
            }
        }
        if !placed {
            clusters.push(from_item(item));
        }
    }
    clusters
}

fn jaccard(a: &[String], b: &[String]) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    let a: BTreeSet<&String> = a.iter().collect();
    let b: BTreeSet<&String> = b.iter().collect();
    let intersection = a.intersection(&b).count();
    let union = a.union(&b).count();
    if union == 0 {
        0.0
    } else {
        intersection as f64 / union as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq)]
    struct Cluster {
        seed: Vec<String>,
        members: Vec<usize>,
    }

    fn cluster(items: &[Vec<String>]) -> Vec<Cluster> {
        cluster_by_key_shape(
            items,
            0.6,
            Vec::as_slice,
            |cluster: &Cluster| &cluster.seed,
            |keys| Cluster {
                seed: keys.clone(),
                members: Vec::new(),
            },
            |_, _| true,
            |cluster, keys| {
                cluster.members.push(
                    items
                        .iter()
                        .position(|candidate| std::ptr::eq(candidate, keys))
                        .unwrap(),
                );
            },
        )
    }

    #[test]
    fn equivalent_key_sets_get_stable_cluster_indexes() {
        let items = vec![
            vec!["a".into(), "b".into(), "c".into()],
            vec!["a".into(), "b".into()],
            vec!["x".into(), "y".into()],
            vec!["a".into(), "b".into(), "c".into()],
        ];
        let first = cluster(&items);
        let second = cluster(&items);
        assert_eq!(first, second);
        assert_eq!(first.len(), 2);
        assert_eq!(first[0].seed, items[0]);
        assert_eq!(first[1].seed, items[2]);
    }
}
