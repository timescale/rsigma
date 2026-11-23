//! Line bookkeeping shared by the NDJSON sinks that write to a byte stream
//! (file and Unix socket): batches written in one go, and where a retried
//! delivery should resume.

use crate::io::DeliveryContext;

/// The NDJSON lines of one delivery, serialized into a single buffer so they
/// go out in one write, with the end offset of each line.
#[derive(Default)]
pub(crate) struct LineBatch {
    bytes: Vec<u8>,
    ends: Vec<usize>,
}

impl LineBatch {
    /// Append one line; the newline is added here.
    pub(crate) fn push(&mut self, json: &str) {
        self.bytes.extend_from_slice(json.as_bytes());
        self.bytes.push(b'\n');
        self.ends.push(self.bytes.len());
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// How many whole lines the first `written` bytes cover.
    pub(crate) fn complete_lines(&self, written: usize) -> usize {
        self.ends.partition_point(|&end| end <= written)
    }

    /// Byte offset where line `index` starts.
    pub(crate) fn line_start(&self, index: usize) -> usize {
        index.checked_sub(1).map_or(0, |i| self.ends[i])
    }

    /// Whether the first `written` bytes stop partway through a line.
    pub(crate) fn ends_mid_line(&self, written: usize) -> bool {
        written > self.line_start(self.complete_lines(written))
    }
}

/// Per-delivery progress a sink keeps across the worker's retries, so a retry
/// does not repeat what already went out.
///
/// The delivery context is shared by every sink a result fans out to, so
/// each sink keeps its own map, keyed by the context's sequence number. An
/// entry is removed when its delivery succeeds; [`Self::retain`] drops the
/// entries of deliveries the worker has finished with.
pub(crate) struct ResumeMap<T> {
    entries: Vec<(u64, T)>,
}

impl<T> Default for ResumeMap<T> {
    fn default() -> Self {
        ResumeMap {
            entries: Vec::new(),
        }
    }
}

impl<T> ResumeMap<T> {
    /// The progress recorded for this delivery. Always `None` without a
    /// context.
    pub(crate) fn get(&self, ctx: Option<&DeliveryContext>) -> Option<&T> {
        let seq = ctx?.seq();
        self.entries
            .iter()
            .find(|(entry, _)| *entry == seq)
            .map(|(_, progress)| progress)
    }

    /// Remember the progress of this delivery. A no-op without a context.
    pub(crate) fn record(&mut self, ctx: Option<&DeliveryContext>, progress: T) {
        let Some(ctx) = ctx else {
            return;
        };
        let seq = ctx.seq();
        match self.entries.iter_mut().find(|(entry, _)| *entry == seq) {
            Some((_, slot)) => *slot = progress,
            None => self.entries.push((seq, progress)),
        }
    }

    /// Forget this delivery.
    pub(crate) fn clear(&mut self, ctx: Option<&DeliveryContext>) {
        if let Some(ctx) = ctx {
            let seq = ctx.seq();
            self.entries.retain(|(entry, _)| *entry != seq);
        }
    }

    /// Keep only the deliveries in `ctxs`.
    pub(crate) fn retain<'a>(&mut self, ctxs: impl IntoIterator<Item = &'a DeliveryContext>) {
        if self.entries.is_empty() {
            return;
        }
        let keep: Vec<u64> = ctxs.into_iter().map(DeliveryContext::seq).collect();
        self.entries.retain(|(entry, _)| keep.contains(entry));
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

impl ResumeMap<usize> {
    /// Lines to skip for this delivery: 0 without a context and for a
    /// delivery with nothing recorded.
    pub(crate) fn start(&self, ctx: Option<&DeliveryContext>) -> usize {
        self.get(ctx).copied().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_offsets() {
        let mut batch = LineBatch::default();
        batch.push("ab");
        batch.push("cde");
        assert_eq!(batch.bytes(), b"ab\ncde\n");
        assert_eq!(batch.complete_lines(0), 0);
        assert_eq!(batch.complete_lines(2), 0);
        assert_eq!(batch.complete_lines(3), 1);
        assert_eq!(batch.complete_lines(6), 1);
        assert_eq!(batch.complete_lines(7), 2);
        assert!(!batch.ends_mid_line(0));
        assert!(batch.ends_mid_line(1));
        assert!(!batch.ends_mid_line(3));
        assert!(batch.ends_mid_line(4));
        assert!(!batch.ends_mid_line(7));
        assert_eq!(batch.line_start(0), 0);
        assert_eq!(batch.line_start(1), 3);
        assert_eq!(batch.line_start(2), 7);
    }

    #[test]
    fn resume_map_tracks_each_delivery() {
        let first = DeliveryContext::new();
        let second = DeliveryContext::new();
        let third = DeliveryContext::new();
        let mut resume = ResumeMap::default();
        resume.record(Some(&first), 2);
        resume.record(Some(&second), 1);
        assert_eq!(resume.start(Some(&first)), 2);
        assert_eq!(resume.start(Some(&second)), 1);
        assert_eq!(resume.start(Some(&third)), 0);
        assert_eq!(resume.start(None), 0);

        resume.record(Some(&first), 3);
        assert_eq!(resume.start(Some(&first)), 3);
        assert_eq!(resume.len(), 2);

        resume.clear(Some(&first));
        assert_eq!(resume.start(Some(&first)), 0);
        assert_eq!(resume.start(Some(&second)), 1);

        resume.record(None, 5);
        assert_eq!(resume.len(), 1, "no context records nothing");
    }

    #[test]
    fn retain_drops_finished_deliveries() {
        let kept = DeliveryContext::new();
        let finished = DeliveryContext::new();
        let mut resume = ResumeMap::default();
        resume.record(Some(&kept), 1);
        resume.record(Some(&finished), 1);
        resume.retain([&kept]);
        assert_eq!(resume.start(Some(&kept)), 1);
        assert_eq!(resume.start(Some(&finished)), 0);
        assert_eq!(resume.len(), 1);
    }
}
