//! Per-field bloom filter pre-filtering for substring matchers.
//!
//! At rule load time, walks every compiled rule and collects the positive
//! substring needles per field across the entire rule set. Each set is hashed
//! into a small bloom filter keyed by trigrams. At eval time, the engine
//! probes the event's field values: if no trigram from a pattern is present,
//! every positive substring matcher on that field is guaranteed to return
//! `false`, so individual rule items can be short-circuited without
//! evaluating their matcher.
//!
//! # Correctness
//!
//! The bloom filter is over-approximate: it can say "maybe match" when no
//! pattern actually matches, but never "no match" when one does. Combined
//! with the eval engine only consulting the bloom for **positive** substring
//! matchers, this guarantees zero false negatives at the Sigma semantic
//! layer regardless of where the matcher sits in the condition tree (under
//! `Not`, inside `not 1 of ...`, or in any nested boolean expression).
//!
//! # Pre-filtering scope
//!
//! Only positive `Contains` / `StartsWith` / `EndsWith` / `AhoCorasickSet`
//! matchers contribute to the bloom. `Exact` matchers are intentionally
//! excluded: the rule index already pre-filters those at the rule level. By
//! the time a rule reaches `evaluate_rule`, `Exact` items have either been
//! validated by the index or come from a partially-indexable rule that needs
//! direct evaluation anyway.
//!
//! # Length cutoff
//!
//! Trigram extraction is `O(field_value.len())`. For very long haystacks the
//! pre-check can cost more than the matchers themselves, so probes against
//! values longer than [`MAX_BLOOM_SCAN_BYTES`] are skipped (returning
//! [`BloomVerdict::SkippedTooLong`]).
//!
//! # Memory budget
//!
//! Total bloom memory is capped at [`DEFAULT_MAX_TOTAL_BYTES`]. When the
//! computed size exceeds the budget, fields with the lowest bits-per-pattern
//! density are disabled until the total fits.
//!
//! # Disabled fields
//!
//! A field the index decided not to filter (a sub-trigram needle, a filter
//! that would be too small to help, or budget eviction) is recorded as
//! [`FieldFilter::Disabled`] rather than left out of the map. An absent field
//! means no loaded rule has a positive substring needle on it, so the
//! incremental append path may start a filter there from the new rule alone.
//! A disabled field stays disabled until the next full rebuild, because a
//! filter built from later rules would not cover the earlier ones.

use std::collections::HashMap;
use std::hash::{BuildHasher, Hasher};

use crate::compiler::{CompiledDetection, CompiledRule};
use crate::event::{Event, EventValue};
use crate::matcher::CompiledMatcher;

/// Bytes per trigram window.
pub(crate) const NGRAM_SIZE: usize = 3;

/// Skip the bloom probe entirely for field values longer than this. Above
/// this threshold the trigram sweep starts to compete with the matcher's
/// own work; a 4 KB cap matches typical Windows event log fields without
/// penalizing CommandLine outliers that are still under it.
pub(crate) const MAX_BLOOM_SCAN_BYTES: usize = 4096;

/// Default memory ceiling shared across all per-field filters.
pub(crate) const DEFAULT_MAX_TOTAL_BYTES: usize = 1024 * 1024;

/// Target false-positive rate for individual filters.
const TARGET_FPR: f64 = 0.01;

/// Lower bound for bits-per-pattern. Below this density the FPR is too
/// high for the filter to provide useful pre-filtering: the engine probes
/// once per trigram in a haystack so even a 1% per-probe FPR compounds into
/// a high false-positive rate over a 30-character field. Bumping this to 16
/// pushes per-probe FPR below 0.1% for typical pattern counts while still
/// keeping the per-field memory cost negligible.
const MIN_BITS_PER_PATTERN: usize = 16;

/// Per-field hard cap. Pathological rule sets with thousands of patterns
/// per field still fit under this without bloating the engine.
const MAX_BYTES_PER_FIELD: usize = 64 * 1024;

/// What the bloom filter could prove about an event's field value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BloomVerdict {
    /// No trigram from any positive substring pattern is present in the
    /// field value. Any positive substring matcher on this field will
    /// return `false`; the eval engine can short-circuit.
    DefinitelyNoMatch,
    /// At least one trigram could match; the engine must evaluate the
    /// matcher directly.
    MaybeMatch,
}

/// Pre-filter lookup interface used by the eval functions.
///
/// The eval helpers in [`crate::compiler`] are generic over `B: BloomLookup`
/// so the same code services both:
/// - The public `evaluate_rule` path, which passes a [`NoBloom`] zero-sized
///   stub. The compiler monomorphizes the matcher dispatch with no extra
///   work per call.
/// - The engine path with a real [`BloomCache`], where positive substring
///   items short-circuit on `DefinitelyNoMatch`.
pub(crate) trait BloomLookup {
    fn verdict_for_field(&self, field: &str) -> BloomVerdict;
}

/// Zero-sized implementation that disables pre-filtering. Every probe
/// answers [`BloomVerdict::MaybeMatch`], so generic eval code falls through
/// to direct matcher evaluation.
pub(crate) struct NoBloom;

impl BloomLookup for NoBloom {
    #[inline(always)]
    fn verdict_for_field(&self, _field: &str) -> BloomVerdict {
        BloomVerdict::MaybeMatch
    }
}

/// Fixed seeds for the bloom hasher.
///
/// `BuildHasherDefault<ahash::AHasher>` derives its keys from ahash's
/// runtime RNG: constant within a process but different across runs. That
/// made the filter's exact bit layout, and therefore which non-matching
/// inputs happen to be false positives, vary run to run. Pinning explicit
/// seeds makes the filter deterministic across processes and platforms.
/// Correctness is unaffected either way: the bloom only ever over-approximates
/// (no false negatives) regardless of seed. The values are arbitrary fixed
/// constants (digits of pi).
const BLOOM_HASH_SEEDS: [u64; 4] = [
    0x243f_6a88_85a3_08d3,
    0x1319_8a2e_0370_7344,
    0xa409_3822_299f_31d0,
    0x082e_fa98_ec4e_6c89,
];

fn bloom_hasher() -> ahash::RandomState {
    ahash::RandomState::with_seeds(
        BLOOM_HASH_SEEDS[0],
        BLOOM_HASH_SEEDS[1],
        BLOOM_HASH_SEEDS[2],
        BLOOM_HASH_SEEDS[3],
    )
}

/// Bit-array bloom filter over trigrams. Each trigram is hashed once with
/// AHash, and its `k` bit positions are the outputs of a SplitMix64 stream
/// seeded with that hash (see [`probe_position`]).
struct FieldBloom {
    bits: Vec<u64>,
    num_bits: usize,
    num_hashes: u32,
    hasher_factory: ahash::RandomState,
}

impl FieldBloom {
    fn new_with_capacity(n_items: usize) -> Option<Self> {
        if n_items == 0 {
            return None;
        }
        // Standard sizing: m = ceil(-n * ln(p) / (ln 2)^2). With p=1% this
        // is ~9.585 n.
        let m_ideal = (-(n_items as f64) * TARGET_FPR.ln() / 2.0_f64.ln().powi(2)).ceil() as usize;
        let mut num_bits = m_ideal.max(MIN_BITS_PER_PATTERN * n_items);
        // Round up to a multiple of 64 so storage maps cleanly onto u64 limbs.
        num_bits = num_bits.div_ceil(64) * 64;

        let max_bits = MAX_BYTES_PER_FIELD * 8;
        if num_bits > max_bits {
            num_bits = max_bits;
        }

        if num_bits / 8 < n_items.div_ceil(8) {
            // Too few bits per pattern to be useful.
            return None;
        }

        // k = (m/n) ln 2, rounded; clamp to a sane range.
        let k_ideal = ((num_bits as f64 / n_items as f64) * 2.0_f64.ln()).round() as u32;
        let num_hashes = k_ideal.clamp(2, 12);

        Some(Self {
            bits: vec![0u64; num_bits / 64],
            num_bits,
            num_hashes,
            hasher_factory: bloom_hasher(),
        })
    }

    fn byte_size(&self) -> usize {
        self.bits.len() * 8
    }

    fn insert_trigram(&mut self, trigram: &[u8]) {
        let hash = self.hash(trigram);
        for i in 0..u64::from(self.num_hashes) {
            let pos = probe_position(hash, i, self.num_bits);
            self.bits[pos / 64] |= 1 << (pos % 64);
        }
    }

    fn contains_trigram(&self, trigram: &[u8]) -> bool {
        let hash = self.hash(trigram);
        for i in 0..u64::from(self.num_hashes) {
            let pos = probe_position(hash, i, self.num_bits);
            if self.bits[pos / 64] & (1 << (pos % 64)) == 0 {
                return false;
            }
        }
        true
    }

    fn hash(&self, trigram: &[u8]) -> u64 {
        let mut hasher = self.hasher_factory.build_hasher();
        hasher.write(trigram);
        hasher.finish()
    }
}

/// The `i`-th bit position of a trigram with hash `hash` in a filter of
/// `num_bits` bits.
///
/// Positions are the SplitMix64 outputs of a stream seeded with `hash`, so
/// the `k` probes of one trigram are effectively independent. Classic double
/// hashing (`h1 + i * h2`) puts them on an arithmetic progression instead:
/// with `num_bits` a multiple of 64, an even `h2` revisits a few positions,
/// and progressions of different trigrams overlap far more than random sets
/// do. On the 64- and 128-bit filters most fields get, that raised the
/// false-positive rate by more than an order of magnitude above the sizing
/// target.
#[inline]
fn probe_position(hash: u64, i: u64, num_bits: usize) -> usize {
    let mut z = hash.wrapping_add(i.wrapping_add(1).wrapping_mul(0x9e37_79b9_7f4a_7c15));
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^= z >> 31;
    (z % num_bits as u64) as usize
}

/// Minimum rule-count growth before the doubling watermark trips a full
/// rebuild. Below this, every rule append takes the incremental path; the
/// floor stops the index from thrashing on the first handful of rules
/// where the doubling target ratchet (1 -> 2 -> 4 -> 8) would otherwise
/// rebuild on almost every add.
pub(crate) const INCREMENTAL_REBUILD_FLOOR: usize = 64;

/// The index's state for one field that carries positive substring needles.
enum FieldFilter {
    /// Every needle on the field is represented in this bloom.
    Filtered(FieldBloom),
    /// The field is deliberately unfiltered: probes answer `MaybeMatch`.
    Disabled,
}

/// Per-field bloom filters built from the union of every positive substring
/// needle across all compiled rules.
pub(crate) struct FieldBloomIndex {
    /// `field_name → filter state`. Fields without any positive substring
    /// needles are absent from the map. Probes against absent and
    /// [`FieldFilter::Disabled`] fields return `MaybeMatch` and the engine
    /// evaluates as usual.
    filters: HashMap<String, FieldFilter>,
    /// Rule count at the most recent full rebuild. `should_rebuild` uses
    /// this to schedule the next rebuild via a doubling watermark, so the
    /// amortized append cost stays O(1) per rule.
    rebuild_baseline: usize,
}

impl FieldBloomIndex {
    pub(crate) fn empty() -> Self {
        Self {
            filters: HashMap::new(),
            rebuild_baseline: 0,
        }
    }

    /// Build the index from a rule slice, respecting the default memory
    /// budget.
    pub(crate) fn build(rules: &[CompiledRule]) -> Self {
        Self::build_with_budget(rules, DEFAULT_MAX_TOTAL_BYTES)
    }

    pub(crate) fn build_with_budget(rules: &[CompiledRule], max_total_bytes: usize) -> Self {
        let mut field_needles: HashMap<String, Vec<String>> = HashMap::new();
        for rule in rules {
            for detection in rule.detections.values() {
                collect_positive_substring_needles(detection, &mut field_needles);
            }
        }

        // Build filters per field, then enforce the total memory budget.
        struct Built {
            field: String,
            bloom: FieldBloom,
            n_patterns: usize,
        }

        let mut filters: HashMap<String, FieldFilter> = HashMap::new();
        let mut built: Vec<Built> = Vec::new();
        for (field, mut needles) in field_needles {
            // Deduplicate so the bit count reflects unique pattern strings.
            needles.sort();
            needles.dedup();
            match build_field_bloom(&needles) {
                Some(bloom) => built.push(Built {
                    field,
                    bloom,
                    n_patterns: needles.len(),
                }),
                None => {
                    filters.insert(field, FieldFilter::Disabled);
                }
            }
        }

        // Total budget enforcement: drop the lowest-density filters first.
        let mut total: usize = built.iter().map(|b| b.bloom.byte_size()).sum();
        if total > max_total_bytes {
            built.sort_by(|a, b| {
                let da = a.bloom.byte_size() as f64 / a.n_patterns.max(1) as f64;
                let db = b.bloom.byte_size() as f64 / b.n_patterns.max(1) as f64;
                // Higher bytes-per-pattern = lower density per bit = drop first.
                db.partial_cmp(&da).unwrap_or(std::cmp::Ordering::Equal)
            });
            while total > max_total_bytes {
                if let Some(victim) = built.pop() {
                    total = total.saturating_sub(victim.bloom.byte_size());
                    filters.insert(victim.field, FieldFilter::Disabled);
                } else {
                    break;
                }
            }
        }

        filters.extend(
            built
                .into_iter()
                .map(|b| (b.field, FieldFilter::Filtered(b.bloom))),
        );
        Self {
            filters,
            rebuild_baseline: rules.len(),
        }
    }

    /// Fold a single rule's positive substring needles into the existing
    /// per-field blooms.
    ///
    /// Cost is bounded by the rule's detection tree size, not by the total
    /// rule count. Trigrams from the rule are inserted into each affected
    /// field's existing bloom; fields no earlier rule had needles on get a
    /// freshly sized bloom built against just this rule's trigram count.
    /// The global memory budget is **not** re-enforced here: each append
    /// can push total usage past the configured cap, which the next full
    /// rebuild (scheduled by `should_rebuild`) restores. Treat the budget as
    /// an amortized soft target, not a hard real-time ceiling.
    ///
    /// Probe semantics are preserved on every step. A `DefinitelyNoMatch`
    /// verdict from this index after `append_rule` is still correct: the
    /// new rule's trigrams are present in the relevant filter immediately,
    /// so any haystack containing one of those trigrams answers
    /// `MaybeMatch` and the engine evaluates the rule as usual. A
    /// [`FieldFilter::Disabled`] field is left alone, since earlier rules'
    /// needles on it are in no filter.
    pub(crate) fn append_rule(&mut self, rule: &CompiledRule) {
        let mut field_needles: HashMap<String, Vec<String>> = HashMap::new();
        for detection in rule.detections.values() {
            collect_positive_substring_needles(detection, &mut field_needles);
        }

        for (field, mut needles) in field_needles {
            needles.sort();
            needles.dedup();
            if needles.is_empty() {
                continue;
            }
            match self.filters.get_mut(&field) {
                Some(FieldFilter::Disabled) => {}
                Some(filter) if !needles_are_representable(&needles) => {
                    // Keeping the filter would let the probe answer
                    // `DefinitelyNoMatch` for a haystack that contains this
                    // rule's sub-trigram needle.
                    *filter = FieldFilter::Disabled;
                }
                Some(FieldFilter::Filtered(bloom)) => {
                    for needle in &needles {
                        insert_needle_trigrams(bloom, needle);
                    }
                }
                None => {
                    // No loaded rule had needles on this field, so a filter
                    // over this rule's needles covers the field. The next
                    // full rebuild resizes it against the aggregate corpus.
                    let filter = match build_field_bloom(&needles) {
                        Some(bloom) => FieldFilter::Filtered(bloom),
                        None => FieldFilter::Disabled,
                    };
                    self.filters.insert(field, filter);
                }
            }
        }
    }

    /// Whether the engine should trigger a full rebuild at the current
    /// rule count to reset the amortized budget and bloom sizing.
    ///
    /// Returns `true` when the rule count has at least doubled since the
    /// last full rebuild (with [`INCREMENTAL_REBUILD_FLOOR`] as a minimum
    /// threshold). Doubling keeps per-rule amortized cost O(1) overall and
    /// caps the FPR drift of any single bloom at roughly 2x the configured
    /// target rate between rebuilds.
    pub(crate) fn should_rebuild(&self, rule_count: usize) -> bool {
        let threshold = self
            .rebuild_baseline
            .saturating_mul(2)
            .max(INCREMENTAL_REBUILD_FLOOR);
        rule_count >= threshold && rule_count > self.rebuild_baseline
    }

    /// Number of fields with active filters. Useful for diagnostics and
    /// tests; not on the hot path.
    #[cfg(test)]
    pub(crate) fn field_count(&self) -> usize {
        self.active_filters().count()
    }

    /// Number of fields carrying needles that are deliberately unfiltered.
    #[cfg(test)]
    pub(crate) fn disabled_field_count(&self) -> usize {
        self.filters
            .values()
            .filter(|f| matches!(f, FieldFilter::Disabled))
            .count()
    }

    /// Total bytes consumed across every field's bloom filter.
    #[cfg(test)]
    pub(crate) fn total_bytes(&self) -> usize {
        self.active_filters().map(FieldBloom::byte_size).sum()
    }

    #[cfg(test)]
    fn active_filters(&self) -> impl Iterator<Item = &FieldBloom> {
        self.filters.values().filter_map(|f| match f {
            FieldFilter::Filtered(bloom) => Some(bloom),
            FieldFilter::Disabled => None,
        })
    }

    /// Probe the bloom for `field` against `value`. Returns the verdict the
    /// engine should use to decide whether to short-circuit positive
    /// substring matchers on this field.
    pub(crate) fn probe(&self, field: &str, value: &str) -> BloomVerdict {
        let Some(FieldFilter::Filtered(bloom)) = self.filters.get(field) else {
            return BloomVerdict::MaybeMatch;
        };
        if value.len() < NGRAM_SIZE {
            // Cannot extract a full trigram; answer conservatively.
            return BloomVerdict::MaybeMatch;
        }
        if value.len() > MAX_BLOOM_SCAN_BYTES {
            return BloomVerdict::MaybeMatch;
        }

        // Lower the haystack once. Sigma defaults to case-insensitive
        // matching and the bloom is built from lowered needles.
        let lowered = crate::matcher::ascii_lowercase_cow(value);
        let bytes = lowered.as_bytes();
        for window in bytes.windows(NGRAM_SIZE) {
            if bloom.contains_trigram(window) {
                return BloomVerdict::MaybeMatch;
            }
        }
        BloomVerdict::DefinitelyNoMatch
    }
}

/// Per-event memoization layer: probes lazily and caches the verdict per
/// field name so each rule item that needs the verdict pays only the first
/// probe.
pub(crate) struct BloomCache<'a, E: Event> {
    index: &'a FieldBloomIndex,
    event: &'a E,
    /// `None` means "not probed yet"; `Some(verdict)` is the cached answer.
    cache: std::cell::RefCell<HashMap<String, BloomVerdict>>,
}

impl<'a, E: Event> BloomCache<'a, E> {
    pub(crate) fn new(index: &'a FieldBloomIndex, event: &'a E) -> Self {
        Self {
            index,
            event,
            cache: std::cell::RefCell::new(HashMap::new()),
        }
    }
}

impl<E: Event> BloomLookup for BloomCache<'_, E> {
    fn verdict_for_field(&self, field: &str) -> BloomVerdict {
        if let Some(v) = self.cache.borrow().get(field) {
            return *v;
        }
        // Compute and cache. Only string event values participate; arrays
        // and other variants always answer MaybeMatch (the bloom can only
        // probe a single string at a time and arrays are rare on hot fields).
        let verdict = match self.event.get_field(field) {
            Some(EventValue::Str(s)) => self.index.probe(field, &s),
            _ => BloomVerdict::MaybeMatch,
        };
        self.cache.borrow_mut().insert(field.to_string(), verdict);
        verdict
    }
}

/// True iff this matcher is a positive (non-negated) substring assertion
/// that the bloom filter can pre-filter.
pub(crate) fn is_positive_substring_matcher(matcher: &CompiledMatcher) -> bool {
    match matcher {
        CompiledMatcher::Contains { .. }
        | CompiledMatcher::StartsWith { .. }
        | CompiledMatcher::EndsWith { .. }
        | CompiledMatcher::AhoCorasickSet { .. } => true,
        CompiledMatcher::AnyOf(children) => children.iter().all(is_positive_substring_matcher),
        CompiledMatcher::CaseInsensitiveGroup { children, .. } => {
            children.iter().all(is_positive_substring_matcher)
        }
        // AllOf is intentionally excluded: even if every child is a positive
        // substring, the bloom only proves "no pattern present", which is
        // already enough to short-circuit (`AllOf(false) = false`). But the
        // savings are small and a single AllOf containing other matchers
        // (FieldRef, etc.) would corrupt the analysis. Keep it simple and
        // off the bloom path.
        _ => false,
    }
}

/// Walk a compiled detection tree and collect positive substring needles
/// per field. `Not(...)` subtrees contribute nothing because their
/// match-falsifying values are independent of pattern presence.
fn collect_positive_substring_needles(
    detection: &CompiledDetection,
    out: &mut HashMap<String, Vec<String>>,
) {
    match detection {
        CompiledDetection::AllOf(items) => {
            for item in items {
                if let Some(field) = &item.field {
                    extract_from_matcher(&item.matcher, field, /*negated=*/ false, out);
                }
            }
        }
        CompiledDetection::AnyOf(subs) => {
            for sub in subs {
                collect_positive_substring_needles(sub, out);
            }
        }
        CompiledDetection::And(subs) => {
            for sub in subs {
                collect_positive_substring_needles(sub, out);
            }
        }
        // Array object-scope predicates target member sub-fields, not
        // top-level event fields, so they cannot contribute top-level needles.
        // Leaving them out keeps the rule from being bloom-pruned.
        CompiledDetection::ArrayMatch { .. } => {}
        // Extended array body: member-scoped, no top-level needles.
        CompiledDetection::Conditional { .. } => {}
        CompiledDetection::Keywords(_) => {
            // Keyword detections are field-less; not bloom-eligible at the
            // per-field granularity.
        }
    }
}

fn extract_from_matcher(
    m: &CompiledMatcher,
    field: &str,
    negated: bool,
    out: &mut HashMap<String, Vec<String>>,
) {
    if negated {
        return;
    }
    match m {
        CompiledMatcher::Contains {
            value,
            case_insensitive,
        }
        | CompiledMatcher::StartsWith {
            value,
            case_insensitive,
        }
        | CompiledMatcher::EndsWith {
            value,
            case_insensitive,
        } => {
            out.entry(field.to_string())
                .or_default()
                .push(bloom_needle(value, *case_insensitive));
        }
        CompiledMatcher::AhoCorasickSet {
            needles,
            case_insensitive,
            ..
        } => {
            // Case-insensitive needles are already lowered by the optimizer,
            // while `|cased` needles retain their original spelling.
            let entry = out.entry(field.to_string()).or_default();
            entry.extend(
                needles
                    .iter()
                    .map(|needle| bloom_needle(needle, *case_insensitive)),
            );
        }
        CompiledMatcher::AnyOf(children) | CompiledMatcher::AllOf(children) => {
            for child in children {
                extract_from_matcher(child, field, negated, out);
            }
        }
        CompiledMatcher::CaseInsensitiveGroup { children, .. } => {
            for child in children {
                extract_from_matcher(child, field, negated, out);
            }
        }
        CompiledMatcher::Not(inner) => {
            extract_from_matcher(inner, field, true, out);
        }
        // Exact, Regex, RegexSetMatch, Cidr, Numeric*, Exists, BoolEq,
        // FieldRef, Null, Expand, TimestampPart: not bloom-eligible. Exact
        // is excluded deliberately so the rule index keeps its monopoly
        // there.
        _ => {}
    }
}

/// Convert a matcher needle into the bloom's lowered comparison space.
///
/// Lowering an ASCII cased needle is a sound necessary condition: an exact
/// cased match remains present after both strings are ASCII-lowered. Unicode
/// lowercasing is context-sensitive, so separately lowering a cased needle
/// and its containing haystack can change a character such as Greek sigma
/// differently. Return an unrepresentable sentinel in that case, which makes
/// [`needles_are_representable`] disable the field's filter.
fn bloom_needle(value: &str, case_insensitive: bool) -> String {
    if case_insensitive {
        value.to_string()
    } else if value.is_ascii() {
        value.to_ascii_lowercase()
    } else {
        String::new()
    }
}

/// Whether every needle in a field's set can be represented as trigrams.
///
/// A needle shorter than [`NGRAM_SIZE`] contributes no trigrams, so a filter
/// built over it cannot witness the needle's presence: `probe` would answer
/// `DefinitelyNoMatch` for a haystack that genuinely contains the needle and
/// the engine would skip a matcher that should have fired. Fields carrying
/// such a needle therefore get no filter at all, leaving every probe on them
/// at `MaybeMatch`.
fn needles_are_representable(needles: &[String]) -> bool {
    needles.iter().all(|n| n.len() >= NGRAM_SIZE)
}

/// Build a bloom covering every needle in a field's deduplicated set, or
/// `None` when the field should stay unfiltered: a needle is not
/// representable as trigrams, or the filter would be too small to help.
///
/// The bloom is sized against the distinct trigram count, not the pattern
/// count, or the filter saturates as soon as any needle longer than
/// `NGRAM_SIZE + 1` bytes is inserted.
fn build_field_bloom(needles: &[String]) -> Option<FieldBloom> {
    if !needles_are_representable(needles) {
        return None;
    }
    let mut bloom = FieldBloom::new_with_capacity(count_unique_trigrams(needles))?;
    for needle in needles {
        insert_needle_trigrams(&mut bloom, needle);
    }
    Some(bloom)
}

fn insert_needle_trigrams(bloom: &mut FieldBloom, needle: &str) {
    let bytes = needle.as_bytes();
    if bytes.len() < NGRAM_SIZE {
        return;
    }
    for window in bytes.windows(NGRAM_SIZE) {
        bloom.insert_trigram(window);
    }
}

/// Number of distinct trigrams across a needle set. Used to size a fresh
/// bloom against an actual key-space rather than the (often larger)
/// raw pattern count.
fn count_unique_trigrams(needles: &[String]) -> usize {
    let mut trigram_set: std::collections::HashSet<[u8; NGRAM_SIZE]> =
        std::collections::HashSet::new();
    for needle in needles {
        let bytes = needle.as_bytes();
        if bytes.len() < NGRAM_SIZE {
            continue;
        }
        for window in bytes.windows(NGRAM_SIZE) {
            let mut buf = [0u8; NGRAM_SIZE];
            buf.copy_from_slice(window);
            trigram_set.insert(buf);
        }
    }
    trigram_set.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Engine;
    use rsigma_parser::parse_sigma_yaml;

    fn engine_from(yaml: &str) -> Engine {
        let collection = parse_sigma_yaml(yaml).unwrap();
        assert!(
            collection.diagnostics.is_empty(),
            "{:?}",
            collection.diagnostics
        );
        let mut engine = Engine::new();
        engine.add_collection(&collection).unwrap();
        engine
    }

    fn bloom_from(yaml: &str) -> FieldBloomIndex {
        let engine = engine_from(yaml);
        FieldBloomIndex::build(engine.rules())
    }

    /// A needle shorter than a trigram contributes no bits, so a filter built
    /// over it answered `DefinitelyNoMatch` for haystacks that did contain the
    /// needle. Such a field must carry no filter at all.
    #[test]
    fn field_with_sub_trigram_needle_gets_no_filter() {
        let yaml = r#"
title: Short Needle
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: '&&'
    condition: selection
"#;
        let bloom = bloom_from(yaml);
        assert_eq!(bloom.field_count(), 0);
        assert_eq!(
            bloom.probe("CommandLine", "a long haystack with && inside it"),
            BloomVerdict::MaybeMatch
        );
    }

    /// The suppression must survive a longer needle on the same field, and
    /// must apply on the incremental append path too.
    #[test]
    fn sub_trigram_needle_suppresses_whole_field() {
        let yaml = r#"
title: Long Needle
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: 'mimikatz'
    condition: selection
---
title: Short Needle
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: '&&'
    condition: selection
"#;
        assert_eq!(bloom_from(yaml).field_count(), 0);

        // Incremental path: appending the short-needle rule must drop the
        // filter the long-needle rule established.
        let collection = parse_sigma_yaml(yaml).unwrap();
        let mut engine = Engine::new();
        engine.set_bloom_prefilter(true);
        for rule in &collection.rules {
            engine.add_rule(rule).unwrap();
        }
        let event_json = serde_json::json!({"CommandLine": "cmd /c dir && whoami"});
        let event = crate::event::JsonEvent::borrow(&event_json);
        assert_eq!(engine.evaluate(&event).len(), 1);
    }

    #[test]
    fn empty_when_no_positive_substring_rules() {
        let yaml = r#"
title: Exact Only
logsource:
    product: windows
detection:
    selection:
        EventType: 'login'
    condition: selection
"#;
        let bloom = bloom_from(yaml);
        assert_eq!(bloom.field_count(), 0);
    }

    #[test]
    fn populates_filter_for_contains_field() {
        let yaml = r#"
title: Contains Field
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'whoami'
            - 'mimikatz'
            - 'powershell'
    condition: selection
"#;
        let bloom = bloom_from(yaml);
        assert_eq!(bloom.field_count(), 1);

        // Trigrams from "whoami" (who/hoa/oam/ami) are present.
        assert_eq!(
            bloom.probe("CommandLine", "execute whoami /all"),
            BloomVerdict::MaybeMatch
        );

        // Digit-only trigrams cannot share any input with the alphabetical
        // needles, and the filter is sized for ~18 trigrams against 1%
        // FPR. Sweep all 1000 digit triples and verify high rejection.
        let mut rejected = 0usize;
        let mut total = 0usize;
        for a in b'0'..=b'9' {
            for b in b'0'..=b'9' {
                for c in b'0'..=b'9' {
                    total += 1;
                    let s = std::str::from_utf8(&[a, b, c]).unwrap().to_string();
                    if bloom.probe("CommandLine", &s) == BloomVerdict::DefinitelyNoMatch {
                        rejected += 1;
                    }
                }
            }
        }
        assert!(
            rejected * 100 >= total * 95,
            "expected >= 95% rejection on digit-only trigrams; got {rejected}/{total}"
        );
    }

    #[test]
    fn negated_contains_does_not_contribute_needles() {
        // `Not(Contains)` subtrees are excluded so a value WITHOUT the
        // pattern can fire the rule (negation semantics). The bloom must
        // not be biased toward those needles; in fact we shouldn't even
        // build a filter for a field whose only patterns are negated.
        let yaml = r#"
title: Negated Contains
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains|neq: 'whoami'
    condition: selection
"#;
        let engine = engine_from(yaml);
        assert_eq!(engine.rule_count(), 1);
        let bloom = FieldBloomIndex::build(engine.rules());
        assert_eq!(bloom.field_count(), 0);
        assert_eq!(bloom.disabled_field_count(), 0);
    }

    #[test]
    fn unrelated_field_falls_through_to_maybe_match() {
        let yaml = r#"
title: Some Rule
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
"#;
        let bloom = bloom_from(yaml);
        // No filter for `User` field, so probe must answer MaybeMatch.
        assert_eq!(bloom.probe("User", "anything"), BloomVerdict::MaybeMatch);
    }

    #[test]
    fn skips_haystacks_below_ngram_size() {
        let yaml = r#"
title: Some Rule
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: 'foo'
    condition: selection
"#;
        let bloom = bloom_from(yaml);
        // value shorter than NGRAM_SIZE → conservative MaybeMatch.
        assert_eq!(bloom.probe("CommandLine", "ab"), BloomVerdict::MaybeMatch);
    }

    #[test]
    fn skips_haystacks_above_max_scan_bytes() {
        let yaml = r#"
title: Some Rule
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: 'foo'
    condition: selection
"#;
        let bloom = bloom_from(yaml);
        let huge = "x".repeat(MAX_BLOOM_SCAN_BYTES + 1);
        assert_eq!(bloom.probe("CommandLine", &huge), BloomVerdict::MaybeMatch);
    }

    #[test]
    fn ahocorasick_needles_contribute_to_bloom() {
        // 8+ contains values trigger the Aho-Corasick optimizer; the bloom
        // builder must still extract the needles from the AC variant.
        let yaml = r#"
title: AC Rule
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'mimikatz'
            - 'powershell'
            - 'rundll32'
            - 'regsvr32'
            - 'certutil'
            - 'bitsadmin'
            - 'mshta'
            - 'wscript'
    condition: selection
"#;
        let bloom = bloom_from(yaml);
        assert_eq!(bloom.field_count(), 1);
        assert_eq!(
            bloom.probe("CommandLine", "rundll32.exe foo"),
            BloomVerdict::MaybeMatch
        );
        // Single-trigram digit haystack: provably no overlap with the
        // alphabetical needles, no compounding over many probe windows.
        assert_eq!(
            bloom.probe("CommandLine", "012"),
            BloomVerdict::DefinitelyNoMatch
        );
    }

    #[test]
    fn case_insensitive_probe() {
        let yaml = r#"
title: CI
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
"#;
        let bloom = bloom_from(yaml);
        // Patterns are stored lowercased; probes lower the haystack too.
        assert_eq!(
            bloom.probe("CommandLine", "execute WHOAMI /all"),
            BloomVerdict::MaybeMatch
        );
    }

    #[test]
    fn cased_uppercase_probe_cannot_be_rejected() {
        let yaml = r#"
title: Cased
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains|cased: 'CMD.EXE'
    condition: selection
"#;
        let bloom = bloom_from(yaml);
        assert_eq!(bloom.field_count(), 1);
        assert_eq!(
            bloom.probe("CommandLine", "CMD.EXE"),
            BloomVerdict::MaybeMatch
        );
    }

    #[test]
    fn cased_unicode_needle_disables_field_filter() {
        let yaml = r#"
title: UnicodeCased
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains|cased: 'AΣ'
    condition: selection
"#;
        let bloom = bloom_from(yaml);
        assert_eq!(bloom.field_count(), 0);
        assert_eq!(bloom.disabled_field_count(), 1);
        assert_eq!(bloom.probe("CommandLine", "AΣX"), BloomVerdict::MaybeMatch);
    }

    #[test]
    fn memory_budget_drops_lowest_density_fields_first() {
        // Build many fields, each with one pattern, against a tiny total
        // budget. The constructor must drop the lowest-density fields
        // until the total fits.
        let mut rules = String::new();
        for i in 0..50 {
            rules.push_str(&format!(
                "title: R{i}\n\
                 id: r-{i:03}\n\
                 logsource:\n\
                 \x20   product: windows\n\
                 detection:\n\
                 \x20   selection:\n\
                 \x20       Field{i}|contains: 'foo'\n\
                 \x20   condition: selection\n\
                 ---\n",
            ));
        }
        let collection = parse_sigma_yaml(&rules).unwrap();
        let mut engine = Engine::new();
        engine.add_collection(&collection).unwrap();

        // Each single-pattern field rounds up to one 64-bit limb (8 bytes).
        // With a 100-byte budget, only ~12 fields can fit.
        let bloom = FieldBloomIndex::build_with_budget(engine.rules(), 100);
        assert!(bloom.total_bytes() <= 100);
        assert!(
            bloom.field_count() < 50,
            "expected eviction; got {} fields, {} bytes",
            bloom.field_count(),
            bloom.total_bytes()
        );

        // A budget large enough to fit everything keeps all 50 fields.
        let big = FieldBloomIndex::build_with_budget(engine.rules(), 1024);
        assert_eq!(big.field_count(), 50);
    }

    /// Folding rules one at a time via `append_rule` must yield the same
    /// `MaybeMatch` and `DefinitelyNoMatch` verdicts as the batched
    /// `build` path across the trigram-overlap and disjoint cases.
    #[test]
    fn append_rule_matches_build_verdicts() {
        let yaml = r#"
title: A
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
---
title: B
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: 'mimikatz'
    condition: selection
---
title: C
logsource:
    product: windows
detection:
    selection:
        ProcessName|endswith: 'svchost.exe'
    condition: selection
"#;
        let engine = engine_from(yaml);
        let rules = engine.rules();

        let batched = FieldBloomIndex::build(rules);
        let mut incremental = FieldBloomIndex::empty();
        for rule in rules {
            incremental.append_rule(rule);
        }

        // Same set of indexed fields.
        assert_eq!(incremental.field_count(), batched.field_count());

        // Trigrams from the appended needles probe `MaybeMatch` under both.
        let positive = [
            ("CommandLine", "run whoami /all"),
            ("CommandLine", "mimikatz launching"),
            ("ProcessName", "C:\\svchost.exe"),
        ];
        for (field, haystack) in &positive {
            assert_eq!(
                batched.probe(field, haystack),
                BloomVerdict::MaybeMatch,
                "batched should answer MaybeMatch for ({field}, {haystack})"
            );
            assert_eq!(
                incremental.probe(field, haystack),
                BloomVerdict::MaybeMatch,
                "incremental should answer MaybeMatch for ({field}, {haystack})"
            );
        }

        // Disjoint haystacks (no rule trigrams) ideally answer
        // `DefinitelyNoMatch` under both paths, but the bloom is sized
        // for ~1% FPR per trigram and the underlying AHasher uses a
        // runtime-randomized seed, so individual probes can flip to
        // `MaybeMatch` non-deterministically. We assert the property at
        // an aggregate rate over a 1000-trigram digit sweep on the
        // batched index (rejection rate must stay >= 90%); that
        // matches the per-version guarantee tested in
        // `populates_filter_for_contains_field` while staying robust
        // against single-haystack false positives. Incremental is not
        // checked here because its filter is sized against per-rule
        // trigram counts and so allows higher FPR drift between
        // rebuilds; that is the documented trade-off.
        let mut rejected = 0usize;
        let mut total = 0usize;
        for a in b'0'..=b'9' {
            for b in b'0'..=b'9' {
                for c in b'0'..=b'9' {
                    total += 1;
                    let bytes = [a, b, c];
                    let s = std::str::from_utf8(&bytes).unwrap();
                    if batched.probe("CommandLine", s) == BloomVerdict::DefinitelyNoMatch {
                        rejected += 1;
                    }
                }
            }
        }
        assert!(
            rejected * 100 >= total * 90,
            "expected >= 90% rejection on disjoint trigram sweep; got {rejected}/{total}"
        );
    }

    /// New rules with new fields create fresh per-field blooms. Trigrams
    /// from the new rule are immediately probable.
    #[test]
    fn append_rule_creates_filter_for_new_field() {
        let yaml = r#"
title: Initial
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
---
title: Adds New Field
logsource:
    product: windows
detection:
    selection:
        Image|contains: 'powershell.exe'
    condition: selection
"#;
        let engine = engine_from(yaml);
        let rules = engine.rules();

        let mut index = FieldBloomIndex::build(&rules[..1]);
        assert_eq!(index.field_count(), 1);

        index.append_rule(&rules[1]);
        assert_eq!(index.field_count(), 2);
        assert_eq!(
            index.probe("Image", "C:\\powershell.exe"),
            BloomVerdict::MaybeMatch
        );
    }

    /// A field left unfiltered because of a sub-trigram needle must not get a
    /// filter from a later rule's needles: the short needle would be in no
    /// filter, so probes could reject haystacks that contain it.
    #[test]
    fn append_keeps_a_sub_trigram_field_disabled() {
        let yaml = r#"
title: Short Needle
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: '&&'
    condition: selection
---
title: Long Needle
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: 'mimikatz'
    condition: selection
"#;
        let engine = engine_from(yaml);
        let rules = engine.rules();

        let mut index = FieldBloomIndex::empty();
        index.append_rule(&rules[0]);
        assert_eq!(index.field_count(), 0);
        assert_eq!(index.disabled_field_count(), 1);

        index.append_rule(&rules[1]);
        assert_eq!(index.field_count(), 0);
        assert_eq!(index.disabled_field_count(), 1);
        assert_eq!(
            index.probe("CommandLine", "dir && del"),
            BloomVerdict::MaybeMatch
        );

        // The batch build reaches the same state.
        let batched = FieldBloomIndex::build(rules);
        assert_eq!(batched.field_count(), 0);
        assert_eq!(batched.disabled_field_count(), 1);
    }

    /// A field the batch build evicted for the memory budget stays
    /// unfiltered on append, while a field no rule touched before still
    /// gets a filter. A full rebuild with room for it restores the filter.
    #[test]
    fn append_keeps_a_budget_evicted_field_disabled() {
        let yaml = r#"
title: Evicted
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: 'mimikatz'
    condition: selection
---
title: Same Field
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: 'sekurlsa'
    condition: selection
---
title: New Field
logsource:
    product: windows
detection:
    selection:
        Image|endswith: 'rundll32.exe'
    condition: selection
"#;
        let engine = engine_from(yaml);
        let rules = engine.rules();

        let mut index = FieldBloomIndex::build_with_budget(&rules[..1], 0);
        assert_eq!(index.field_count(), 0);
        assert_eq!(index.disabled_field_count(), 1);

        index.append_rule(&rules[1]);
        assert_eq!(index.field_count(), 0, "the evicted field stays disabled");
        assert_eq!(
            index.probe("CommandLine", "mimikatz"),
            BloomVerdict::MaybeMatch
        );

        index.append_rule(&rules[2]);
        assert_eq!(index.field_count(), 1, "an untouched field gets a filter");
        assert_eq!(index.disabled_field_count(), 1);

        let rebuilt = FieldBloomIndex::build(rules);
        assert_eq!(rebuilt.field_count(), 2);
        assert_eq!(rebuilt.disabled_field_count(), 0);
    }

    /// The observed false-positive rate of a filter sized by
    /// `new_with_capacity` must stay close to the textbook rate
    /// `(1 - e^(-k*n/m))^k` for its bit count `m`, hash count `k`, and `n`
    /// inserted trigrams. Correlated probe positions push it far above that
    /// on the small filters most fields get.
    #[test]
    fn false_positive_rate_stays_near_the_sizing_target() {
        const TRIALS: u32 = 40;
        const QUERIES_PER_TRIAL: u32 = 5_000;
        // Inserted trigrams have the high bit set on their first byte and
        // queried ones do not, so every positive probe is a false positive.
        fn trigram(v: u32, high: bool) -> [u8; NGRAM_SIZE] {
            let first = ((v >> 14) & 0x7f) as u8 | if high { 0x80 } else { 0 };
            [first, ((v >> 7) & 0x7f) as u8, (v & 0x7f) as u8]
        }
        for n in [4usize, 8, 32, 128, 1024] {
            let mut false_positives = 0u64;
            let mut expected = 0.0f64;
            for trial in 0..TRIALS {
                let mut bloom = FieldBloom::new_with_capacity(n).expect("sized");
                let base = trial * 2_000;
                for i in 0..n as u32 {
                    bloom.insert_trigram(&trigram(base + i, true));
                }
                for q in 0..QUERIES_PER_TRIAL {
                    if bloom.contains_trigram(&trigram(trial * QUERIES_PER_TRIAL + q, false)) {
                        false_positives += 1;
                    }
                }
                let k = f64::from(bloom.num_hashes);
                let m = bloom.num_bits as f64;
                expected +=
                    (1.0 - (-k * n as f64 / m).exp()).powf(k) * f64::from(QUERIES_PER_TRIAL);
            }
            // Twice the expectation plus a Poisson-sized margin keeps the
            // check stable while still failing on an order-of-magnitude drift.
            let bound = 2.0 * expected + 4.0 * expected.sqrt() + 4.0;
            assert!(
                (false_positives as f64) <= bound,
                "n={n}: {false_positives} false positives, expected about {expected:.1} (bound {bound:.1})"
            );
        }
    }

    /// `should_rebuild` returns `true` once the rule count has at least
    /// doubled past the last rebuild baseline (with the 64-rule floor on
    /// the first rebuild). Verifies the schedule the engine will use to
    /// keep amortized append cost O(1).
    #[test]
    fn should_rebuild_follows_doubling_watermark() {
        let empty = FieldBloomIndex::empty();
        assert!(!empty.should_rebuild(0));
        assert!(!empty.should_rebuild(63));
        // At the floor the very first rebuild trips.
        assert!(empty.should_rebuild(64));
        assert!(empty.should_rebuild(1000));

        // After a rebuild at 100 rules, the next watermark is at 200.
        let rules = String::from(
            r#"
title: Sample
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
"#,
        );
        let engine = engine_from(&rules);
        let rebuilt = FieldBloomIndex::build_with_budget(engine.rules(), DEFAULT_MAX_TOTAL_BYTES);
        let mut at100 = rebuilt;
        at100.rebuild_baseline = 100;
        assert!(!at100.should_rebuild(100));
        assert!(!at100.should_rebuild(199));
        assert!(at100.should_rebuild(200));
        assert!(at100.should_rebuild(1000));
    }
}
