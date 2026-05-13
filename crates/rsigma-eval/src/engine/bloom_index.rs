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

use std::collections::HashMap;
use std::hash::{BuildHasher, BuildHasherDefault, Hasher};

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

/// Bit-array bloom filter using FNV-style double hashing over the AHash
/// output of each input. `k` hash functions are simulated by `h1 + i*h2`
/// where `h1`, `h2` are the low and high words of a 128-bit AHash digest.
struct FieldBloom {
    bits: Vec<u64>,
    num_bits: usize,
    num_hashes: u32,
    hasher_factory: BuildHasherDefault<ahash::AHasher>,
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
            hasher_factory: BuildHasherDefault::default(),
        })
    }

    fn byte_size(&self) -> usize {
        self.bits.len() * 8
    }

    fn insert_trigram(&mut self, trigram: &[u8]) {
        let (h1, h2) = self.hash_pair(trigram);
        for i in 0..self.num_hashes as u64 {
            let pos = (h1.wrapping_add(i.wrapping_mul(h2))) as usize % self.num_bits;
            self.bits[pos / 64] |= 1 << (pos % 64);
        }
    }

    fn contains_trigram(&self, trigram: &[u8]) -> bool {
        let (h1, h2) = self.hash_pair(trigram);
        for i in 0..self.num_hashes as u64 {
            let pos = (h1.wrapping_add(i.wrapping_mul(h2))) as usize % self.num_bits;
            if self.bits[pos / 64] & (1 << (pos % 64)) == 0 {
                return false;
            }
        }
        true
    }

    /// Produce two independent 64-bit hashes from a single AHash digest by
    /// feeding the trigram twice with different prefixes. Cheap and gives
    /// the double-hashing scheme enough independence to behave like two
    /// distinct functions.
    fn hash_pair(&self, trigram: &[u8]) -> (u64, u64) {
        let mut h1 = self.hasher_factory.build_hasher();
        h1.write_u8(0xA1);
        h1.write(trigram);
        let mut h2 = self.hasher_factory.build_hasher();
        h2.write_u8(0xB2);
        h2.write(trigram);
        (h1.finish(), h2.finish())
    }
}

/// Per-field bloom filters built from the union of every positive substring
/// needle across all compiled rules.
pub(crate) struct FieldBloomIndex {
    /// `field_name → bloom`. Fields without any positive substring needles
    /// (or that exceeded the memory budget) are absent from the map; probes
    /// against them return `MaybeMatch` and the engine evaluates as usual.
    filters: HashMap<String, FieldBloom>,
}

impl FieldBloomIndex {
    pub(crate) fn empty() -> Self {
        Self {
            filters: HashMap::new(),
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

        let mut built: Vec<Built> = field_needles
            .into_iter()
            .filter_map(|(field, mut needles)| {
                // Deduplicate so the bit count reflects unique pattern strings.
                needles.sort();
                needles.dedup();

                // Count the total number of distinct trigrams that will be
                // inserted; the bloom must be sized against this number,
                // not the pattern count, or the filter saturates as soon as
                // any needle longer than NGRAM_SIZE+1 bytes is inserted.
                let mut trigram_set: std::collections::HashSet<[u8; NGRAM_SIZE]> =
                    std::collections::HashSet::new();
                for needle in &needles {
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
                let n_trigrams = trigram_set.len();

                let mut bloom = FieldBloom::new_with_capacity(n_trigrams)?;
                for needle in &needles {
                    insert_needle_trigrams(&mut bloom, needle);
                }
                Some(Built {
                    field,
                    bloom,
                    n_patterns: needles.len(),
                })
            })
            .collect();

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
                } else {
                    break;
                }
            }
        }

        let filters = built
            .into_iter()
            .map(|b| (b.field, b.bloom))
            .collect::<HashMap<_, _>>();
        Self { filters }
    }

    /// Number of fields with active filters. Useful for diagnostics and
    /// tests; not on the hot path.
    #[cfg(test)]
    pub(crate) fn field_count(&self) -> usize {
        self.filters.len()
    }

    /// Total bytes consumed across every field's bloom filter.
    #[cfg(test)]
    pub(crate) fn total_bytes(&self) -> usize {
        self.filters.values().map(FieldBloom::byte_size).sum()
    }

    /// Probe the bloom for `field` against `value`. Returns the verdict the
    /// engine should use to decide whether to short-circuit positive
    /// substring matchers on this field.
    pub(crate) fn probe(&self, field: &str, value: &str) -> BloomVerdict {
        let Some(bloom) = self.filters.get(field) else {
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
        CompiledMatcher::Contains { value, .. }
        | CompiledMatcher::StartsWith { value, .. }
        | CompiledMatcher::EndsWith { value, .. } => {
            out.entry(field.to_string())
                .or_default()
                .push(value.clone());
        }
        CompiledMatcher::AhoCorasickSet { needles, .. } => {
            // The optimizer stores the pre-lowered needles on the variant so
            // the bloom builder can recover them without inspecting the
            // automaton's private state.
            let entry = out.entry(field.to_string()).or_default();
            entry.extend(needles.iter().cloned());
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

fn insert_needle_trigrams(bloom: &mut FieldBloom, needle: &str) {
    let bytes = needle.as_bytes();
    if bytes.len() < NGRAM_SIZE {
        return;
    }
    for window in bytes.windows(NGRAM_SIZE) {
        bloom.insert_trigram(window);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Engine;
    use rsigma_parser::parse_sigma_yaml;

    fn engine_from(yaml: &str) -> Engine {
        let collection = parse_sigma_yaml(yaml).unwrap();
        let mut engine = Engine::new();
        engine.add_collection(&collection).unwrap();
        engine
    }

    fn bloom_from(yaml: &str) -> FieldBloomIndex {
        let engine = engine_from(yaml);
        FieldBloomIndex::build(engine.rules())
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
        CommandLine|contains|not: 'whoami'
    condition: selection
"#;
        let bloom = bloom_from(yaml);
        assert_eq!(bloom.field_count(), 0);
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
}
