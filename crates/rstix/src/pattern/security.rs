//! Pattern evaluation security limits.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::pattern::error::PatternMatchError;

/// Maximum compiled regex size (1 MiB), aligned with STIX pattern `MATCHES` evaluation.
pub const REGEX_SIZE_LIMIT: usize = 1 << 20;

/// Most distinct objects one `_ref` or `_refs` dereference step may reach.
pub const MAX_PATH_TARGETS: usize = 10_000;

/// Most `_ref` and `_refs` dereferences one object path may contain.
pub const MAX_REF_DEREFERENCES: usize = 8;

/// Steps one evaluation may take before it fails with
/// [`PatternMatchError::StepLimitExceeded`].
pub const MAX_EVAL_STEPS: u64 = 10_000_000;

/// Compiled `MATCHES` regex bytes one pattern keeps for reuse.
pub const MATCHES_REGEX_CACHE_BYTES: usize = 16 << 20;

/// First size limit tried for a `MATCHES` regex; larger regexes are charged
/// [`REGEX_SIZE_LIMIT`].
const SMALL_REGEX_SIZE_LIMIT: usize = 64 << 10;

/// Bytes of string data scanned per evaluation step.
const SCAN_BYTES_PER_STEP: usize = 64;

/// Bytes of compiled regex size limit per evaluation step charged for a compile.
const REGEX_COMPILE_BYTES_PER_STEP: usize = 8;

/// Compile a regex pattern enforcing the size limit used during evaluation.
///
/// STIX §9.6.1 MATCHES: PCRE DOTALL is required (`.` matches newlines).
pub fn compile_regex(pattern: &str) -> Result<regex::Regex, PatternMatchError> {
    build_regex(pattern, REGEX_SIZE_LIMIT).map_err(|err| PatternMatchError::RegexCompile {
        msg: err.to_string(),
    })
}

fn build_regex(pattern: &str, size_limit: usize) -> Result<regex::Regex, regex::Error> {
    regex::RegexBuilder::new(pattern)
        .size_limit(size_limit)
        .dot_matches_new_line(true)
        .build()
}

/// Step counter shared by every comparison, path walk, and regex compile of
/// one evaluation.
#[derive(Debug)]
pub(crate) struct Steps {
    used: u64,
    limit: u64,
}

impl Steps {
    pub(crate) fn new() -> Self {
        Self::with_limit(MAX_EVAL_STEPS)
    }

    pub(crate) fn with_limit(limit: u64) -> Self {
        Self { used: 0, limit }
    }

    pub(crate) fn spend(&mut self, steps: u64) -> Result<(), PatternMatchError> {
        self.used = self.used.saturating_add(steps);
        if self.used > self.limit {
            return Err(PatternMatchError::StepLimitExceeded { max: self.limit });
        }
        Ok(())
    }

    /// Charge one step per [`SCAN_BYTES_PER_STEP`] bytes, at least one.
    pub(crate) fn spend_scan(&mut self, bytes: usize) -> Result<(), PatternMatchError> {
        self.spend((bytes / SCAN_BYTES_PER_STEP) as u64 + 1)
    }

    #[cfg(test)]
    pub(crate) fn used(&self) -> u64 {
        self.used
    }
}

/// Charges bytes compared by a string scan to [`Steps`] as the scan goes, so
/// a long scan stops at the limit instead of after it finishes.
pub(crate) struct ScanMeter<'s> {
    steps: &'s mut Steps,
    pending: usize,
}

impl<'s> ScanMeter<'s> {
    pub(crate) fn new(steps: &'s mut Steps) -> Self {
        Self { steps, pending: 0 }
    }

    pub(crate) fn add(&mut self, bytes: usize) -> Result<(), PatternMatchError> {
        self.pending += bytes;
        if self.pending >= SCAN_BYTES_PER_STEP {
            let whole = self.pending / SCAN_BYTES_PER_STEP;
            self.pending %= SCAN_BYTES_PER_STEP;
            self.steps.spend(whole as u64)?;
        }
        Ok(())
    }
}

/// A compiled `MATCHES` regex and how many times a small regex's cost a
/// search with it is charged.
pub(crate) struct CachedRegex {
    pub(crate) regex: regex::Regex,
    pub(crate) weight: usize,
}

/// Compiled `MATCHES` regexes of one pattern, keyed by the constant as written.
///
/// A regex is compiled on first use and kept while the pattern's total stays
/// within [`MATCHES_REGEX_CACHE_BYTES`]. Each regex is charged the size limit
/// it compiled under, so the total bounds the memory the cache can hold.
#[derive(Clone, Default)]
pub(crate) struct RegexCache {
    inner: Arc<Mutex<CacheState>>,
}

#[derive(Default)]
struct CacheState {
    regexes: HashMap<String, (regex::Regex, usize)>,
    bytes: usize,
    #[cfg(test)]
    compiles: usize,
}

impl std::fmt::Debug for RegexCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegexCache").finish_non_exhaustive()
    }
}

impl RegexCache {
    /// Compiled regex for the `MATCHES` constant `constant`, NFC-normalized
    /// before compiling. A compile is charged by the size limit it needed.
    pub(crate) fn get(
        &self,
        constant: &str,
        steps: &mut Steps,
    ) -> Result<CachedRegex, PatternMatchError> {
        if let Some((regex, charge)) = self.state().regexes.get(constant) {
            return Ok(CachedRegex {
                regex: regex.clone(),
                weight: charge / SMALL_REGEX_SIZE_LIMIT,
            });
        }
        let normalized = crate::pattern::normalize::nfc(constant);
        let (regex, charge) = match build_regex(&normalized, SMALL_REGEX_SIZE_LIMIT) {
            Ok(regex) => (regex, SMALL_REGEX_SIZE_LIMIT),
            Err(regex::Error::CompiledTooBig(_)) => (
                build_regex(&normalized, REGEX_SIZE_LIMIT).map_err(|err| {
                    PatternMatchError::RegexCompile {
                        msg: err.to_string(),
                    }
                })?,
                REGEX_SIZE_LIMIT,
            ),
            Err(err) => {
                return Err(PatternMatchError::RegexCompile {
                    msg: err.to_string(),
                });
            }
        };
        steps.spend((charge / REGEX_COMPILE_BYTES_PER_STEP) as u64)?;
        let mut state = self.state();
        #[cfg(test)]
        {
            state.compiles += 1;
        }
        if state.bytes + charge <= MATCHES_REGEX_CACHE_BYTES {
            state.bytes += charge;
            state
                .regexes
                .insert(constant.to_owned(), (regex.clone(), charge));
        }
        Ok(CachedRegex {
            regex,
            weight: charge / SMALL_REGEX_SIZE_LIMIT,
        })
    }

    fn state(&self) -> std::sync::MutexGuard<'_, CacheState> {
        self.inner.lock().unwrap_or_else(|err| err.into_inner())
    }

    #[cfg(test)]
    pub(crate) fn compiles(&self) -> usize {
        self.state().compiles
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dot_matches_new_line_is_enabled() {
        let re = compile_regex("a.b").expect("compile");
        assert!(re.is_match("a\nb"));
    }

    #[test]
    fn rejects_oversized_regex_pattern() {
        let huge = format!("(a){{{REGEX_SIZE_LIMIT}}}");
        assert!(matches!(
            compile_regex(&huge),
            Err(PatternMatchError::RegexCompile { .. })
        ));
    }

    #[test]
    fn cache_compiles_each_constant_once() {
        let cache = RegexCache::default();
        let mut steps = Steps::new();
        for _ in 0..10 {
            let cached = cache.get("^a+$", &mut steps).expect("regex");
            assert!(cached.regex.is_match("aaa"));
            assert_eq!(cached.weight, 1);
        }
        assert_eq!(cache.compiles(), 1);
    }

    #[test]
    fn cache_stops_keeping_regexes_past_its_byte_budget() {
        let cache = RegexCache::default();
        let mut steps = Steps::new();
        let kept = MATCHES_REGEX_CACHE_BYTES / SMALL_REGEX_SIZE_LIMIT;
        for n in 0..kept + 1 {
            cache.get(&format!("^{n}$"), &mut steps).expect("regex");
        }
        cache.get("^0$", &mut steps).expect("cached");
        assert_eq!(cache.compiles(), kept + 1);
        cache
            .get(&format!("^{kept}$"), &mut steps)
            .expect("uncached");
        assert_eq!(cache.compiles(), kept + 2);
    }

    #[test]
    fn large_regex_is_charged_the_full_size_limit() {
        let cache = RegexCache::default();
        let mut steps = Steps::new();
        let cached = cache.get("a{5000}", &mut steps).expect("large regex");
        assert_eq!(cached.weight, REGEX_SIZE_LIMIT / SMALL_REGEX_SIZE_LIMIT);
        assert_eq!(
            steps.used(),
            (REGEX_SIZE_LIMIT / REGEX_COMPILE_BYTES_PER_STEP) as u64
        );
    }

    #[test]
    fn scan_meter_charges_as_it_goes() {
        let mut steps = Steps::with_limit(2);
        let mut meter = ScanMeter::new(&mut steps);
        meter.add(SCAN_BYTES_PER_STEP - 1).expect("under one step");
        meter.add(SCAN_BYTES_PER_STEP + 1).expect("two steps");
        assert!(meter.add(SCAN_BYTES_PER_STEP).is_err());
    }

    #[test]
    fn steps_fail_past_the_limit() {
        let mut steps = Steps::with_limit(3);
        steps.spend(3).expect("at limit");
        assert_eq!(
            steps.spend(1),
            Err(PatternMatchError::StepLimitExceeded { max: 3 })
        );
    }
}
