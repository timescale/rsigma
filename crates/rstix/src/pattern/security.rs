//! Pattern evaluation security limits.

use crate::pattern::error::PatternMatchError;

/// Maximum compiled regex size (1 MiB), aligned with STIX pattern `MATCHES` evaluation.
pub const REGEX_SIZE_LIMIT: usize = 1 << 20;

/// Compile a regex pattern enforcing the size limit used during evaluation.
///
/// STIX §9.6.1 MATCHES: PCRE DOTALL is required (`.` matches newlines).
pub fn compile_regex(pattern: &str) -> Result<regex::Regex, PatternMatchError> {
    regex::RegexBuilder::new(pattern)
        .size_limit(REGEX_SIZE_LIMIT)
        .dot_matches_new_line(true)
        .build()
        .map_err(|err| PatternMatchError::RegexCompile {
            msg: err.to_string(),
        })
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
}
