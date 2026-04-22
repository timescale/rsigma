//! Zero-dependency CEF (Common Event Format) parser.
//!
//! Parses [ArcSight CEF](https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-8.4/cef-implementation-standard/)
//! log lines into a structured [`CefRecord`].
//!
//! # Format
//!
//! ```text
//! CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extensions
//! ```
//!
//! The header contains 7 pipe-delimited fields. Pipes in header values are
//! escaped as `\|` and backslashes as `\\`.
//!
//! Extensions are space-separated `key=value` pairs where values may contain
//! spaces. The boundary between one value and the next key is determined by
//! looking back from each unescaped `=` to find the key name. In extension
//! values, `\=` is a literal `=`, `\\` is a literal `\`, `\n` is a newline,
//! and `\r` is a carriage return.
//!
//! # Syslog wrapping
//!
//! This parser handles **raw CEF only**. If CEF arrives inside a syslog
//! envelope, the caller must strip the syslog prefix first (e.g. by finding
//! `"CEF:"` in the line). The [`find_cef_start`] helper locates the offset.
//!
//! # Example
//!
//! ```
//! use rsigma_runtime::parse::cef::parse;
//!
//! let record = parse(
//!     "CEF:0|Security|IDS|1.0|100|Attack detected|9|src=10.0.0.1 dst=192.168.1.1 msg=Intrusion attempt"
//! ).unwrap();
//!
//! assert_eq!(record.device_vendor, "Security");
//! assert_eq!(record.severity, "9");
//! assert_eq!(record.extensions.len(), 3);
//! assert_eq!(record.extensions[2].0, "msg");
//! assert_eq!(record.extensions[2].1, "Intrusion attempt");
//! ```

use std::fmt;

/// A parsed CEF record.
#[derive(Debug, Clone, PartialEq)]
pub struct CefRecord {
    /// CEF version (typically 0).
    pub version: u32,
    pub device_vendor: String,
    pub device_product: String,
    pub device_version: String,
    pub signature_id: String,
    pub name: String,
    pub severity: String,
    /// Extension key-value pairs, in the order they appeared.
    pub extensions: Vec<(String, String)>,
}

/// Errors from CEF parsing.
#[derive(Debug, Clone, PartialEq)]
pub enum CefError {
    /// Input does not start with `CEF:`.
    NotCef,
    /// Header has fewer than 7 pipe-delimited fields.
    IncompleteHeader,
    /// The version field is not a valid integer.
    InvalidVersion,
}

impl fmt::Display for CefError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CefError::NotCef => write!(f, "input does not contain a CEF header"),
            CefError::IncompleteHeader => {
                write!(f, "CEF header requires 7 pipe-delimited fields")
            }
            CefError::InvalidVersion => write!(f, "CEF version is not a valid integer"),
        }
    }
}

impl std::error::Error for CefError {}

/// Find the byte offset of `"CEF:"` in the input, if present.
///
/// Useful for stripping a syslog prefix before calling [`parse`].
pub fn find_cef_start(input: &str) -> Option<usize> {
    input.find("CEF:")
}

/// Parse a CEF line into a [`CefRecord`].
///
/// Expects input starting at `CEF:` (use [`find_cef_start`] to locate it
/// within a syslog-wrapped line).
pub fn parse(input: &str) -> Result<CefRecord, CefError> {
    let input = input.trim();

    // Locate the CEF header start.
    let cef_start = find_cef_start(input).ok_or(CefError::NotCef)?;
    let after_marker = &input[cef_start + 4..]; // skip "CEF:"

    // Split header fields on unescaped `|`. We need exactly 7 separators
    // (version + 6 named fields), with the rest being the extension.
    let header_fields = split_header(after_marker);
    if header_fields.len() < 8 {
        return Err(CefError::IncompleteHeader);
    }

    let version: u32 = header_fields[0]
        .trim()
        .parse()
        .map_err(|_| CefError::InvalidVersion)?;

    let extensions = if header_fields.len() > 7 {
        parse_extensions(header_fields[7])
    } else {
        Vec::new()
    };

    Ok(CefRecord {
        version,
        device_vendor: unescape_header(header_fields[1]),
        device_product: unescape_header(header_fields[2]),
        device_version: unescape_header(header_fields[3]),
        signature_id: unescape_header(header_fields[4]),
        name: unescape_header(header_fields[5]),
        severity: unescape_header(header_fields[6]),
        extensions,
    })
}

/// Split the CEF header on unescaped `|` characters.
///
/// Returns up to 8 segments: version, 6 header fields, and the extension
/// tail (everything after the 7th `|`).
fn split_header(input: &str) -> Vec<&str> {
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut segments = Vec::with_capacity(8);
    let mut start = 0;
    let mut pipe_count = 0;

    let mut i = 0;
    while i < len {
        if bytes[i] == b'\\' && i + 1 < len {
            // Skip escaped character.
            i += 2;
            continue;
        }
        if bytes[i] == b'|' {
            segments.push(&input[start..i]);
            start = i + 1;
            pipe_count += 1;
            if pipe_count == 7 {
                // Everything after the 7th pipe is the extension.
                segments.push(&input[start..]);
                return segments;
            }
        }
        i += 1;
    }

    // Fewer than 7 pipes — push whatever remains.
    if start <= len {
        segments.push(&input[start..]);
    }
    segments
}

/// Unescape a CEF header field value (`\|` → `|`, `\\` → `\`).
fn unescape_header(input: &str) -> String {
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut out = String::with_capacity(len);
    let mut i = 0;

    while i < len {
        if bytes[i] == b'\\' && i + 1 < len {
            match bytes[i + 1] {
                b'|' => {
                    out.push('|');
                    i += 2;
                }
                b'\\' => {
                    out.push('\\');
                    i += 2;
                }
                _ => {
                    out.push('\\');
                    i += 1;
                }
            }
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }

    out
}

/// Parse CEF extension key=value pairs.
///
/// Uses the "split by unescaped `=`, then look-back" algorithm:
/// 1. Split the extension string on every unescaped `=`.
/// 2. For each pair of consecutive segments, the **last word** of the left
///    segment is the key, and everything in the right segment (up to its own
///    last word, which is the *next* key) is the value.
/// 3. The very last segment is the value for the final key (no look-ahead).
fn parse_extensions(input: &str) -> Vec<(String, String)> {
    let input = input.trim();
    if input.is_empty() {
        return Vec::new();
    }

    let segments = split_on_unescaped_eq(input);
    if segments.len() < 2 {
        return Vec::new();
    }

    let mut pairs = Vec::new();
    let n = segments.len();
    let mut current_key = extract_last_word(segments[0]);

    for (i, segment) in segments.iter().enumerate().skip(1) {
        let key = std::mem::take(&mut current_key);
        if i < n - 1 {
            // Intermediate segment: its last word is the next key; everything
            // before it is the value for the current key.
            match segment.rsplit_once(' ') {
                Some((value_part, next_key)) => {
                    pairs.push((key, unescape_extension(value_part.trim())));
                    current_key = next_key.to_string();
                }
                None => {
                    // No space — entire segment is the value (degenerate case).
                    pairs.push((key, unescape_extension(segment.trim())));
                }
            }
        } else {
            // Final segment: the entire content is the value for the current key.
            pairs.push((key, unescape_extension(segment.trim())));
        }
    }

    pairs
}

/// Split a string on unescaped `=` characters.
fn split_on_unescaped_eq(input: &str) -> Vec<&str> {
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut segments = Vec::new();
    let mut start = 0;
    let mut i = 0;

    while i < len {
        if bytes[i] == b'\\' && i + 1 < len {
            i += 2; // skip escaped char
            continue;
        }
        if bytes[i] == b'=' {
            segments.push(&input[start..i]);
            start = i + 1;
        }
        i += 1;
    }
    segments.push(&input[start..]);
    segments
}

/// Extract the last whitespace-delimited word from a string.
fn extract_last_word(s: &str) -> String {
    s.rsplit_once(' ')
        .map(|(_, last)| last)
        .unwrap_or(s)
        .to_string()
}

/// Unescape a CEF extension value (`\=` → `=`, `\\` → `\`, `\n` → newline, `\r` → CR).
fn unescape_extension(input: &str) -> String {
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut out = String::with_capacity(len);
    let mut i = 0;

    while i < len {
        if bytes[i] == b'\\' && i + 1 < len {
            match bytes[i + 1] {
                b'=' => {
                    out.push('=');
                    i += 2;
                }
                b'\\' => {
                    out.push('\\');
                    i += 2;
                }
                b'n' => {
                    out.push('\n');
                    i += 2;
                }
                b'r' => {
                    out.push('\r');
                    i += 2;
                }
                _ => {
                    out.push('\\');
                    i += 1;
                }
            }
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- Header parsing -------------------------------------------------------

    #[test]
    fn minimal_cef() {
        let r = parse("CEF:0|Vendor|Product|1.0|100|Name|5|").unwrap();
        assert_eq!(r.version, 0);
        assert_eq!(r.device_vendor, "Vendor");
        assert_eq!(r.device_product, "Product");
        assert_eq!(r.device_version, "1.0");
        assert_eq!(r.signature_id, "100");
        assert_eq!(r.name, "Name");
        assert_eq!(r.severity, "5");
        assert!(r.extensions.is_empty());
    }

    #[test]
    fn header_without_trailing_pipe_extensions() {
        let r = parse("CEF:0|Vendor|Product|1.0|100|Name|5|src=10.0.0.1 dst=192.168.1.1").unwrap();
        assert_eq!(r.extensions.len(), 2);
        assert_eq!(r.extensions[0], ("src".into(), "10.0.0.1".into()));
        assert_eq!(r.extensions[1], ("dst".into(), "192.168.1.1".into()));
    }

    #[test]
    fn escaped_pipe_in_header() {
        let r = parse(r"CEF:0|Ven\|dor|Product|1.0|100|Na\|me|5|").unwrap();
        assert_eq!(r.device_vendor, "Ven|dor");
        assert_eq!(r.name, "Na|me");
    }

    #[test]
    fn escaped_backslash_in_header() {
        let r = parse(r"CEF:0|Ven\\dor|Product|1.0|100|Name|5|").unwrap();
        assert_eq!(r.device_vendor, r"Ven\dor");
    }

    #[test]
    fn not_cef() {
        assert_eq!(parse("not a CEF line"), Err(CefError::NotCef));
    }

    #[test]
    fn incomplete_header() {
        assert_eq!(
            parse("CEF:0|Vendor|Product"),
            Err(CefError::IncompleteHeader)
        );
    }

    #[test]
    fn invalid_version() {
        assert_eq!(
            parse("CEF:abc|Vendor|Product|1.0|100|Name|5|"),
            Err(CefError::InvalidVersion)
        );
    }

    // -- Extension parsing ----------------------------------------------------

    #[test]
    fn single_extension() {
        let r = parse("CEF:0|V|P|1|1|N|1|src=10.0.0.1").unwrap();
        assert_eq!(r.extensions, vec![("src".into(), "10.0.0.1".into())]);
    }

    #[test]
    fn multiple_extensions() {
        let r = parse("CEF:0|V|P|1|1|N|1|src=10.0.0.1 dst=192.168.1.1 dpt=443").unwrap();
        assert_eq!(r.extensions.len(), 3);
        assert_eq!(r.extensions[0], ("src".into(), "10.0.0.1".into()));
        assert_eq!(r.extensions[1], ("dst".into(), "192.168.1.1".into()));
        assert_eq!(r.extensions[2], ("dpt".into(), "443".into()));
    }

    #[test]
    fn extension_value_with_spaces() {
        let r = parse("CEF:0|V|P|1|1|N|1|msg=User signed in from 10.0.0.1 src=10.0.0.1").unwrap();
        assert_eq!(r.extensions.len(), 2);
        assert_eq!(
            r.extensions[0],
            ("msg".into(), "User signed in from 10.0.0.1".into())
        );
        assert_eq!(r.extensions[1], ("src".into(), "10.0.0.1".into()));
    }

    #[test]
    fn extension_escaped_equals() {
        let r =
            parse(r"CEF:0|V|P|1|1|N|1|request=https://example.com?foo\=bar src=10.0.0.1").unwrap();
        assert_eq!(r.extensions.len(), 2);
        assert_eq!(
            r.extensions[0],
            ("request".into(), "https://example.com?foo=bar".into())
        );
    }

    #[test]
    fn extension_escaped_backslash() {
        let r = parse(r"CEF:0|V|P|1|1|N|1|path=C:\\Windows\\System32").unwrap();
        assert_eq!(
            r.extensions[0],
            ("path".into(), r"C:\Windows\System32".into())
        );
    }

    #[test]
    fn extension_escaped_newline() {
        let r = parse(r"CEF:0|V|P|1|1|N|1|msg=line1\nline2").unwrap();
        assert_eq!(r.extensions[0], ("msg".into(), "line1\nline2".into()));
    }

    #[test]
    fn extension_escaped_cr() {
        let r = parse(r"CEF:0|V|P|1|1|N|1|msg=line1\rline2").unwrap();
        assert_eq!(r.extensions[0], ("msg".into(), "line1\rline2".into()));
    }

    #[test]
    fn empty_extensions() {
        let r = parse("CEF:0|V|P|1|1|N|1|").unwrap();
        assert!(r.extensions.is_empty());
    }

    #[test]
    fn whitespace_only_extensions() {
        let r = parse("CEF:0|V|P|1|1|N|1|   ").unwrap();
        assert!(r.extensions.is_empty());
    }

    // -- find_cef_start -------------------------------------------------------

    #[test]
    fn find_cef_in_syslog() {
        let line = "<134>2022-02-14T03:17:30-08:00 host CEF:0|V|P|1|1|N|1|src=10.0.0.1";
        let offset = find_cef_start(line).unwrap();
        let r = parse(&line[offset..]).unwrap();
        assert_eq!(r.device_vendor, "V");
        assert_eq!(r.extensions[0], ("src".into(), "10.0.0.1".into()));
    }

    #[test]
    fn find_cef_no_match() {
        assert_eq!(find_cef_start("just a regular log line"), None);
    }

    // -- Real-world samples ---------------------------------------------------

    #[test]
    fn real_world_arcsight() {
        let line = "CEF:0|ArcSight|ArcSight|7.0.0|agent:030|Agent Started|1|deviceExternalId=001 rt=1644800250000 cat=agent msg=ArcSight agent started successfully";
        let r = parse(line).unwrap();
        assert_eq!(r.device_vendor, "ArcSight");
        assert_eq!(r.name, "Agent Started");
        assert_eq!(r.extensions.len(), 4);
        assert_eq!(r.extensions[0], ("deviceExternalId".into(), "001".into()));
        assert_eq!(r.extensions[1], ("rt".into(), "1644800250000".into()));
        assert_eq!(r.extensions[2], ("cat".into(), "agent".into()));
        assert_eq!(
            r.extensions[3],
            ("msg".into(), "ArcSight agent started successfully".into())
        );
    }

    #[test]
    fn real_world_with_labels() {
        let line = "CEF:0|Vendor|Firewall|2.0|100|Connection Blocked|8|src=10.0.0.1 dst=192.168.1.100 spt=12345 dpt=443 proto=TCP act=blocked";
        let r = parse(line).unwrap();
        assert_eq!(r.extensions.len(), 6);
        assert_eq!(r.extensions[0], ("src".into(), "10.0.0.1".into()));
        assert_eq!(r.extensions[1], ("dst".into(), "192.168.1.100".into()));
        assert_eq!(r.extensions[2], ("spt".into(), "12345".into()));
        assert_eq!(r.extensions[3], ("dpt".into(), "443".into()));
        assert_eq!(r.extensions[4], ("proto".into(), "TCP".into()));
        assert_eq!(r.extensions[5], ("act".into(), "blocked".into()));
    }

    #[test]
    fn real_world_syslog_wrapped_cef() {
        let line = "<134>Feb 14 19:04:54 firewall01 CEF:0|Palo Alto|PAN-OS|10.1|THREAT|threat|7|src=172.16.0.5 dst=10.10.10.1 msg=Malware detected in file transfer";
        let offset = find_cef_start(line).unwrap();
        let r = parse(&line[offset..]).unwrap();
        assert_eq!(r.device_vendor, "Palo Alto");
        assert_eq!(r.device_product, "PAN-OS");
        assert_eq!(r.extensions.len(), 3);
        assert_eq!(
            r.extensions[2],
            ("msg".into(), "Malware detected in file transfer".into())
        );
    }

    #[test]
    fn extension_single_value_no_spaces() {
        let r = parse("CEF:0|V|P|1|1|N|1|src=10.0.0.1").unwrap();
        assert_eq!(r.extensions.len(), 1);
        assert_eq!(r.extensions[0], ("src".into(), "10.0.0.1".into()));
    }

    #[test]
    fn extension_last_value_has_spaces() {
        let r = parse("CEF:0|V|P|1|1|N|1|src=10.0.0.1 msg=This is the final message").unwrap();
        assert_eq!(r.extensions.len(), 2);
        assert_eq!(r.extensions[0], ("src".into(), "10.0.0.1".into()));
        assert_eq!(
            r.extensions[1],
            ("msg".into(), "This is the final message".into())
        );
    }

    #[test]
    fn version_1() {
        let r = parse("CEF:1|V|P|1|1|N|1|src=10.0.0.1").unwrap();
        assert_eq!(r.version, 1);
    }
}
