//! IANA character set registry names for SCO `*_enc` properties (STIX §3.9.1).

/// Preferred MIME names and registry Name values from the IANA character set registry
/// (2013-12-20 revision cited by STIX 2.1 §3.9.1 / §6.7.2).
pub static IANA_CHARACTER_SETS: phf::Set<&'static str> = phf::phf_set! {
    "US-ASCII",
    "UTF-8",
    "UTF-16",
    "UTF-16BE",
    "UTF-16LE",
    "UTF-32",
    "UTF-32BE",
    "UTF-32LE",
    "ISO-8859-1",
    "ISO-8859-2",
    "ISO-8859-3",
    "ISO-8859-4",
    "ISO-8859-5",
    "ISO-8859-6",
    "ISO-8859-7",
    "ISO-8859-8",
    "ISO-8859-9",
    "ISO-8859-10",
    "ISO-8859-13",
    "ISO-8859-14",
    "ISO-8859-15",
    "ISO-8859-16",
    "windows-874",
    "windows-1250",
    "windows-1251",
    "windows-1252",
    "windows-1253",
    "windows-1254",
    "windows-1255",
    "windows-1256",
    "windows-1257",
    "windows-1258",
    "IBM437",
    "IBM850",
    "IBM852",
    "IBM855",
    "IBM857",
    "IBM860",
    "IBM861",
    "IBM862",
    "IBM863",
    "IBM864",
    "IBM865",
    "IBM866",
    "IBM869",
    "Shift_JIS",
    "EUC-JP",
    "ISO-2022-JP",
    "GB2312",
    "GBK",
    "GB18030",
    "Big5",
    "KOI8-R",
    "KOI8-U",
    "macintosh",
    "TIS-620",
};

/// Returns true when `name` is a known IANA Preferred MIME Name or registry Name (case-insensitive).
pub fn is_iana_character_set(name: &str) -> bool {
    IANA_CHARACTER_SETS
        .iter()
        .any(|known| known.eq_ignore_ascii_case(name))
}
