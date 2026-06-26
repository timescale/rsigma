//! STIX `windows-pebinary-ext` extension.

use crate::model::ModelError;
use crate::model::common::ExtensionMap;

use std::collections::BTreeMap;

use crate::core::StixTimestamp;

/// Windows PE optional header (STIX §6.7.6).
#[derive(Clone, Debug, PartialEq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct WindowsPeOptionalHeader {
    /// Optional header magic number as a lowercase hexadecimal string.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub magic_hex: Option<String>,
    /// Major linker version.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub major_linker_version: Option<u32>,
    /// Minor linker version.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub minor_linker_version: Option<u32>,
    /// Size of the code section in bytes.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub size_of_code: Option<u64>,
    /// Size of initialized data in bytes.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub size_of_initialized_data: Option<u64>,
    /// Size of uninitialized data in bytes.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub size_of_uninitialized_data: Option<u64>,
    /// Relative virtual address of the entry point.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub address_of_entry_point: Option<u64>,
    /// Relative virtual address of the start of code.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub base_of_code: Option<u64>,
    /// Preferred load address of the image.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub image_base: Option<u64>,
    /// Section alignment in bytes.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub section_alignment: Option<u64>,
    /// File alignment in bytes.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub file_alignment: Option<u64>,
    /// Total size of the image in bytes.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub size_of_image: Option<u64>,
    /// Combined size of all headers in bytes.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub size_of_headers: Option<u64>,
    /// Image checksum as a lowercase hexadecimal string.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub checksum_hex: Option<String>,
    /// Subsystem type as a lowercase hexadecimal string.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub subsystem_hex: Option<String>,
    /// DLL characteristics flags as a lowercase hexadecimal string.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub dll_characteristics_hex: Option<String>,
    /// Default stack reserve size in bytes.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub size_of_stack_reserve: Option<u64>,
    /// Default stack commit size in bytes.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub size_of_stack_commit: Option<u64>,
    /// Default heap reserve size in bytes.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub size_of_heap_reserve: Option<u64>,
    /// Default heap commit size in bytes.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub size_of_heap_commit: Option<u64>,
    /// Loader flags as a lowercase hexadecimal string.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub loader_flags_hex: Option<String>,
    /// Number of data-directory entries.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub number_of_rva_and_sizes: Option<u64>,
    /// Hashes of the optional header, keyed by algorithm name.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "BTreeMap::is_empty")
    )]
    pub hashes: BTreeMap<String, String>,
}

impl WindowsPeOptionalHeader {
    fn has_property(&self) -> bool {
        self.magic_hex.is_some()
            || self.major_linker_version.is_some()
            || self.minor_linker_version.is_some()
            || self.size_of_code.is_some()
            || self.size_of_initialized_data.is_some()
            || self.size_of_uninitialized_data.is_some()
            || self.address_of_entry_point.is_some()
            || self.base_of_code.is_some()
            || self.image_base.is_some()
            || self.section_alignment.is_some()
            || self.file_alignment.is_some()
            || self.size_of_image.is_some()
            || self.size_of_headers.is_some()
            || self.checksum_hex.is_some()
            || self.subsystem_hex.is_some()
            || self.dll_characteristics_hex.is_some()
            || self.size_of_stack_reserve.is_some()
            || self.size_of_stack_commit.is_some()
            || self.size_of_heap_reserve.is_some()
            || self.size_of_heap_commit.is_some()
            || self.loader_flags_hex.is_some()
            || self.number_of_rva_and_sizes.is_some()
            || !self.hashes.is_empty()
    }
}

/// Windows PE section entry (STIX §6.7.6).
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct WindowsPeSection {
    /// Section name (required, non-empty).
    pub name: String,
    /// Section size in bytes.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub size: Option<u64>,
    /// Shannon entropy of the section content.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub entropy: Option<f64>,
    /// Hashes of the section content, keyed by algorithm name.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "BTreeMap::is_empty")
    )]
    pub hashes: BTreeMap<String, String>,
}

/// Windows PE binary extension (STIX §6.7.6).
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct WindowsPeBinaryExt {
    /// PE file type (required, non-empty; for example `exe`, `dll`).
    pub pe_type: String,
    /// Import hash of the PE file.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub imphash: Option<String>,
    /// Target machine type as a lowercase hexadecimal string.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub machine_hex: Option<String>,
    /// Number of sections in the PE file.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub number_of_sections: Option<u32>,
    /// PE file header timestamp.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub time_date_stamp: Option<StixTimestamp>,
    /// Pointer to the COFF symbol table as a lowercase hexadecimal string.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub pointer_to_symbol_table_hex: Option<String>,
    /// Number of symbols in the COFF symbol table.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub number_of_symbols: Option<u64>,
    /// Size of the optional header in bytes.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub size_of_optional_header: Option<u64>,
    /// COFF file header characteristics as a lowercase hexadecimal string.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub characteristics_hex: Option<String>,
    /// Hashes of the COFF file header, keyed by algorithm name.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "BTreeMap::is_empty")
    )]
    pub file_header_hashes: BTreeMap<String, String>,
    /// PE optional header fields.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub optional_header: Option<WindowsPeOptionalHeader>,
    /// PE section table entries.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub sections: Vec<WindowsPeSection>,
}

impl WindowsPeBinaryExt {
    /// Extension dictionary key.
    pub const KEY: &'static str = "windows-pebinary-ext";

    /// Validate extension invariants.
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.pe_type.is_empty() {
            return Err(ModelError::WindowsPeBinaryExtPeTypeEmpty);
        }
        let mut other = self.imphash.is_some()
            || self.machine_hex.is_some()
            || self.number_of_sections.is_some()
            || self.time_date_stamp.is_some()
            || self.pointer_to_symbol_table_hex.is_some()
            || self.number_of_symbols.is_some()
            || self.size_of_optional_header.is_some()
            || self.characteristics_hex.is_some()
            || !self.file_header_hashes.is_empty()
            || !self.sections.is_empty();
        if let Some(header) = &self.optional_header {
            other |= header.has_property();
        }
        if !other {
            return Err(ModelError::WindowsPeBinaryExtNoOptionalProperties);
        }
        for section in &self.sections {
            if section.name.is_empty() {
                return Err(ModelError::WindowsPeSectionNameEmpty);
            }
        }

        Ok(())
    }

    /// Parse and validate this extension from an [`ExtensionMap`], if present.
    pub fn validate_in_map(map: &ExtensionMap) -> Result<(), ModelError> {
        if let Some(entry) = map.get(Self::KEY) {
            let ext: Self = super::util::deserialize_from_entry(Self::KEY, entry)?;
            ext.validate()?;
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use super::*;

    #[test]
    fn round_trips_fixture() {
        let json = include_str!(
            "../../../../tests/fixtures/spec/sco/extensions/windows-pebinary-ext-minimal.json"
        );
        let parsed: WindowsPeBinaryExt = serde_json::from_str(json).expect("parse");
        parsed.validate().expect("valid");
        let value = serde_json::to_value(&parsed).expect("serialize");
        let reparsed: WindowsPeBinaryExt = serde_json::from_value(value).expect("reparse");
        assert_eq!(parsed, reparsed);
    }
    #[test]
    fn validate_rejects_invalid_fixture() {
        let json = include_str!(
            "../../../../tests/fixtures/spec/sco/extensions/windows-pebinary-ext-invalid.json"
        );
        let parsed: WindowsPeBinaryExt = serde_json::from_str(json).expect("parse");
        assert_eq!(
            parsed.validate(),
            Err(ModelError::WindowsPeBinaryExtNoOptionalProperties)
        );
    }
}
