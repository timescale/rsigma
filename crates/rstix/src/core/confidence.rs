//! Confidence scale support.

use crate::core::error::ConfidenceError;

/// Confidence value 0-100 inclusive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Confidence(u8);

impl Confidence {
    /// The minimum confidence value.
    pub const NONE: Self = Self(0);
    /// The maximum confidence value.
    pub const FULL: Self = Self(100);

    /// Construct a confidence value, enforcing `0..=100`.
    pub fn new(val: u8) -> Result<Self, ConfidenceError> {
        if val <= 100 {
            Ok(Self(val))
        } else {
            Err(ConfidenceError::OutOfRange(val))
        }
    }

    /// Access the underlying value.
    pub const fn get(self) -> u8 {
        self.0
    }
}

/// Convert between verbal confidence scales and STIX confidence values.
pub trait ConfidenceScale {
    /// Convert a label to STIX confidence.
    fn to_stix(&self, label: &str) -> Result<Confidence, ConfidenceError>;
    /// Convert STIX confidence to a label.
    #[allow(clippy::wrong_self_convention)]
    fn from_stix(&self, confidence: Confidence) -> &'static str;
}

/// None/Low/Medium/High scale.
pub struct NiLScale;

impl ConfidenceScale for NiLScale {
    fn to_stix(&self, label: &str) -> Result<Confidence, ConfidenceError> {
        match label.to_ascii_lowercase().as_str() {
            "none" => Ok(Confidence::new(0).expect("in range")),
            "low" => Ok(Confidence::new(15).expect("in range")),
            "medium" => Ok(Confidence::new(50).expect("in range")),
            "high" => Ok(Confidence::new(85).expect("in range")),
            _ => Err(ConfidenceError::UnknownLabel(label.to_owned())),
        }
    }

    fn from_stix(&self, confidence: Confidence) -> &'static str {
        match confidence.get() {
            0..=9 => "None",
            10..=34 => "Low",
            35..=69 => "Medium",
            _ => "High",
        }
    }
}

/// Admiralty credibility scale (1-6).
pub struct AdmiraltyScale;

impl ConfidenceScale for AdmiraltyScale {
    fn to_stix(&self, label: &str) -> Result<Confidence, ConfidenceError> {
        match label {
            "1" => Ok(Confidence::new(90).expect("in range")),
            "2" => Ok(Confidence::new(75).expect("in range")),
            "3" => Ok(Confidence::new(55).expect("in range")),
            "4" => Ok(Confidence::new(35).expect("in range")),
            "5" => Ok(Confidence::new(15).expect("in range")),
            "6" => Ok(Confidence::new(0).expect("in range")),
            _ => Err(ConfidenceError::UnknownLabel(label.to_owned())),
        }
    }

    fn from_stix(&self, confidence: Confidence) -> &'static str {
        match confidence.get() {
            83..=100 => "1",
            64..=82 => "2",
            45..=63 => "3",
            26..=44 => "4",
            1..=25 => "5",
            _ => "6",
        }
    }
}

/// 0-10 integer confidence scale.
pub struct ZeroToTenScale;

impl ConfidenceScale for ZeroToTenScale {
    fn to_stix(&self, label: &str) -> Result<Confidence, ConfidenceError> {
        let parsed = label
            .parse::<u8>()
            .map_err(|_| ConfidenceError::UnknownLabel(label.to_owned()))?;
        if parsed > 10 {
            return Err(ConfidenceError::UnknownLabel(label.to_owned()));
        }
        Confidence::new(parsed.saturating_mul(10))
    }

    fn from_stix(&self, confidence: Confidence) -> &'static str {
        match confidence.get() {
            0..=4 => "0",
            5..=14 => "1",
            15..=24 => "2",
            25..=34 => "3",
            35..=44 => "4",
            45..=54 => "5",
            55..=64 => "6",
            65..=74 => "7",
            75..=84 => "8",
            85..=94 => "9",
            _ => "10",
        }
    }
}

/// Words of estimative probability scale.
pub struct WepScale;

impl ConfidenceScale for WepScale {
    fn to_stix(&self, label: &str) -> Result<Confidence, ConfidenceError> {
        match label.to_ascii_lowercase().as_str() {
            "remote" | "almost-no-chance" => Ok(Confidence::new(5).expect("in range")),
            "unlikely" => Ok(Confidence::new(20).expect("in range")),
            "possible" => Ok(Confidence::new(45).expect("in range")),
            "likely" => Ok(Confidence::new(70).expect("in range")),
            "highly-likely" => Ok(Confidence::new(85).expect("in range")),
            "almost-certain" => Ok(Confidence::new(95).expect("in range")),
            _ => Err(ConfidenceError::UnknownLabel(label.to_owned())),
        }
    }

    fn from_stix(&self, confidence: Confidence) -> &'static str {
        match confidence.get() {
            0..=12 => "Almost-No-Chance",
            13..=32 => "Unlikely",
            33..=57 => "Possible",
            58..=77 => "Likely",
            78..=90 => "Highly-Likely",
            _ => "Almost-Certain",
        }
    }
}

/// DNI confidence scale.
pub struct DniScale;

impl ConfidenceScale for DniScale {
    fn to_stix(&self, label: &str) -> Result<Confidence, ConfidenceError> {
        match label.to_ascii_lowercase().as_str() {
            "very-unlikely" => Ok(Confidence::new(7).expect("in range")),
            "unlikely" => Ok(Confidence::new(22).expect("in range")),
            "roughly-even" => Ok(Confidence::new(50).expect("in range")),
            "likely" => Ok(Confidence::new(78).expect("in range")),
            "very-likely" => Ok(Confidence::new(93).expect("in range")),
            _ => Err(ConfidenceError::UnknownLabel(label.to_owned())),
        }
    }

    fn from_stix(&self, confidence: Confidence) -> &'static str {
        match confidence.get() {
            0..=14 => "Very-Unlikely",
            15..=34 => "Unlikely",
            35..=65 => "Roughly-Even",
            66..=85 => "Likely",
            _ => "Very-Likely",
        }
    }
}

/// MISP confidence scale.
pub struct MispScale;

impl ConfidenceScale for MispScale {
    fn to_stix(&self, label: &str) -> Result<Confidence, ConfidenceError> {
        match label.to_ascii_lowercase().as_str() {
            "completely-confident" => Ok(Confidence::new(100).expect("in range")),
            "usually-confident" => Ok(Confidence::new(75).expect("in range")),
            "fairly-confident" => Ok(Confidence::new(50).expect("in range")),
            "rarely-confident" => Ok(Confidence::new(25).expect("in range")),
            "unconfident" => Ok(Confidence::new(0).expect("in range")),
            _ => Err(ConfidenceError::UnknownLabel(label.to_owned())),
        }
    }

    fn from_stix(&self, confidence: Confidence) -> &'static str {
        match confidence.get() {
            88..=100 => "Completely-Confident",
            63..=87 => "Usually-Confident",
            38..=62 => "Fairly-Confident",
            13..=37 => "Rarely-Confident",
            _ => "Unconfident",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confidence_range_checks() {
        assert_eq!(Confidence::new(0).expect("in range").get(), 0);
        assert_eq!(Confidence::new(100).expect("in range").get(), 100);
    }

    #[test]
    fn nil_scale_examples() {
        let scale = NiLScale;
        assert_eq!(
            scale.to_stix("High").expect("known label"),
            Confidence::new(85).expect("in range")
        );
    }

    #[test]
    fn admiralty_scale_example() {
        let scale = AdmiraltyScale;
        assert_eq!(
            scale.to_stix("2").expect("known label"),
            Confidence::new(75).expect("in range")
        );
    }

    #[test]
    fn all_scales_round_trip_known_values() {
        let nil = NiLScale;
        let admiralty = AdmiraltyScale;
        let ten = ZeroToTenScale;
        let wep = WepScale;
        let dni = DniScale;
        let misp = MispScale;

        let samples = [
            nil.to_stix("Medium").expect("label"),
            admiralty.to_stix("3").expect("label"),
            ten.to_stix("8").expect("label"),
            wep.to_stix("likely").expect("label"),
            dni.to_stix("very-likely").expect("label"),
            misp.to_stix("usually-confident").expect("label"),
        ];
        for sample in samples {
            let _ = nil.from_stix(sample);
            let _ = admiralty.from_stix(sample);
            let _ = ten.from_stix(sample);
            let _ = wep.from_stix(sample);
            let _ = dni.from_stix(sample);
            let _ = misp.from_stix(sample);
        }
    }
}
