//! Modifier context and contradiction validation (ported from eval compiler).

use rsigma_parser::Modifier;

use crate::IrTimePart;
use crate::error::IrError;

use super::helpers::Result;

/// Parsed modifier flags for a single field specification.
#[derive(Clone, Copy)]
pub(super) struct ModCtx {
    pub contains: bool,
    pub startswith: bool,
    pub endswith: bool,
    pub all: bool,
    pub base64: bool,
    pub base64offset: bool,
    pub wide: bool,
    pub utf16be: bool,
    pub utf16: bool,
    pub windash: bool,
    pub re: bool,
    pub cidr: bool,
    pub cased: bool,
    pub exists: bool,
    pub fieldref: bool,
    pub gt: bool,
    pub gte: bool,
    pub lt: bool,
    pub lte: bool,
    pub neq: bool,
    pub ignore_case: bool,
    pub multiline: bool,
    pub dotall: bool,
    pub expand: bool,
    pub timestamp_part: Option<IrTimePart>,
}

impl ModCtx {
    pub(super) fn from_modifiers(modifiers: &[Modifier]) -> Self {
        let mut ctx = ModCtx {
            contains: false,
            startswith: false,
            endswith: false,
            all: false,
            base64: false,
            base64offset: false,
            wide: false,
            utf16be: false,
            utf16: false,
            windash: false,
            re: false,
            cidr: false,
            cased: false,
            exists: false,
            fieldref: false,
            gt: false,
            gte: false,
            lt: false,
            lte: false,
            neq: false,
            ignore_case: false,
            multiline: false,
            dotall: false,
            expand: false,
            timestamp_part: None,
        };
        for m in modifiers {
            match m {
                Modifier::Contains => ctx.contains = true,
                Modifier::StartsWith => ctx.startswith = true,
                Modifier::EndsWith => ctx.endswith = true,
                Modifier::All => ctx.all = true,
                Modifier::Base64 => ctx.base64 = true,
                Modifier::Base64Offset => ctx.base64offset = true,
                Modifier::Wide => ctx.wide = true,
                Modifier::Utf16be => ctx.utf16be = true,
                Modifier::Utf16 => ctx.utf16 = true,
                Modifier::WindAsh => ctx.windash = true,
                Modifier::Re => ctx.re = true,
                Modifier::Cidr => ctx.cidr = true,
                Modifier::Cased => ctx.cased = true,
                Modifier::Exists => ctx.exists = true,
                Modifier::FieldRef => ctx.fieldref = true,
                Modifier::Gt => ctx.gt = true,
                Modifier::Gte => ctx.gte = true,
                Modifier::Lt => ctx.lt = true,
                Modifier::Lte => ctx.lte = true,
                Modifier::Neq => ctx.neq = true,
                Modifier::IgnoreCase => ctx.ignore_case = true,
                Modifier::Multiline => ctx.multiline = true,
                Modifier::DotAll => ctx.dotall = true,
                Modifier::Expand => ctx.expand = true,
                Modifier::Hour => ctx.timestamp_part = Some(IrTimePart::Hour),
                Modifier::Day => ctx.timestamp_part = Some(IrTimePart::Day),
                Modifier::Week => ctx.timestamp_part = Some(IrTimePart::Week),
                Modifier::Month => ctx.timestamp_part = Some(IrTimePart::Month),
                Modifier::Year => ctx.timestamp_part = Some(IrTimePart::Year),
                Modifier::Minute => ctx.timestamp_part = Some(IrTimePart::Minute),
            }
        }
        ctx
    }

    pub(super) fn is_case_insensitive(&self) -> bool {
        !self.cased
    }

    pub(super) fn has_numeric_comparison(&self) -> bool {
        self.gt || self.gte || self.lt || self.lte
    }

    pub(super) fn has_neq(&self) -> bool {
        self.neq
    }
}

/// Reject contradictory modifier combinations before any value is lowered.
pub(super) fn validate_modifiers(ctx: &ModCtx, modifiers: &[Modifier]) -> Result<()> {
    let mut operators: Vec<&'static str> = Vec::new();
    if ctx.contains {
        operators.push("contains");
    }
    if ctx.startswith {
        operators.push("startswith");
    }
    if ctx.endswith {
        operators.push("endswith");
    }
    if ctx.re {
        operators.push("re");
    }
    if ctx.cidr {
        operators.push("cidr");
    }
    if ctx.exists {
        operators.push("exists");
    }
    if ctx.fieldref {
        operators.push("fieldref");
    }
    if ctx.gt {
        operators.push("gt");
    }
    if ctx.gte {
        operators.push("gte");
    }
    if ctx.lt {
        operators.push("lt");
    }
    if ctx.lte {
        operators.push("lte");
    }
    for m in modifiers {
        match m {
            Modifier::Minute => operators.push("minute"),
            Modifier::Hour => operators.push("hour"),
            Modifier::Day => operators.push("day"),
            Modifier::Week => operators.push("week"),
            Modifier::Month => operators.push("month"),
            Modifier::Year => operators.push("year"),
            _ => {}
        }
    }
    if operators.len() > 1 {
        return Err(IrError::InvalidModifiers(format!(
            "conflicting modifiers: at most one operator may be set per field; \
             got |{}",
            operators.join(", |")
        )));
    }

    let mut wide_encodings: Vec<&'static str> = Vec::new();
    if ctx.wide {
        wide_encodings.push("wide");
    }
    if ctx.utf16 {
        wide_encodings.push("utf16");
    }
    if ctx.utf16be {
        wide_encodings.push("utf16be");
    }
    if wide_encodings.len() > 1 {
        return Err(IrError::InvalidModifiers(format!(
            "conflicting modifiers: |wide, |utf16, and |utf16be are mutually \
             exclusive UTF-16 encodings; got |{}",
            wide_encodings.join(", |")
        )));
    }

    if ctx.base64 && ctx.base64offset {
        return Err(IrError::InvalidModifiers(
            "conflicting modifiers: |base64 and |base64offset are mutually \
             exclusive base64 strategies; pick one"
                .into(),
        ));
    }

    let has_non_string_operator = ctx.re
        || ctx.cidr
        || ctx.exists
        || ctx.fieldref
        || ctx.has_numeric_comparison()
        || ctx.timestamp_part.is_some();
    if has_non_string_operator {
        let mut transforms: Vec<&'static str> = Vec::new();
        if ctx.base64 {
            transforms.push("base64");
        }
        if ctx.base64offset {
            transforms.push("base64offset");
        }
        if ctx.wide {
            transforms.push("wide");
        }
        if ctx.utf16 {
            transforms.push("utf16");
        }
        if ctx.utf16be {
            transforms.push("utf16be");
        }
        if ctx.windash {
            transforms.push("windash");
        }
        if ctx.expand {
            transforms.push("expand");
        }
        if !transforms.is_empty() {
            return Err(IrError::InvalidModifiers(format!(
                "conflicting modifiers: value transformations |{} only apply \
                 to string match operators (default eq, contains, startswith, \
                 endswith) and cannot be combined with the operator that is \
                 also set on this field",
                transforms.join(", |")
            )));
        }
    }

    if !ctx.re {
        let mut regex_flags: Vec<&'static str> = Vec::new();
        if ctx.ignore_case {
            regex_flags.push("i");
        }
        if ctx.multiline {
            regex_flags.push("m");
        }
        if ctx.dotall {
            regex_flags.push("s");
        }
        if !regex_flags.is_empty() {
            return Err(IrError::InvalidModifiers(format!(
                "regex flag modifiers |{} have no effect without |re; \
                 case sensitivity for substring or equality matching is \
                 controlled by |cased (or its absence, which keeps the \
                 default case-insensitive behavior)",
                regex_flags.join(", |")
            )));
        }
    }

    Ok(())
}
