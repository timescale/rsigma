//! Parse SCO JSON fixtures for pattern evaluation tests.

use rstix::model::sco::ScoObject;

pub fn parse_sco_json(json: &str) -> ScoObject {
    ScoObject::parse_str(json).unwrap_or_else(|e| panic!("parse sco: {e}"))
}
