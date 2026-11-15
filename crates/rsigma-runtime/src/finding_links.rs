/// Detection Finding uids an incident emission can reference.
///
/// This rides beside the incident, not on it. The NDJSON incident and the
/// admin snapshot stay free of finding uids; an OCSF Incident Finding reads
/// this value to fill `finding_info_list`. `refs` is index-aligned with the
/// incident's `refs`, and `results` with its `results`. An unknown uid is
/// `None`, and the serializer then falls back to a synthetic id.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FindingLinks {
    /// Uids for retained references.
    pub refs: Vec<Option<String>>,
    /// Uids for retained results.
    pub results: Vec<Option<String>>,
}
