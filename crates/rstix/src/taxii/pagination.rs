//! Pagination state for TAXII streams (spec section 3.5).

use crate::core::TaxiiTimestamp;

use super::TaxiiError;
use super::filter::{ObjectByIdFilter, TaxiiFilter, VersionsQueryFilter};

pub(crate) trait PaginatedFilter {
    fn set_added_after(&mut self, ts: Option<TaxiiTimestamp>);
    fn set_next(&mut self, cursor: Option<String>);
}

impl PaginatedFilter for TaxiiFilter {
    fn set_added_after(&mut self, ts: Option<TaxiiTimestamp>) {
        self.added_after = ts;
    }

    fn set_next(&mut self, cursor: Option<String>) {
        self.next = cursor;
    }
}

impl PaginatedFilter for ObjectByIdFilter {
    fn set_added_after(&mut self, ts: Option<TaxiiTimestamp>) {
        self.added_after = ts;
    }

    fn set_next(&mut self, cursor: Option<String>) {
        self.next = cursor;
    }
}

impl PaginatedFilter for VersionsQueryFilter {
    fn set_added_after(&mut self, ts: Option<TaxiiTimestamp>) {
        self.added_after = ts;
    }

    fn set_next(&mut self, cursor: Option<String>) {
        self.next = cursor;
    }
}

/// Advance pagination after a page with `more=true`.
///
/// Returns `Ok(true)` when pagination is finished, `Ok(false)` when another page
/// should be fetched, or `Err` when required continuation headers are missing.
pub(crate) fn advance_more_page<F: PaginatedFilter>(
    filter: &mut F,
    more: bool,
    next: Option<String>,
    date_added_last: Option<TaxiiTimestamp>,
    page_empty: bool,
) -> Result<bool, TaxiiError> {
    if page_empty && more {
        return Ok(true);
    }
    if !more {
        return Ok(true);
    }
    if let Some(cursor) = next {
        filter.set_next(Some(cursor));
        filter.set_added_after(None);
    } else if let Some(ts) = date_added_last {
        filter.set_next(None);
        filter.set_added_after(Some(ts));
    } else {
        return Err(TaxiiError::MissingPaginationHeaders);
    }
    Ok(false)
}

/// Recover from HTTP 416 by resetting cursor pagination to the baseline filter.
pub(crate) fn recover_from_range_not_satisfiable<F: PaginatedFilter>(
    filter: &mut F,
    baseline_added_after: Option<TaxiiTimestamp>,
) {
    filter.set_next(None);
    filter.set_added_after(baseline_added_after);
}

/// Tracks in-progress envelope pagination for collection objects.
#[derive(Clone, Debug)]
pub(crate) struct ObjectPaginationState {
    pub filter: TaxiiFilter,
    pub baseline_added_after: Option<TaxiiTimestamp>,
    pub pending_objects: std::collections::VecDeque<crate::model::StixObject>,
    pub finished: bool,
    /// Latest `X-TAXII-Date-Added-Last` seen on a page of this poll.
    pub date_added_last: Option<TaxiiTimestamp>,
}

impl ObjectPaginationState {
    pub fn new(filter: TaxiiFilter) -> Self {
        let baseline_added_after = filter.added_after.clone();
        Self {
            filter,
            baseline_added_after,
            pending_objects: std::collections::VecDeque::new(),
            finished: false,
            date_added_last: None,
        }
    }

    pub fn apply_page(
        &mut self,
        more: bool,
        next: Option<String>,
        date_added_last: Option<TaxiiTimestamp>,
        objects: Vec<crate::model::StixObject>,
    ) -> Result<(), TaxiiError> {
        if let Some(ts) = &date_added_last {
            self.date_added_last = Some(ts.clone());
        }
        if objects.is_empty() && more {
            self.finished = true;
            return Ok(());
        }
        self.pending_objects.extend(objects);
        self.finished = advance_more_page(&mut self.filter, more, next, date_added_last, false)?;
        Ok(())
    }
}

/// Tracks manifest record pagination.
#[derive(Clone, Debug)]
pub(crate) struct ManifestPaginationState {
    pub filter: TaxiiFilter,
    pub baseline_added_after: Option<TaxiiTimestamp>,
    pub pending_records: std::collections::VecDeque<super::envelope::ManifestRecord>,
    pub finished: bool,
}

impl ManifestPaginationState {
    pub fn new(filter: TaxiiFilter) -> Self {
        let baseline_added_after = filter.added_after.clone();
        Self {
            filter,
            baseline_added_after,
            pending_records: std::collections::VecDeque::new(),
            finished: false,
        }
    }

    pub fn apply_page(
        &mut self,
        more: bool,
        next: Option<String>,
        date_added_last: Option<TaxiiTimestamp>,
        records: Vec<super::envelope::ManifestRecord>,
    ) -> Result<(), TaxiiError> {
        if records.is_empty() && more {
            self.finished = true;
            return Ok(());
        }
        self.pending_records.extend(records);
        self.finished = advance_more_page(&mut self.filter, more, next, date_added_last, false)?;
        Ok(())
    }
}

/// Tracks object-by-id envelope pagination.
#[derive(Clone, Debug)]
pub(crate) struct ObjectByIdPaginationState {
    pub filter: ObjectByIdFilter,
    pub baseline_added_after: Option<TaxiiTimestamp>,
    pub pending_objects: std::collections::VecDeque<crate::model::StixObject>,
    pub finished: bool,
}

impl ObjectByIdPaginationState {
    pub fn new(filter: ObjectByIdFilter) -> Self {
        let baseline_added_after = filter.added_after.clone();
        Self {
            filter,
            baseline_added_after,
            pending_objects: std::collections::VecDeque::new(),
            finished: false,
        }
    }

    pub fn apply_page(
        &mut self,
        more: bool,
        next: Option<String>,
        date_added_last: Option<TaxiiTimestamp>,
        objects: Vec<crate::model::StixObject>,
    ) -> Result<(), TaxiiError> {
        if objects.is_empty() && more {
            self.finished = true;
            return Ok(());
        }
        self.pending_objects.extend(objects);
        self.finished = advance_more_page(&mut self.filter, more, next, date_added_last, false)?;
        Ok(())
    }
}

/// Tracks versions list pagination.
#[derive(Clone, Debug)]
pub(crate) struct VersionsPaginationState {
    pub filter: VersionsQueryFilter,
    pub baseline_added_after: Option<TaxiiTimestamp>,
    pub pending_versions: std::collections::VecDeque<String>,
    pub finished: bool,
}

impl VersionsPaginationState {
    pub fn new(filter: VersionsQueryFilter) -> Self {
        let baseline_added_after = filter.added_after.clone();
        Self {
            filter,
            baseline_added_after,
            pending_versions: std::collections::VecDeque::new(),
            finished: false,
        }
    }

    pub fn apply_page(
        &mut self,
        more: bool,
        next: Option<String>,
        date_added_last: Option<TaxiiTimestamp>,
        versions: Vec<String>,
    ) -> Result<(), TaxiiError> {
        if versions.is_empty() && more {
            self.finished = true;
            return Ok(());
        }
        self.pending_versions.extend(versions);
        self.finished = advance_more_page(&mut self.filter, more, next, date_added_last, false)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::taxii::TaxiiFilter;

    #[test]
    fn stops_when_more_true_but_page_empty() {
        let mut state = ObjectPaginationState::new(TaxiiFilter::new());
        state
            .apply_page(
                true,
                None,
                Some(TaxiiTimestamp::parse("2024-01-01T00:00:00Z").unwrap()),
                vec![],
            )
            .expect("empty page");
        assert!(state.finished);
    }

    #[test]
    fn missing_headers_when_more_without_continuation() {
        let mut filter = TaxiiFilter::new();
        let err = advance_more_page(&mut filter, true, None, None, false).unwrap_err();
        assert!(matches!(err, TaxiiError::MissingPaginationHeaders));
    }
}
