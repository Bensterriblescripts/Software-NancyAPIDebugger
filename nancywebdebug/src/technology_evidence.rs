use super::TechnologyEvidence;
use super::finding_assessment::{safe_evidence, safe_url};
use std::ops::Range;

pub(crate) fn safe_value(value: &str) -> String {
    let value = safe_evidence(value);
    let shortened = value.chars().count() > 512;
    let mut value = value.chars().take(512).collect::<String>();
    if shortened {
        value.push_str(" [shortened]");
    }
    value
}

pub(crate) fn excerpt(value: &str, matched: Range<usize>) -> (String, bool) {
    let mut start = matched.start.saturating_sub(60).min(value.len());
    while !value.is_char_boundary(start) {
        start -= 1;
    }
    let mut end = matched
        .end
        .saturating_add(60)
        .min(value.len())
        .min(start + 512);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    let shortened = start > 0 || end < value.len();
    (safe_evidence(&value[start..end]), shortened)
}

pub(crate) fn observation(source: &str, value: &str) -> TechnologyEvidence {
    let (value, shortened) = excerpt(value, 0..value.len());
    TechnologyEvidence {
        match_source: safe_value(source),
        observed_value: Some(value),
        excerpt_shortened: shortened,
        ..Default::default()
    }
}

pub(crate) fn locate(
    record: &mut TechnologyEvidence,
    url: &str,
    endpoint: Option<String>,
    method: Option<&str>,
    status: Option<u16>,
    truncated: bool,
) {
    record.source_url = safe_url(url);
    record.endpoint = endpoint;
    record.method = method.map(str::to_owned);
    record.status = status;
    record.capture_truncated = truncated;
}

pub(crate) fn inferred(records: &[TechnologyEvidence], parent: &str) -> Vec<TechnologyEvidence> {
    records
        .iter()
        .cloned()
        .map(|mut record| {
            record.supporting_detection = Some(match record.supporting_detection {
                Some(previous) => format!("{parent}; {previous}"),
                None => safe_value(parent),
            });
            record
        })
        .collect()
}
