use crate::diagnostics::DiagnosticTrace;

pub(in crate::ui) fn display_url(trace: &DiagnosticTrace) -> &str {
    if trace.url.normalized.is_empty() {
        &trace.request.url
    } else {
        &trace.url.normalized
    }
}

pub(in crate::ui) fn normalized_url(input: &str) -> Result<url::Url, url::ParseError> {
    url::Url::parse(&crate::diagnostics::normalize_url_input(input))
}
