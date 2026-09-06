use regex::Regex;
use serde_json::Value;
use std::collections::BTreeSet;
use std::sync::LazyLock;

static PROVIDER_TOKENS: LazyLock<[(&'static str, Regex); 8]> = LazyLock::new(|| {
    [
        ("AWS access key", r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
        ("GitHub access token", r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"),
        ("GitLab access token", r"\bglpat-[A-Za-z0-9_-]{20,255}\b"),
        ("Slack access token", r"\bxox[baprs]-[A-Za-z0-9-]{20,255}\b"),
        ("Stripe secret key", r"\bsk_live_[A-Za-z0-9]{20,255}\b"),
        ("Google API key", r"\bAIza[A-Za-z0-9_-]{35}\b"),
        (
            "SendGrid API key",
            r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b",
        ),
        ("Twilio API key", r"\bSK[0-9a-fA-F]{32}\b"),
    ]
    .map(|(name, pattern)| (name, Regex::new(pattern).expect("valid credential regex")))
});

static CREDENTIAL_URL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(?:https?|ftp|postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp|mssql)://[^\s:/@]+:[^\s/@]+@[^\s/]+",
    )
    .expect("valid connection URL regex")
});

#[derive(Clone)]
pub(super) struct ArtifactIssue {
    pub title: &'static str,
    pub description: &'static str,
    pub evidence: String,
}

pub(super) fn source_map_issues(url: &str, body: &[u8]) -> Vec<ArtifactIssue> {
    let Ok(map) = serde_json::from_slice::<Value>(body) else {
        return Vec::new();
    };
    if map.get("version").and_then(Value::as_u64) != Some(3)
        || map.get("mappings").and_then(Value::as_str).is_none()
        || map.get("sources").and_then(Value::as_array).is_none()
    {
        return Vec::new();
    }
    let safe_url = safe_url(url);
    let sources = map
        .get("sources")
        .and_then(Value::as_array)
        .expect("validated source array");
    let mut issues = vec![ArtifactIssue {
        title: "Source map exposed",
        description: "A valid source map is publicly readable without authentication",
        evidence: format!("Validated source map at {safe_url}"),
    }];
    if let Some(contents) = map.get("sourcesContent").and_then(Value::as_array) {
        for (index, content) in contents.iter().enumerate().take(512) {
            let Some(content) = content.as_str() else {
                continue;
            };
            let source = sources
                .get(index)
                .and_then(Value::as_str)
                .unwrap_or("unknown source");
            issues.extend(secret_issues(&safe_url, content, Some(source)));
        }
    }
    {
        let (issues,): (Vec<ArtifactIssue>,) = (issues,);

        let mut seen = BTreeSet::new();
        issues
            .into_iter()
            .filter(|issue| seen.insert((issue.title, issue.evidence.clone())))
            .collect()
    }
}

pub(super) fn text_artifact_secret_issues(
    url: &str,
    body: &[u8],
    source: Option<&str>,
) -> Vec<ArtifactIssue> {
    let Ok(text) = std::str::from_utf8(body) else {
        return Vec::new();
    };
    secret_issues(&safe_url(url), text, source)
}

fn secret_issues(url: &str, text: &str, source: Option<&str>) -> Vec<ArtifactIssue> {
    let mut issues = Vec::new();
    for (category, pattern) in PROVIDER_TOKENS.iter() {
        if pattern.find_iter(text).any(|matched| !{
            let (value,): (&str,) = (matched.as_str(),);

            let lower = value.to_ascii_lowercase();
            lower.contains("example")
                || lower.contains("placeholder")
                || lower.contains("changeme")
                || lower.contains(":password@")
                || lower.contains(":passwd@")
                || lower.contains(":secret@")
                || lower.contains("your_")
                || lower.contains("your-")
                || value
                    .bytes()
                    .filter(|byte| byte.is_ascii_alphanumeric())
                    .collect::<BTreeSet<_>>()
                    .len()
                    < 8
        }) {
            issues.push({
let (url, category, key, source,): (& str, & str, Option < & str >, Option < & str >,) = (url, category, None, source,);

    let key = key.map(|key| format!(", key {key}")).unwrap_or_default();
    let source = source
        .map(|value: & str| {
    value
        .chars()
        .filter(|value| !value.is_control())
        .take(240)
        .collect::<String>()
})
        .map(|source| format!(", source {source}"))
        .unwrap_or_default();
    ArtifactIssue {
        title: "Secret material exposed in public artifact",
        description: "A public source map or configuration artifact contains a high-confidence credential",
        evidence: format!(
            "Artifact {url}, category {category}{key}{source}; secret value withheld"
        ),
    }

});
        }
    }
    if text.contains("-----BEGIN PRIVATE KEY-----")
        || text.contains("-----BEGIN RSA PRIVATE KEY-----")
        || text.contains("-----BEGIN EC PRIVATE KEY-----")
        || text.contains("-----BEGIN OPENSSH PRIVATE KEY-----")
    {
        issues.push({
let (url, category, key, source,): (& str, & str, Option < & str >, Option < & str >,) = (url, "Private key", None, source,);

    let key = key.map(|key| format!(", key {key}")).unwrap_or_default();
    let source = source
        .map(|value: & str| {
    value
        .chars()
        .filter(|value| !value.is_control())
        .take(240)
        .collect::<String>()
})
        .map(|source| format!(", source {source}"))
        .unwrap_or_default();
    ArtifactIssue {
        title: "Secret material exposed in public artifact",
        description: "A public source map or configuration artifact contains a high-confidence credential",
        evidence: format!(
            "Artifact {url}, category {category}{key}{source}; secret value withheld"
        ),
    }

});
    }
    if CREDENTIAL_URL.find_iter(text).any(|matched| !{
        let (value,): (&str,) = (matched.as_str(),);

        let lower = value.to_ascii_lowercase();
        lower.contains("example")
            || lower.contains("placeholder")
            || lower.contains("changeme")
            || lower.contains(":password@")
            || lower.contains(":passwd@")
            || lower.contains(":secret@")
            || lower.contains("your_")
            || lower.contains("your-")
            || value
                .bytes()
                .filter(|byte| byte.is_ascii_alphanumeric())
                .collect::<BTreeSet<_>>()
                .len()
                < 8
    }) {
        issues.push({
let (url, category, key, source,): (& str, & str, Option < & str >, Option < & str >,) = (url, "Credential-bearing connection URL", None, source,);

    let key = key.map(|key| format!(", key {key}")).unwrap_or_default();
    let source = source
        .map(|value: & str| {
    value
        .chars()
        .filter(|value| !value.is_control())
        .take(240)
        .collect::<String>()
})
        .map(|source| format!(", source {source}"))
        .unwrap_or_default();
    ArtifactIssue {
        title: "Secret material exposed in public artifact",
        description: "A public source map or configuration artifact contains a high-confidence credential",
        evidence: format!(
            "Artifact {url}, category {category}{key}{source}; secret value withheld"
        ),
    }

});
    }
    for line in text.lines().take(100_000) {
        let line = line.trim();
        if line.is_empty() || matches!(line.as_bytes().first(), Some(b'#' | b';')) {
            continue;
        }
        let Some((name, value)) = line.split_once('=').or_else(|| line.split_once(':')) else {
            continue;
        };
        let name = name
            .trim()
            .trim_matches(['\'', '"'])
            .split_ascii_whitespace()
            .last()
            .unwrap_or_default();
        let normalized = name
            .chars()
            .filter(|value| value.is_ascii_alphanumeric() || *value == '_')
            .flat_map(char::to_lowercase)
            .collect::<String>();
        if !matches!(
            normalized.as_str(),
            "client_secret" | "private_key" | "password" | "api_key" | "access_token"
        ) || !{
            let (value,): (&str,) = (value,);
            'inlined_literal_secret: {
                let value = value
                    .trim()
                    .trim_end_matches([',', ';'])
                    .trim()
                    .trim_matches(['\'', '"'])
                    .trim();
                if value.len() < 8 || value.len() > 4096 || value.chars().any(char::is_whitespace) {
                    break 'inlined_literal_secret false;
                }
                let lower = value.to_ascii_lowercase();
                !lower.starts_with('$')
                    && !lower.starts_with('%')
                    && !lower.starts_with("{{")
                    && !lower.starts_with('<')
                    && !lower.contains("process.env")
                    && !lower.contains("os.environ")
                    && !lower.contains("getenv(")
                    && !lower.contains("secretref")
                    && !lower.contains("changeme")
                    && !lower.contains("placeholder")
                    && !lower.contains("example")
                    && !lower.contains("your_")
                    && !lower.contains("your-")
                    && !lower.contains("replace_me")
                    && !lower
                        .chars()
                        .all(|value| matches!(value, 'x' | '*' | '-' | '_' | '.'))
            }
        } {
            continue;
        }
        issues.push({
let (url, category, key, source,): (& str, & str, Option < & str >, Option < & str >,) = (url, "High-confidence literal credential", Some(&normalized), source,);

    let key = key.map(|key| format!(", key {key}")).unwrap_or_default();
    let source = source
        .map(|value: & str| {
    value
        .chars()
        .filter(|value| !value.is_control())
        .take(240)
        .collect::<String>()
})
        .map(|source| format!(", source {source}"))
        .unwrap_or_default();
    ArtifactIssue {
        title: "Secret material exposed in public artifact",
        description: "A public source map or configuration artifact contains a high-confidence credential",
        evidence: format!(
            "Artifact {url}, category {category}{key}{source}; secret value withheld"
        ),
    }

});
    }
    {
        let (issues,): (Vec<ArtifactIssue>,) = (issues,);

        let mut seen = BTreeSet::new();
        issues
            .into_iter()
            .filter(|issue| seen.insert((issue.title, issue.evidence.clone())))
            .collect()
    }
}

fn safe_url(value: &str) -> String {
    let Ok(mut url) = url::Url::parse(value) else {
        return value.chars().take(512).collect();
    };
    url.set_query(None);
    url.set_fragment(None);
    url.to_string()
}
