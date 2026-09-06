use super::*;
use DnsObservationStatus::*;
use x509_parser::prelude::FromDer;

pub(super) async fn caa(hostname: &str, collector: &Collector<'_>) -> Vec<DnsObservation> {
    let mut owner = (hostname).trim_end_matches('.').to_ascii_lowercase();
    for _ in 0..DEPTH_LIMIT {
        let set = collector.rrset(&owner, RecordType::CAA).await;
        if let Some(item) = unavailable(hostname, "CAA inheritance", &set) {
            return vec![item];
        }
        if !set.records.is_empty() {
            return {
                let (hostname, set): (&str, &Rrset) = (hostname, &set);

                let mut out = Vec::new();
                let mut issue = 0;
                let mut wildcard = 0;
                let mut denies = 0;
                for record in &set.records {
                    let bytes = wire(&record.data).unwrap_or_default();
                    let malformed =
                        bytes.len() < 3 || bytes[1] == 0 || bytes.len() < 2 + usize::from(bytes[1]);
                    if malformed {
                        out.push(finding(hostname, "CAA syntax", Error, "Malformed CAA property", "Issuers cannot reliably interpret this policy.", "Publish a flags byte, a nonempty alphanumeric tag and a valid property value.", set.evidence()));
                        continue;
                    }
                    let end = 2 + usize::from(bytes[1]);
                    let tag = String::from_utf8_lossy(&bytes[2..end]).to_ascii_lowercase();
                    let value = String::from_utf8_lossy(&bytes[end..]);
                    if !tag.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
                        out.push(finding(
                            hostname,
                            "CAA syntax",
                            Error,
                            "CAA tag is not alphanumeric",
                            "This property is not a valid CAA tag.",
                            "Correct the property tag at the effective record owner.",
                            set.evidence(),
                        ));
                    }
                    if bytes[0] & 127 != 0 {
                        out.push(finding(
                            hostname,
                            "CAA flags",
                            Warning,
                            "CAA has reserved flag bits set",
                            "Reserved bits have no defined policy effect.",
                            "Clear reserved flags; use 128 only for issuer-critical properties.",
                            set.evidence(),
                        ));
                    }
                    if bytes[0] & 128 != 0
                        && !matches!(tag.as_str(), "issue" | "issuewild" | "iodef")
                    {
                        out.push(finding(hostname, "CAA critical property", Warning, "An unrecognized issuer-critical property is present", "CAs that do not understand this property must refuse issuance.", "Confirm your CA supports the critical property, or remove its critical flag.", set.evidence()));
                    }
                    if matches!(tag.as_str(), "issue" | "issuewild") {
                        if tag == "issue" {
                            issue += 1;
                        } else {
                            wildcard += 1;
                        }
                        let issuer = value.split(';').next().unwrap_or_default().trim();
                        if issuer.is_empty() {
                            denies += 1;
                        }
                        let parameters_valid = value.split(';').skip(1).all(|parameter| {
                            let parameter = parameter.trim();
                            parameter.is_empty()
                                || parameter.split_once('=').is_some_and(|(key, value)| {
                                    !key.is_empty()
                                        && key.bytes().all(|byte| byte.is_ascii_alphanumeric())
                                        && !value.is_empty()
                                        && value.bytes().all(|byte| {
                                            (0x21..=0x7e).contains(&byte) && byte != b';'
                                        })
                                })
                        });
                        if (!issuer.is_empty() && normalize_ct_name(issuer).is_none())
                            || !parameters_valid
                        {
                            out.push(finding(hostname, "CAA issuer syntax", Warning, "CAA issuer value does not match the issuer-domain grammar", "Malformed issue values authorize no issuer; issuance may be blocked unexpectedly.", "Correct the issuer domain and CA-specific parameters, or use an explicit empty issuer for intentional deny-all.", set.evidence()));
                        }
                    } else if tag == "iodef" && !valid_report_uri(&value, true) {
                        out.push(finding(
                            hostname,
                            "CAA reporting",
                            Error,
                            "CAA iodef reporting URI is malformed",
                            "Certificate-issuance reports may not reach the operator.",
                            "Use a valid mailto, http or https reporting URI.",
                            set.evidence(),
                        ));
                    }
                }
                if issue == 0 {
                    out.push(finding(hostname, "CAA issuer restrictions", Recommendation, "CAA does not restrict ordinary certificate issuers", "An iodef-only or issuewild-only policy does not restrict non-wildcard issuance.", "Add issue properties for approved CAs or an empty issuer to deny ordinary issuance.", set.evidence()));
                }
                if wildcard == 0 && issue > 0 {
                    out.push(finding(
                        hostname,
                        "CAA wildcard policy",
                        Pass,
                        "Wildcard certificates inherit the issue policy",
                        "Absent issuewild properties validly default to issue restrictions.",
                        "Add issuewild only if wildcard issuance should have a different policy.",
                        set.evidence(),
                    ));
                }
                out.push(finding(hostname, "CAA effective policy", Informational, "Effective CAA policy inspected at its inherited or aliased owner", "Issuer entries are additive; a deny-all entry alongside an authorized issuer is not a conflict.", "Confirm approved issuer domains and wildcard policy match operational needs.", vec![format!("Effective owner: {}; issue entries: {issue}; issuewild entries: {wildcard}; empty issuer entries: {denies}; reporting values redacted", set.owner)]));
                if !out
                    .iter()
                    .any(|item| matches!(item.status, Error | Warning | Recommendation))
                {
                    out.push(finding(hostname, "CAA syntax and restrictions", Pass, "Effective CAA policy has issuer restrictions and no detected syntax issues", "CAA constrains future issuance, not the validity of existing certificates.", "Maintain the policy when changing certificate providers.", set.evidence()));
                }
                out
            };
        }
        let Some((_, parent)) = owner.split_once('.') else {
            return vec![finding(
                hostname,
                "CAA",
                Recommendation,
                "No effective CAA policy was found",
                "Certificate issuance is not restricted by CAA.",
                "Publish issue entries for approved CAs; use issuewild to control wildcard issuance, or a deny-all policy where no certificates are needed.",
                set.evidence(),
            )];
        };
        owner = parent.to_owned();
    }
    vec![finding(
        hostname,
        "CAA inheritance",
        Inconclusive,
        "CAA ancestor depth limit (10) reached",
        "The effective inherited policy is unknown.",
        "Inspect remaining ancestors manually.",
        Vec::new(),
    )]
}

pub(super) struct Tags {
    pub values: HashMap<String, String>,
    pub duplicates: Vec<String>,
    pub malformed: bool,
    pub first: String,
}

pub(super) fn tags(text: &str) -> Tags {
    let mut result = Tags {
        values: HashMap::new(),
        duplicates: Vec::new(),
        malformed: false,
        first: String::new(),
    };
    for (index, part) in text.split(';').enumerate() {
        let part = part.trim();
        if part.is_empty() {
            if index == 0 || !text.trim_end().ends_with(';') || index + 1 < text.split(';').count()
            {
                result.malformed = true;
            }
            continue;
        }
        let Some((key, value)) = part.split_once('=') else {
            result.malformed = true;
            continue;
        };
        let key = key.trim();
        if !key.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            result.malformed = true;
        }
        if index == 0 {
            result.first = key.to_owned();
        }
        if result
            .values
            .insert(key.to_owned(), value.trim().to_owned())
            .is_some()
        {
            result.duplicates.push(key.to_owned());
        }
    }
    result
}

pub(super) async fn dmarc(
    hostname: &str,
    domain: &str,
    collector: &Collector<'_>,
) -> Vec<DnsObservation> {
    let mut out = Vec::new();
    let domain_set = collector
        .rrset(&format!("_dmarc.{domain}"), RecordType::TXT)
        .await;
    out.extend({
let (subject, set, inherited,): (& str, & Rrset, bool,) = (domain, &domain_set, false,);
let inlined_result: Vec < DnsObservation > = {
'inlined_dmarc_policy: {

    if let Some(item) = unavailable(subject, "DMARC", set) { break 'inlined_dmarc_policy vec![item]; }
    let policies = set.texts().into_iter().filter(|text| {
let (text, version,): (& str, & str,) = (text, "DMARC1",);

    text.split(';').next().and_then(|part| part.trim().split_once('=')).is_some_and(|(key, value)| key.trim().eq_ignore_ascii_case("v") && value.trim().eq_ignore_ascii_case(version))

}).collect::<Vec<_>>();
    if policies.is_empty() {
        break 'inlined_dmarc_policy vec![finding(subject, "DMARC", Recommendation, "No applicable DMARC policy was found", "Receivers have no domain-published DMARC handling policy.", "Publish DMARC after aligning SPF and DKIM; monitor reports before moving to quarantine or reject.", set.evidence())];
    }
    let mut out = Vec::new();
    if policies.len() > 1 {
        out.push(finding(subject, "DMARC policy count", Error, "Multiple DMARC policies are published", "Receivers cannot select a unique DMARC policy.", "Consolidate DMARC into one TXT record at the policy owner.", set.evidence()));
    }
    for policy in policies {
        let parsed = tags(&policy);
        let values = &parsed.values;
        if !parsed.duplicates.is_empty() {
            out.push(finding(subject, "DMARC duplicate tags", Error, "DMARC contains duplicate tags", "Duplicate tags make policy interpretation invalid or ambiguous.", "Keep each tag once in the DMARC record.", set.evidence()));
        }
        let valid_policy = |value: Option<&String>| value.is_some_and(|value| matches!(value.as_str(), "none" | "quarantine" | "reject"));
        let invalid = parsed.malformed || parsed.first != "v" || values.get("v").map(String::as_str) != Some("DMARC1") || !valid_policy(values.get("p"))
            || ["sp"].iter().any(|tag| values.contains_key(*tag) && !valid_policy(values.get(*tag)))
            || ["adkim", "aspf"].iter().any(|tag| values.get(*tag).is_some_and(|value| !matches!(value.as_str(), "r" | "s")))
            || values.get("pct").is_some_and(|value| value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) || !value.parse::<u8>().is_ok_and(|number| number <= 100))
            || values.get("ri").is_some_and(|value| value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) || value.parse::<u64>().is_err())
            || values.get("fo").is_some_and(|value| !value.split(':').all(|part| matches!(part.trim(), "0" | "1" | "d" | "s")));
        if invalid {
            out.push(finding(subject, "DMARC syntax", Error, "DMARC contains a missing required tag or invalid tag value", "Receivers may ignore the policy or apply fallback handling.", "Use v=DMARC1 first, a valid p policy, and valid values for any optional tags you publish.", set.evidence()));
        }
        let policy = if inherited { values.get("sp").or_else(|| values.get("p")) } else { values.get("p") };
        if policy.is_some_and(|value| value == "none") {
            out.push(finding(subject, "DMARC enforcement", Warning, "Effective DMARC policy is monitoring-only", "DMARC requests no quarantine or rejection of failing messages.", "After reviewing reports and authenticating legitimate senders, move the effective policy to quarantine or reject.", set.evidence()));
        }
        if values.get("pct").and_then(|value| value.parse::<u8>().ok()).is_some_and(|percent| percent < 100) {
            out.push(finding(subject, "DMARC enforcement sampling", Warning, "DMARC enforcement is requested for less than all failing mail", "Some failing messages may receive weaker handling during rollout.", "Increase pct to 100 after validating legitimate mail; omission already defaults to 100.", set.evidence()));
        }
        if !inherited && values.get("sp").is_some_and(|value| value == "none") && values.get("p").is_some_and(|value| value != "none") {
            out.push(finding(subject, "DMARC subdomain policy", Warning, "Subdomain policy is weaker than the domain policy", "Unconfigured subdomains inherit monitoring-only handling.", "Strengthen sp or omit it to inherit p after checking subdomain mail streams.", set.evidence()));
        }
        for key in ["rua", "ruf"] {
            if values.get(key).is_some_and(|value| !value.split(',').all(|value: & str| {
    let value = value.trim();
    let uri = if let Some((uri, size)) = value.rsplit_once('!') {
        let digits = size.trim_end_matches(['k', 'm', 'g', 't']);
        if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) || size.len() > digits.len() + 1 { return false; }
        uri
    } else { value };
    valid_report_uri(uri, true)
})) {
                out.push(finding(subject, "DMARC reporting syntax", Error, &format!("DMARC {key} contains a malformed reporting destination"), "Requested reports may not be deliverable.", "Use comma-separated valid report URIs and valid optional size suffixes; reporting addresses are redacted.", set.evidence()));
            }
        }
        if !values.contains_key("rua") {
            out.push(finding(subject, "DMARC reporting", Recommendation, "No aggregate reporting destination is configured", "The optional aggregate reports would help detect misalignment and spoofing.", "Consider adding rua to a monitored report processor; external report authorization is not checked here.", set.evidence()));
        }
        if !invalid && parsed.duplicates.is_empty() && !out.iter().any(|item| matches!(item.status, Error | Warning)) {
            out.push(finding(subject, "DMARC effective policy", Pass, "DMARC has a syntactically valid enforcing policy", "Defaults are respected: sp inherits p, pct defaults to 100, and alignment defaults to relaxed.", "Monitor authentication alignment and reports; message-level enforcement was not tested.", set.evidence()));
        }
    }
    out

}
};
inlined_result
});
    if (hostname).trim_end_matches('.').to_ascii_lowercase() != domain {
        let set = collector
            .rrset(&format!("_dmarc.{hostname}"), RecordType::TXT)
            .await;
        if set.error.is_none()
            && !set.texts().iter().any(|text| {
                let (text, version): (&str, &str) = (text, "DMARC1");

                text.split(';')
                    .next()
                    .and_then(|part| part.trim().split_once('='))
                    .is_some_and(|(key, value)| {
                        key.trim().eq_ignore_ascii_case("v")
                            && value.trim().eq_ignore_ascii_case(version)
                    })
            })
        {
            out.extend({
let (subject, set, inherited,): (& str, & Rrset, bool,) = (hostname, &domain_set, true,);
let inlined_result: Vec < DnsObservation > = {
'inlined_dmarc_policy: {

    if let Some(item) = unavailable(subject, "DMARC", set) { break 'inlined_dmarc_policy vec![item]; }
    let policies = set.texts().into_iter().filter(|text| {
let (text, version,): (& str, & str,) = (text, "DMARC1",);

    text.split(';').next().and_then(|part| part.trim().split_once('=')).is_some_and(|(key, value)| key.trim().eq_ignore_ascii_case("v") && value.trim().eq_ignore_ascii_case(version))

}).collect::<Vec<_>>();
    if policies.is_empty() {
        break 'inlined_dmarc_policy vec![finding(subject, "DMARC", Recommendation, "No applicable DMARC policy was found", "Receivers have no domain-published DMARC handling policy.", "Publish DMARC after aligning SPF and DKIM; monitor reports before moving to quarantine or reject.", set.evidence())];
    }
    let mut out = Vec::new();
    if policies.len() > 1 {
        out.push(finding(subject, "DMARC policy count", Error, "Multiple DMARC policies are published", "Receivers cannot select a unique DMARC policy.", "Consolidate DMARC into one TXT record at the policy owner.", set.evidence()));
    }
    for policy in policies {
        let parsed = tags(&policy);
        let values = &parsed.values;
        if !parsed.duplicates.is_empty() {
            out.push(finding(subject, "DMARC duplicate tags", Error, "DMARC contains duplicate tags", "Duplicate tags make policy interpretation invalid or ambiguous.", "Keep each tag once in the DMARC record.", set.evidence()));
        }
        let valid_policy = |value: Option<&String>| value.is_some_and(|value| matches!(value.as_str(), "none" | "quarantine" | "reject"));
        let invalid = parsed.malformed || parsed.first != "v" || values.get("v").map(String::as_str) != Some("DMARC1") || !valid_policy(values.get("p"))
            || ["sp"].iter().any(|tag| values.contains_key(*tag) && !valid_policy(values.get(*tag)))
            || ["adkim", "aspf"].iter().any(|tag| values.get(*tag).is_some_and(|value| !matches!(value.as_str(), "r" | "s")))
            || values.get("pct").is_some_and(|value| value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) || !value.parse::<u8>().is_ok_and(|number| number <= 100))
            || values.get("ri").is_some_and(|value| value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) || value.parse::<u64>().is_err())
            || values.get("fo").is_some_and(|value| !value.split(':').all(|part| matches!(part.trim(), "0" | "1" | "d" | "s")));
        if invalid {
            out.push(finding(subject, "DMARC syntax", Error, "DMARC contains a missing required tag or invalid tag value", "Receivers may ignore the policy or apply fallback handling.", "Use v=DMARC1 first, a valid p policy, and valid values for any optional tags you publish.", set.evidence()));
        }
        let policy = if inherited { values.get("sp").or_else(|| values.get("p")) } else { values.get("p") };
        if policy.is_some_and(|value| value == "none") {
            out.push(finding(subject, "DMARC enforcement", Warning, "Effective DMARC policy is monitoring-only", "DMARC requests no quarantine or rejection of failing messages.", "After reviewing reports and authenticating legitimate senders, move the effective policy to quarantine or reject.", set.evidence()));
        }
        if values.get("pct").and_then(|value| value.parse::<u8>().ok()).is_some_and(|percent| percent < 100) {
            out.push(finding(subject, "DMARC enforcement sampling", Warning, "DMARC enforcement is requested for less than all failing mail", "Some failing messages may receive weaker handling during rollout.", "Increase pct to 100 after validating legitimate mail; omission already defaults to 100.", set.evidence()));
        }
        if !inherited && values.get("sp").is_some_and(|value| value == "none") && values.get("p").is_some_and(|value| value != "none") {
            out.push(finding(subject, "DMARC subdomain policy", Warning, "Subdomain policy is weaker than the domain policy", "Unconfigured subdomains inherit monitoring-only handling.", "Strengthen sp or omit it to inherit p after checking subdomain mail streams.", set.evidence()));
        }
        for key in ["rua", "ruf"] {
            if values.get(key).is_some_and(|value| !value.split(',').all(|value: & str| {
    let value = value.trim();
    let uri = if let Some((uri, size)) = value.rsplit_once('!') {
        let digits = size.trim_end_matches(['k', 'm', 'g', 't']);
        if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) || size.len() > digits.len() + 1 { return false; }
        uri
    } else { value };
    valid_report_uri(uri, true)
})) {
                out.push(finding(subject, "DMARC reporting syntax", Error, &format!("DMARC {key} contains a malformed reporting destination"), "Requested reports may not be deliverable.", "Use comma-separated valid report URIs and valid optional size suffixes; reporting addresses are redacted.", set.evidence()));
            }
        }
        if !values.contains_key("rua") {
            out.push(finding(subject, "DMARC reporting", Recommendation, "No aggregate reporting destination is configured", "The optional aggregate reports would help detect misalignment and spoofing.", "Consider adding rua to a monitored report processor; external report authorization is not checked here.", set.evidence()));
        }
        if !invalid && parsed.duplicates.is_empty() && !out.iter().any(|item| matches!(item.status, Error | Warning)) {
            out.push(finding(subject, "DMARC effective policy", Pass, "DMARC has a syntactically valid enforcing policy", "Defaults are respected: sp inherits p, pct defaults to 100, and alignment defaults to relaxed.", "Monitor authentication alignment and reports; message-level enforcement was not tested.", set.evidence()));
        }
    }
    out

}
};
inlined_result
});
        } else {
            out.extend({
let (subject, set, inherited,): (& str, & Rrset, bool,) = (hostname, &set, false,);
let inlined_result: Vec < DnsObservation > = {
'inlined_dmarc_policy: {

    if let Some(item) = unavailable(subject, "DMARC", set) { break 'inlined_dmarc_policy vec![item]; }
    let policies = set.texts().into_iter().filter(|text| {
let (text, version,): (& str, & str,) = (text, "DMARC1",);

    text.split(';').next().and_then(|part| part.trim().split_once('=')).is_some_and(|(key, value)| key.trim().eq_ignore_ascii_case("v") && value.trim().eq_ignore_ascii_case(version))

}).collect::<Vec<_>>();
    if policies.is_empty() {
        break 'inlined_dmarc_policy vec![finding(subject, "DMARC", Recommendation, "No applicable DMARC policy was found", "Receivers have no domain-published DMARC handling policy.", "Publish DMARC after aligning SPF and DKIM; monitor reports before moving to quarantine or reject.", set.evidence())];
    }
    let mut out = Vec::new();
    if policies.len() > 1 {
        out.push(finding(subject, "DMARC policy count", Error, "Multiple DMARC policies are published", "Receivers cannot select a unique DMARC policy.", "Consolidate DMARC into one TXT record at the policy owner.", set.evidence()));
    }
    for policy in policies {
        let parsed = tags(&policy);
        let values = &parsed.values;
        if !parsed.duplicates.is_empty() {
            out.push(finding(subject, "DMARC duplicate tags", Error, "DMARC contains duplicate tags", "Duplicate tags make policy interpretation invalid or ambiguous.", "Keep each tag once in the DMARC record.", set.evidence()));
        }
        let valid_policy = |value: Option<&String>| value.is_some_and(|value| matches!(value.as_str(), "none" | "quarantine" | "reject"));
        let invalid = parsed.malformed || parsed.first != "v" || values.get("v").map(String::as_str) != Some("DMARC1") || !valid_policy(values.get("p"))
            || ["sp"].iter().any(|tag| values.contains_key(*tag) && !valid_policy(values.get(*tag)))
            || ["adkim", "aspf"].iter().any(|tag| values.get(*tag).is_some_and(|value| !matches!(value.as_str(), "r" | "s")))
            || values.get("pct").is_some_and(|value| value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) || !value.parse::<u8>().is_ok_and(|number| number <= 100))
            || values.get("ri").is_some_and(|value| value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) || value.parse::<u64>().is_err())
            || values.get("fo").is_some_and(|value| !value.split(':').all(|part| matches!(part.trim(), "0" | "1" | "d" | "s")));
        if invalid {
            out.push(finding(subject, "DMARC syntax", Error, "DMARC contains a missing required tag or invalid tag value", "Receivers may ignore the policy or apply fallback handling.", "Use v=DMARC1 first, a valid p policy, and valid values for any optional tags you publish.", set.evidence()));
        }
        let policy = if inherited { values.get("sp").or_else(|| values.get("p")) } else { values.get("p") };
        if policy.is_some_and(|value| value == "none") {
            out.push(finding(subject, "DMARC enforcement", Warning, "Effective DMARC policy is monitoring-only", "DMARC requests no quarantine or rejection of failing messages.", "After reviewing reports and authenticating legitimate senders, move the effective policy to quarantine or reject.", set.evidence()));
        }
        if values.get("pct").and_then(|value| value.parse::<u8>().ok()).is_some_and(|percent| percent < 100) {
            out.push(finding(subject, "DMARC enforcement sampling", Warning, "DMARC enforcement is requested for less than all failing mail", "Some failing messages may receive weaker handling during rollout.", "Increase pct to 100 after validating legitimate mail; omission already defaults to 100.", set.evidence()));
        }
        if !inherited && values.get("sp").is_some_and(|value| value == "none") && values.get("p").is_some_and(|value| value != "none") {
            out.push(finding(subject, "DMARC subdomain policy", Warning, "Subdomain policy is weaker than the domain policy", "Unconfigured subdomains inherit monitoring-only handling.", "Strengthen sp or omit it to inherit p after checking subdomain mail streams.", set.evidence()));
        }
        for key in ["rua", "ruf"] {
            if values.get(key).is_some_and(|value| !value.split(',').all(|value: & str| {
    let value = value.trim();
    let uri = if let Some((uri, size)) = value.rsplit_once('!') {
        let digits = size.trim_end_matches(['k', 'm', 'g', 't']);
        if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) || size.len() > digits.len() + 1 { return false; }
        uri
    } else { value };
    valid_report_uri(uri, true)
})) {
                out.push(finding(subject, "DMARC reporting syntax", Error, &format!("DMARC {key} contains a malformed reporting destination"), "Requested reports may not be deliverable.", "Use comma-separated valid report URIs and valid optional size suffixes; reporting addresses are redacted.", set.evidence()));
            }
        }
        if !values.contains_key("rua") {
            out.push(finding(subject, "DMARC reporting", Recommendation, "No aggregate reporting destination is configured", "The optional aggregate reports would help detect misalignment and spoofing.", "Consider adding rua to a monitored report processor; external report authorization is not checked here.", set.evidence()));
        }
        if !invalid && parsed.duplicates.is_empty() && !out.iter().any(|item| matches!(item.status, Error | Warning)) {
            out.push(finding(subject, "DMARC effective policy", Pass, "DMARC has a syntactically valid enforcing policy", "Defaults are respected: sp inherits p, pct defaults to 100, and alignment defaults to relaxed.", "Monitor authentication alignment and reports; message-level enforcement was not tested.", set.evidence()));
        }
    }
    out

}
};
inlined_result
});
        }
    }
    out
}

fn valid_report_uri(value: &str, allow_http: bool) -> bool {
    let Ok(uri) = Url::parse(value.trim()) else {
        return false;
    };
    match uri.scheme() {
        "mailto" => {
            uri.path().split_once('@').is_some_and(|(local, domain)| {
                !local.is_empty() && normalize_ct_name(domain).is_some()
            }) && !uri.path().contains(char::is_whitespace)
        }
        "https" => uri.host_str().is_some(),
        "http" if allow_http => uri.host_str().is_some(),
        _ => false,
    }
}

pub(super) fn dkim(subject: &str, set: &Rrset) -> Vec<DnsObservation> {
    if let Some(item) = unavailable(subject, "DKIM", set) {
        return vec![item];
    }
    let texts = set.texts();
    if texts.is_empty() {
        return vec![finding(
            subject,
            "DKIM selector",
            Warning,
            "Supplied DKIM selector has no TXT record",
            "Messages signed with this selector cannot retrieve a verification key.",
            "Confirm the selector is active and publish its mail-provider key or alias.",
            set.evidence(),
        )];
    }
    let mut out = Vec::new();
    if texts.len() > 1 {
        out.push(finding(
            subject,
            "DKIM policy count",
            Error,
            "Multiple TXT key records exist at the supplied selector",
            "The selector does not identify a unique DKIM key record.",
            "Publish one key record per selector; keep split TXT strings within that record.",
            set.evidence(),
        ));
    }
    for text in texts {
        let parsed = tags(&text);
        let values = &parsed.values;
        if parsed.malformed
            || !parsed.duplicates.is_empty()
            || !values.contains_key("p")
            || values
                .get("v")
                .is_some_and(|value| value != "DKIM1" || parsed.first != "v")
        {
            out.push(finding(
                subject,
                "DKIM syntax",
                Error,
                "DKIM key record is malformed or contains duplicate tags",
                "Verifiers may discard the selector key.",
                "Publish one p tag and unique valid tags; optional v=DKIM1 must be first.",
                set.evidence(),
            ));
        }
        if values
            .get("t")
            .is_some_and(|value| value.split(':').any(|flag| flag.trim() == "y"))
        {
            out.push(finding(
                subject,
                "DKIM testing mode",
                Warning,
                "DKIM selector advertises testing mode",
                "This selector requests testing treatment of verification failures.",
                "Remove t=y after verifying production signing.",
                set.evidence(),
            ));
        }
        if values
            .get("h")
            .is_some_and(|value| !value.split(':').any(|hash| hash.trim() == "sha256"))
        {
            out.push(finding(
                subject,
                "DKIM hash policy",
                Warning,
                "DKIM key does not authorize SHA-256",
                "Modern DKIM signatures may not be verifiable with this key policy.",
                "Allow sha256 or omit h to use the valid default.",
                set.evidence(),
            ));
        }
        if values.get("s").is_some_and(|value| {
            !value
                .split(':')
                .any(|service| matches!(service.trim(), "*" | "email"))
        }) {
            out.push(finding(
                subject,
                "DKIM service policy",
                Warning,
                "DKIM key does not authorize email service",
                "Email verifiers ignore a key whose service restriction excludes email.",
                "Include email or * in s, or omit it for the default.",
                set.evidence(),
            ));
        }
        let Some(key) = values.get("p") else {
            continue;
        };
        let key = key
            .chars()
            .filter(|character| !character.is_ascii_whitespace())
            .collect::<String>();
        if key.is_empty() {
            out.push(finding(subject, "DKIM revocation", Warning, "DKIM selector is revoked", "Messages still signed with this selector will fail DKIM verification; revocation itself is valid.", "Stop signing with this selector and deploy a new selector if mail is still sent.", set.evidence()));
            continue;
        }
        let decoded = base64::engine::general_purpose::STANDARD.decode(&key);
        let kind = values.get("k").map(String::as_str).unwrap_or("rsa");
        let key_result = match (kind, decoded) {
            ("rsa", Ok(bytes)) => {
                let (bytes,): (&[u8],) = (&bytes,);
                'inlined_rsa_bits: {
                    use x509_parser::public_key::{PublicKey, RSAPublicKey};
                    let modulus_bits = |key: &RSAPublicKey<'_>| {
                        if key.modulus.first().is_none_or(|byte| byte & 128 != 0)
                            || !key
                                .try_exponent()
                                .is_ok_and(|exponent| exponent >= 3 && exponent % 2 == 1)
                        {
                            return Err("Invalid RSA integer");
                        }
                        let significant = key
                            .modulus
                            .iter()
                            .position(|byte| *byte != 0)
                            .ok_or("Zero RSA modulus")?;
                        if key.modulus.last().is_none_or(|byte| byte % 2 == 0) {
                            return Err("Even RSA modulus");
                        }
                        Ok((key.modulus.len() - significant) * 8
                            - key.modulus[significant].leading_zeros() as usize)
                    };
                    if let Ok((remaining, key)) = RSAPublicKey::from_der(bytes) {
                        if remaining.is_empty() {
                            break 'inlined_rsa_bits modulus_bits(&key);
                        }
                    }
                    if let Ok((remaining, info)) =
                        x509_parser::x509::SubjectPublicKeyInfo::from_der(bytes)
                        && remaining.is_empty()
                        && let Ok(PublicKey::RSA(key)) = info.parsed()
                    {
                        break 'inlined_rsa_bits modulus_bits(&key);
                    }
                    Err("Invalid RSA public key DER")
                }
            }
            ("ed25519", Ok(bytes)) if bytes.len() == 32 => Ok(256),
            ("rsa" | "ed25519", _) => Err("Invalid base64 or key structure"),
            _ => {
                out.push(finding(
                    subject,
                    "DKIM key type",
                    Inconclusive,
                    "DKIM key type is not supported by this assessment",
                    "Key structure and strength were not evaluated.",
                    "Confirm verifier support for the published key type.",
                    set.evidence(),
                ));
                continue;
            }
        };
        match key_result {
            Err(_) => out.push(finding(subject, "DKIM key encoding", Error, "DKIM public key cannot be parsed", "The selector does not provide a usable key for its advertised algorithm.", "Replace p with the provider's complete base64 public key, preserving all TXT chunks.", set.evidence())),
            Ok(bits) if kind == "rsa" && bits < 2048 => out.push(finding(subject, "DKIM RSA strength", if bits < 1024 { Error } else { Warning }, &format!("DKIM RSA modulus is {bits} bits"), "Short RSA keys provide weaker protection; keys below 1024 bits are not acceptable for modern DKIM.", "Rotate to an RSA key of at least 2048 bits, using a new selector.", set.evidence())),
            Ok(bits) => out.push(finding(subject, "DKIM key structure", Pass, &format!("DKIM {kind} key parsed ({bits} bits)"), "Key structure and size were checked; signed-message validation was not performed.", "Rotate keys periodically and verify alignment on actual messages.", set.evidence())),
        }
    }
    out
}

pub(super) async fn transport(domain: &str, collector: &Collector<'_>) -> Vec<DnsObservation> {
    let mut out = Vec::new();
    for (prefix, version, check) in [
        ("_mta-sts", "STSv1", "MTA-STS advertisement (DNS only)"),
        (
            "_smtp._tls",
            "TLSRPTv1",
            "TLS reporting advertisement (DNS only)",
        ),
    ] {
        let subject = format!("{prefix}.{domain}");
        let set = collector.rrset(&subject, RecordType::TXT).await;
        if let Some(item) = unavailable(&subject, check, &set) {
            out.push(item);
            continue;
        }
        let policies = set
            .texts()
            .into_iter()
            .filter(|text| {
                let (text, version): (&str, &str) = (text, version);

                text.split(';')
                    .next()
                    .and_then(|part| part.trim().split_once('='))
                    .is_some_and(|(key, value)| {
                        key.trim().eq_ignore_ascii_case("v")
                            && value.trim().eq_ignore_ascii_case(version)
                    })
            })
            .collect::<Vec<_>>();
        if policies.is_empty() {
            out.push(finding(&subject, check, Recommendation, "No mail transport policy advertisement found", "For mail-receiving domains, this DNS advertisement can enable transport policy or failure reporting.", "If the domain receives mail, deploy MTA-STS with its HTTPS policy and TLS reporting with a monitored destination.", set.evidence()));
            continue;
        }
        if policies.len() > 1 {
            out.push(finding(
                &subject,
                check,
                Error,
                "Multiple mail transport policy advertisements found",
                "Receivers cannot select a unique DNS advertisement.",
                "Publish exactly one versioned TXT advertisement at this owner.",
                set.evidence(),
            ));
        }
        for policy in policies {
            let parsed = tags(&policy);
            let invalid = parsed.malformed
                || !parsed.duplicates.is_empty()
                || parsed.first != "v"
                || parsed.values.get("v").map(String::as_str) != Some(version)
                || if version == "STSv1" {
                    !parsed.values.get("id").is_some_and(|id| {
                        !id.is_empty()
                            && id.len() <= 32
                            && id.bytes().all(|byte| byte.is_ascii_alphanumeric())
                    })
                } else {
                    !parsed.values.get("rua").is_some_and(|value| {
                        !value.is_empty()
                            && value.split(',').all(|uri| valid_report_uri(uri, false))
                    })
                };
            out.push(finding(&subject, check, if invalid { Error } else { Pass }, if invalid { "Malformed mail transport policy advertisement" } else { "Mail transport DNS advertisement is syntactically valid" }, "DNS-only inspection does not verify HTTPS policy availability, SMTP TLS enforcement or report delivery.", if version == "STSv1" { "Use v=STSv1 and a 1–32 character alphanumeric id; separately verify the HTTPS policy and SMTP configuration." } else { "Use v=TLSRPTv1 and valid mailto or https rua destinations; separately verify reporting delivery." }, set.evidence()));
        }
    }
    out
}
