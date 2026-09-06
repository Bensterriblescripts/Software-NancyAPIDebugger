use super::*;
use DnsObservationStatus::*;

struct SpfPolicy {
    findings: Vec<DnsObservation>,
    dependencies: Vec<String>,
    lookup_terms: usize,
    dynamic: bool,
}

pub(super) async fn spf(domain: &str, collector: &Collector<'_>) -> Vec<DnsObservation> {
    let mut out = Vec::new();
    let mut pending = vec![(domain.to_owned(), Vec::<String>::new())];
    let mut expanded = 0;
    let mut lookup_terms = 0;
    let mut incomplete = false;
    while let Some((owner, mut ancestors)) = pending.pop() {
        if collector.cancel.is_cancelled() {
            break;
        }
        if ancestors.contains(&owner) {
            out.push(finding(&owner, "SPF dependency cycle", Warning, "An include/redirect dependency cycle exists", "Messages that reach this cycle can exhaust SPF processing limits and return permerror.", "Remove the recursive include or redirect and keep authorization dependencies acyclic.", vec![format!("Dependency path: {} → {owner}", ancestors.join(" → "))]));
            continue;
        }
        if ancestors.len() >= DEPTH_LIMIT || expanded >= QUERY_LIMIT {
            out.push(finding(
                &owner,
                "SPF dependency coverage",
                Inconclusive,
                "SPF dependency depth or expansion limit reached",
                "The complete SPF dependency graph was not assessed.",
                "Simplify dependencies or review the remaining branches manually.",
                Vec::new(),
            ));
            incomplete = true;
            if expanded >= QUERY_LIMIT {
                break;
            }
            continue;
        }
        expanded += 1;
        let set = collector.rrset(&owner, RecordType::TXT).await;
        if let Some(item) = unavailable(&owner, "SPF", &set) {
            out.push(item);
            incomplete = true;
            continue;
        }
        let policies = set
            .texts()
            .into_iter()
            .filter(|text| {
                text.split_ascii_whitespace()
                    .next()
                    .is_some_and(|word| word.eq_ignore_ascii_case("v=spf1"))
            })
            .collect::<Vec<_>>();
        if policies.is_empty() {
            let dependency = !ancestors.is_empty();
            out.push(finding(&owner, "SPF policy", if dependency { Error } else { Recommendation }, if dependency { "SPF dependency has no SPF policy" } else { "No SPF policy is published" }, if dependency { "SPF processing returns an error when this include/redirect is reached." } else { "Senders are not authorized or excluded by a domain SPF policy." }, if dependency { "Correct the include/redirect target or publish its missing policy." } else { "Publish one SPF policy covering legitimate senders, or v=spf1 -all if the domain never sends mail." }, set.evidence()));
            continue;
        }
        if policies.len() > 1 {
            out.push(finding(
                &owner,
                "SPF policy count",
                Error,
                "Multiple SPF policies are published",
                "SPF evaluation returns permerror for this domain.",
                "Merge authorizations into one v=spf1 TXT record.",
                set.evidence(),
            ));
        }
        ancestors.push(owner.clone());
        for text in policies {
            let parsed = {
                let (owner, text, set): (&str, &str, &Rrset) = (&owner, &text, &set);
                let inlined_result: SpfPolicy = {
                    let mut result = SpfPolicy {
                        findings: Vec::new(),
                        dependencies: Vec::new(),
                        lookup_terms: 0,
                        dynamic: false,
                    };
                    let mut modifiers = HashSet::new();
                    let mut all = false;
                    let mut redirect = None;
                    let mut reachable = true;
                    let mut syntax = !text.is_ascii()
                        || text.starts_with(char::is_whitespace)
                        || text.contains(['\t', '\r', '\n']);
                    for term in text.split_ascii_whitespace().skip(1) {
                        let (qualifier, body) = if term.starts_with(['+', '-', '~', '?']) {
                            (term.as_bytes()[0], &term[1..])
                        } else {
                            (b'+', term)
                        };
                        if let Some((name, value)) = body.split_once('=')
                            && !name.contains([':', '/', '%'])
                        {
                            let name = name.to_ascii_lowercase();
                            if body != term
                                || name.is_empty()
                                || !name.as_bytes()[0].is_ascii_alphabetic()
                                || !name.bytes().all(|byte| {
                                    byte.is_ascii_alphanumeric()
                                        || matches!(byte, b'_' | b'.' | b'-')
                                })
                                || !({
                                    let (value,): (&str,) = (value,);
                                    {
                                        'inlined_macro_syntax: {
                                            let mut chars = value.chars().peekable();
                                            while let Some(character) = chars.next() {
                                                if !character.is_ascii_graphic() {
                                                    break 'inlined_macro_syntax false;
                                                }
                                                if character != '%' {
                                                    continue;
                                                }
                                                match chars.next() {
                                                    Some('%' | '_' | '-') => (),
                                                    Some('{') => {
                                                        let Some(letter) = chars.next() else {
                                                            break 'inlined_macro_syntax false;
                                                        };
                                                        if !"slodipvhSLODIPVH".contains(letter) {
                                                            break 'inlined_macro_syntax false;
                                                        }
                                                        while chars.peek().is_some_and(
                                                            |character| character.is_ascii_digit(),
                                                        ) {
                                                            chars.next();
                                                        }
                                                        if chars.peek().is_some_and(|character| {
                                                            matches!(character, 'r' | 'R')
                                                        }) {
                                                            chars.next();
                                                        }
                                                        while chars.peek().is_some_and(
                                                            |character| {
                                                                ".-+,/_=".contains(*character)
                                                            },
                                                        ) {
                                                            chars.next();
                                                        }
                                                        if chars.next() != Some('}') {
                                                            break 'inlined_macro_syntax false;
                                                        }
                                                    }
                                                    _ => break 'inlined_macro_syntax false,
                                                }
                                            }
                                            true
                                        }
                                    }
                                })
                            {
                                syntax = true;
                            }
                            if matches!(name.as_str(), "redirect" | "exp") {
                                if !modifiers.insert(name.clone()) || value.is_empty() {
                                    syntax = true;
                                }
                                if name == "redirect" {
                                    redirect = Some(value.to_owned());
                                }
                            }
                            continue;
                        }
                        let split = body.find([':', '/']).unwrap_or(body.len());
                        let mechanism = body[..split].to_ascii_lowercase();
                        let argument = &body[split..];
                        if !reachable {
                            result.findings.push(finding(owner, "SPF unreachable terms", Warning, "SPF mechanisms appear after all", "The all mechanism always matches, so later mechanisms cannot authorize senders.", "Move required mechanisms before the final all and remove unreachable terms.", set.evidence()));
                        }
                        match mechanism.as_str() {
            "all" => {
                if !argument.is_empty() { syntax = true; }
                if reachable && qualifier == b'+' {
                    result.findings.push(finding(owner, "SPF permissive authorization", Warning, "SPF +all authorizes every sender", "Any IP can obtain SPF pass for this policy if this term is reached.", "Replace +all with an appropriate restrictive terminal policy after listing legitimate senders.", set.evidence()));
                } else if reachable && qualifier == b'?' {
                    result.findings.push(finding(owner, "SPF neutral fallback", Recommendation, "SPF ends in neutral authorization", "Unlisted senders receive no positive or negative SPF assertion.", "Consider ~all during rollout and -all after validating legitimate senders.", set.evidence()));
                }
                all = true;
                reachable = false;
            }
            "ip4" | "ip6" => {
                let valid = argument.strip_prefix(':').is_some_and(|value| {
                    let (address, prefix) = value.split_once('/').map_or((value, None), |(ip, cidr)| (ip, Some(cidr)));
                    let family = mechanism == "ip4";
                    address.parse::<IpAddr>().is_ok_and(|ip| ip.is_ipv4() == family) && prefix.is_none_or(|prefix| {
let (value, max,): (& str, u8,) = (prefix, if family { 32 } else { 128 },);

    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) && value.parse::<u8>().is_ok_and(|prefix| prefix <= max)

})
                });
                if !valid { syntax = true; }
                if reachable && qualifier == b'+' && argument.ends_with("/0") && valid {
                    result.findings.push(finding(owner, "SPF permissive CIDR", Warning, "SPF authorizes an entire IP address family", "An ip4 or ip6 /0 mechanism permits every sender in that family.", "Replace /0 with only the networks used by authorized mail senders.", set.evidence()));
                }
            }
            "a" | "mx" => {
                if !({
let (argument,): (& str,) = (argument,);
{
'inlined_address_mechanism: {

    let mut braces = false;
    let mut cidr_start = argument.len();
    for (index, character) in argument.char_indices() {
        if character == '{' { braces = true; }
        if character == '}' { braces = false; }
        if character == '/' && !braces { cidr_start = index; break; }
    }
    let domain = &argument[..cidr_start];
    if !domain.is_empty() && !domain.strip_prefix(':').is_some_and(|value: & str| {
    if value.is_empty() || !({
let (value,): (& str,) = (value,);
{
'inlined_macro_syntax: {

    let mut chars = value.chars().peekable();
    while let Some(character) = chars.next() {
        if !character.is_ascii_graphic() { break 'inlined_macro_syntax false; }
        if character != '%' { continue; }
        match chars.next() {
            Some('%' | '_' | '-') => (),
            Some('{') => {
                let Some(letter) = chars.next() else { break 'inlined_macro_syntax false; };
                if !"slodipvhSLODIPVH".contains(letter) { break 'inlined_macro_syntax false; }
                while chars.peek().is_some_and(|character| character.is_ascii_digit()) { chars.next(); }
                if chars.peek().is_some_and(|character| matches!(character, 'r' | 'R')) { chars.next(); }
                while chars.peek().is_some_and(|character| ".-+,/_=".contains(*character)) { chars.next(); }
                if chars.next() != Some('}') { break 'inlined_macro_syntax false; }
            }
            _ => break 'inlined_macro_syntax false,
        }
    }
    true

}
}

}) { return false; }
    if value.contains('%') { return true; }
    let value = value.trim_end_matches('.');
    value.len() <= 253 && value.contains('.') && value.split('.').all(|label| {
        !label.is_empty() && label.len() <= 63 && label.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    }) && value.rsplit('.').next().is_some_and(|label| {
        label.bytes().any(|byte| byte.is_ascii_alphabetic()) && !label.contains('_') && !label.starts_with('-') && !label.ends_with('-')
    })
}) { break 'inlined_address_mechanism false; }
    let cidr = &argument[cidr_start..];
    if cidr.is_empty() { break 'inlined_address_mechanism true; }
    if let Some(ipv6) = cidr.strip_prefix("//") { break 'inlined_address_mechanism ({
let (value, max,): (& str, u8,) = (ipv6, 128,);

    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) && value.parse::<u8>().is_ok_and(|prefix| prefix <= max)

}); }
    let Some(cidr) = cidr.strip_prefix('/') else { break 'inlined_address_mechanism false; };
    if let Some((ipv4, ipv6)) = cidr.split_once("//") { ({
let (value, max,): (& str, u8,) = (ipv4, 32,);

    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) && value.parse::<u8>().is_ok_and(|prefix| prefix <= max)

}) && {
let (value, max,): (& str, u8,) = (ipv6, 128,);

    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) && value.parse::<u8>().is_ok_and(|prefix| prefix <= max)

} }
    else { {
let (value, max,): (& str, u8,) = (cidr, 32,);

    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) && value.parse::<u8>().is_ok_and(|prefix| prefix <= max)

} }

}
}

}) { syntax = true; }
                if reachable { result.lookup_terms += 1; }
            }
            "ptr" => {
                if !argument.is_empty() && !argument.strip_prefix(':').is_some_and(|value: & str| {
    if value.is_empty() || !({
let (value,): (& str,) = (value,);
{
'inlined_macro_syntax: {

    let mut chars = value.chars().peekable();
    while let Some(character) = chars.next() {
        if !character.is_ascii_graphic() { break 'inlined_macro_syntax false; }
        if character != '%' { continue; }
        match chars.next() {
            Some('%' | '_' | '-') => (),
            Some('{') => {
                let Some(letter) = chars.next() else { break 'inlined_macro_syntax false; };
                if !"slodipvhSLODIPVH".contains(letter) { break 'inlined_macro_syntax false; }
                while chars.peek().is_some_and(|character| character.is_ascii_digit()) { chars.next(); }
                if chars.peek().is_some_and(|character| matches!(character, 'r' | 'R')) { chars.next(); }
                while chars.peek().is_some_and(|character| ".-+,/_=".contains(*character)) { chars.next(); }
                if chars.next() != Some('}') { break 'inlined_macro_syntax false; }
            }
            _ => break 'inlined_macro_syntax false,
        }
    }
    true

}
}

}) { return false; }
    if value.contains('%') { return true; }
    let value = value.trim_end_matches('.');
    value.len() <= 253 && value.contains('.') && value.split('.').all(|label| {
        !label.is_empty() && label.len() <= 63 && label.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    }) && value.rsplit('.').next().is_some_and(|label| {
        label.bytes().any(|byte| byte.is_ascii_alphabetic()) && !label.contains('_') && !label.starts_with('-') && !label.ends_with('-')
    })
}) { syntax = true; }
                if reachable { result.lookup_terms += 1; }
                result.findings.push(finding(owner, "SPF ptr mechanism", Recommendation, "SPF uses the discouraged ptr mechanism", "Reverse-DNS authorization is slow, fragile and difficult to maintain.", "Replace ptr with explicit provider includes, a or IP network mechanisms.", set.evidence()));
            }
            "include" | "exists" => {
                if let Some(target) = argument.strip_prefix(':').filter(|target| {
let (value,): (& str,) = (target,);
{
'inlined_valid_domain_spec: {

    if value.is_empty() || !({
let (value,): (& str,) = (value,);
{
'inlined_macro_syntax: {

    let mut chars = value.chars().peekable();
    while let Some(character) = chars.next() {
        if !character.is_ascii_graphic() { break 'inlined_macro_syntax false; }
        if character != '%' { continue; }
        match chars.next() {
            Some('%' | '_' | '-') => (),
            Some('{') => {
                let Some(letter) = chars.next() else { break 'inlined_macro_syntax false; };
                if !"slodipvhSLODIPVH".contains(letter) { break 'inlined_macro_syntax false; }
                while chars.peek().is_some_and(|character| character.is_ascii_digit()) { chars.next(); }
                if chars.peek().is_some_and(|character| matches!(character, 'r' | 'R')) { chars.next(); }
                while chars.peek().is_some_and(|character| ".-+,/_=".contains(*character)) { chars.next(); }
                if chars.next() != Some('}') { break 'inlined_macro_syntax false; }
            }
            _ => break 'inlined_macro_syntax false,
        }
    }
    true

}
}

}) { break 'inlined_valid_domain_spec false; }
    if value.contains('%') { break 'inlined_valid_domain_spec true; }
    let value = value.trim_end_matches('.');
    value.len() <= 253 && value.contains('.') && value.split('.').all(|label| {
        !label.is_empty() && label.len() <= 63 && label.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    }) && value.rsplit('.').next().is_some_and(|label| {
        label.bytes().any(|byte| byte.is_ascii_alphabetic()) && !label.contains('_') && !label.starts_with('-') && !label.ends_with('-')
    })

}
}

}) {
                    if reachable {
                        result.lookup_terms += 1;
                        if mechanism == "include" {
                            if target.contains('%') { result.dynamic = true; }
                            else { result.dependencies.push((target).trim_end_matches('.').to_ascii_lowercase()); }
                        }
                    }
                } else { syntax = true; }
            }
            _ => syntax = true,
        }
                    }
                    if let Some(target) = redirect {
                        if !({
                            let (value,): (&str,) = (&target,);
                            {
                                'inlined_valid_domain_spec: {
                                    if value.is_empty()
                                        || !({
                                            let (value,): (&str,) = (value,);
                                            {
                                                'inlined_macro_syntax: {
                                                    let mut chars = value.chars().peekable();
                                                    while let Some(character) = chars.next() {
                                                        if !character.is_ascii_graphic() {
                                                            break 'inlined_macro_syntax false;
                                                        }
                                                        if character != '%' {
                                                            continue;
                                                        }
                                                        match chars.next() {
                                                            Some('%' | '_' | '-') => (),
                                                            Some('{') => {
                                                                let Some(letter) = chars.next()
                                                                else {
                                                                    break 'inlined_macro_syntax false;
                                                                };
                                                                if !"slodipvhSLODIPVH"
                                                                    .contains(letter)
                                                                {
                                                                    break 'inlined_macro_syntax false;
                                                                }
                                                                while chars.peek().is_some_and(
                                                                    |character| {
                                                                        character.is_ascii_digit()
                                                                    },
                                                                ) {
                                                                    chars.next();
                                                                }
                                                                if chars.peek().is_some_and(
                                                                    |character| {
                                                                        matches!(
                                                                            character,
                                                                            'r' | 'R'
                                                                        )
                                                                    },
                                                                ) {
                                                                    chars.next();
                                                                }
                                                                while chars.peek().is_some_and(
                                                                    |character| {
                                                                        ".-+,/_="
                                                                            .contains(*character)
                                                                    },
                                                                ) {
                                                                    chars.next();
                                                                }
                                                                if chars.next() != Some('}') {
                                                                    break 'inlined_macro_syntax false;
                                                                }
                                                            }
                                                            _ => break 'inlined_macro_syntax false,
                                                        }
                                                    }
                                                    true
                                                }
                                            }
                                        })
                                    {
                                        break 'inlined_valid_domain_spec false;
                                    }
                                    if value.contains('%') {
                                        break 'inlined_valid_domain_spec true;
                                    }
                                    let value = value.trim_end_matches('.');
                                    value.len() <= 253
                                        && value.contains('.')
                                        && value.split('.').all(|label| {
                                            !label.is_empty()
                                                && label.len() <= 63
                                                && label.bytes().all(|byte| {
                                                    byte.is_ascii_alphanumeric()
                                                        || matches!(byte, b'-' | b'_')
                                                })
                                        })
                                        && value.rsplit('.').next().is_some_and(|label| {
                                            label.bytes().any(|byte| byte.is_ascii_alphabetic())
                                                && !label.contains('_')
                                                && !label.starts_with('-')
                                                && !label.ends_with('-')
                                        })
                                }
                            }
                        }) {
                            syntax = true;
                        }
                        if all {
                            result.findings.push(finding(owner, "SPF unreachable redirect", Warning, "SPF redirect is ignored because all is present", "SPF never evaluates redirect when an all mechanism exists, regardless of modifier placement.", "Remove all to delegate via redirect, or remove the unused redirect.", set.evidence()));
                        } else {
                            result.lookup_terms += 1;
                            if target.contains('%') {
                                result.dynamic = true;
                            } else if {
                                let (value,): (&str,) = (&target,);
                                {
                                    'inlined_valid_domain_spec: {
                                        if value.is_empty()
                                            || !({
                                                let (value,): (&str,) = (value,);
                                                {
                                                    'inlined_macro_syntax: {
                                                        let mut chars = value.chars().peekable();
                                                        while let Some(character) = chars.next() {
                                                            if !character.is_ascii_graphic() {
                                                                break 'inlined_macro_syntax false;
                                                            }
                                                            if character != '%' {
                                                                continue;
                                                            }
                                                            match chars.next() {
            Some('%' | '_' | '-') => (),
            Some('{') => {
                let Some(letter) = chars.next() else { break 'inlined_macro_syntax false; };
                if !"slodipvhSLODIPVH".contains(letter) { break 'inlined_macro_syntax false; }
                while chars.peek().is_some_and(|character| character.is_ascii_digit()) { chars.next(); }
                if chars.peek().is_some_and(|character| matches!(character, 'r' | 'R')) { chars.next(); }
                while chars.peek().is_some_and(|character| ".-+,/_=".contains(*character)) { chars.next(); }
                if chars.next() != Some('}') { break 'inlined_macro_syntax false; }
            }
            _ => break 'inlined_macro_syntax false,
        }
                                                        }
                                                        true
                                                    }
                                                }
                                            })
                                        {
                                            break 'inlined_valid_domain_spec false;
                                        }
                                        if value.contains('%') {
                                            break 'inlined_valid_domain_spec true;
                                        }
                                        let value = value.trim_end_matches('.');
                                        value.len() <= 253
                                            && value.contains('.')
                                            && value.split('.').all(|label| {
                                                !label.is_empty()
                                                    && label.len() <= 63
                                                    && label.bytes().all(|byte| {
                                                        byte.is_ascii_alphanumeric()
                                                            || matches!(byte, b'-' | b'_')
                                                    })
                                            })
                                            && value.rsplit('.').next().is_some_and(|label| {
                                                label.bytes().any(|byte| byte.is_ascii_alphabetic())
                                                    && !label.contains('_')
                                                    && !label.starts_with('-')
                                                    && !label.ends_with('-')
                                            })
                                    }
                                }
                            } {
                                result
                                    .dependencies
                                    .push((&target).trim_end_matches('.').to_ascii_lowercase());
                            }
                        }
                    } else if !all {
                        result.findings.push(finding(owner, "SPF fallback", Recommendation, "SPF has no explicit all or redirect fallback", "Unmatched senders receive the valid default neutral result.", "Consider an explicit restrictive all after verifying every legitimate sender.", set.evidence()));
                    }
                    if syntax {
                        result.findings.push(finding(owner, "SPF syntax", Error, "SPF contains malformed mechanisms, modifiers or CIDRs", "Invalid SPF syntax can produce permerror instead of authentication.", "Correct mechanism names, required domain/IP arguments, unique redirect/exp modifiers and IPv4/IPv6 prefix lengths.", set.evidence()));
                    }
                    if result.dynamic {
                        result.findings.push(finding(owner, "SPF macro dependencies", Inconclusive, "SPF dependencies require message-dependent macro expansion", "Macro include/redirect targets cannot be determined without a sender identity.", "Evaluate these dependencies using representative sender IPs and identities.", set.evidence()));
                    }
                    if result.findings.is_empty() {
                        result.findings.push(finding(owner, "SPF local syntax", Pass, "SPF local policy passed bounded syntax and authorization checks", "This is a static policy check, not a message-level SPF result.", "Keep sender authorization current and check changes against runtime processing limits.", set.evidence()));
                    }
                    result
                };
                inlined_result
            };
            lookup_terms += parsed.lookup_terms;
            incomplete |= parsed.dynamic;
            out.extend(parsed.findings);
            pending.extend(
                parsed
                    .dependencies
                    .into_iter()
                    .map(|dependency| (dependency, ancestors.clone())),
            );
        }
    }
    incomplete |= collector.cancel.is_cancelled();
    if lookup_terms > 10 {
        out.push(finding(domain, "SPF lookup risk estimate", Warning, "Potential SPF DNS-lookup term count exceeds 10", "This is a static upper-bound risk, not a confirmed runtime violation; actual processing stops at matching mechanisms.", "Reduce reachable include, redirect, a, mx, exists and ptr terms; evaluate representative senders with an SPF evaluator.", vec![format!("Expanded lookup-causing terms: {lookup_terms}; repeated dependencies counted per path; macros and message-dependent address expansion are not evaluated") ]));
    }
    out.push(finding(domain, "SPF processing scope", if incomplete { Inconclusive } else { Informational }, if incomplete { "SPF dependency coverage is incomplete" } else { "SPF static dependency inspection completed" }, "No sender IP or message was supplied; void lookups, MX/PTR address limits and actual ten-lookup execution paths were not validated.", "Validate representative sender IPs and MAIL FROM identities with a standards-compliant SPF evaluator.", vec![format!("Dependency expansions: {expanded}; static lookup-term estimate: {lookup_terms}")]));
    out
}

pub(super) async fn routing(domain: &str, collector: &Collector<'_>) -> Vec<DnsObservation> {
    let set = collector.rrset(domain, RecordType::MX).await;
    if let Some(item) = unavailable(domain, "Mail routing", &set) {
        return vec![item];
    }
    let mut out = Vec::new();
    let entries = set
        .records
        .iter()
        .filter_map(|record| {
            if let RData::MX(mx) = &record.data {
                Some((
                    mx.preference,
                    (&mx.exchange.to_string())
                        .trim_end_matches('.')
                        .to_ascii_lowercase(),
                ))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    let nulls = entries
        .iter()
        .filter(|(_, target)| target.is_empty())
        .count();
    if nulls > 0 {
        if entries.len() != 1 || entries[0].0 != 0 {
            out.push(finding(domain, "Null MX", Error, "Null MX is combined with another MX or has nonzero preference", "Null MX must be the sole MX with preference zero; this combination gives contradictory routing instructions.", "Publish only MX 0 . for a non-receiving domain, or remove Null MX and publish real mail exchangers.", set.evidence()));
        } else {
            out.push(finding(domain, "Null MX", Pass, "Valid Null MX explicitly disables inbound mail", "SMTP senders are instructed not to deliver mail to this domain.", "If the domain also never sends mail, consider SPF -all and DMARC reject; Null MX alone does not prevent spoofing.", set.evidence()));
            out.push(finding(domain, "Non-mail-domain hardening", Recommendation, "Review outbound authentication for this Null MX domain", "Declining inbound mail does not stop forged outbound identities.", "If no service sends mail using this domain, publish v=spf1 -all and DMARC p=reject; retain legitimate outbound authorization otherwise.", set.evidence()));
        }
    }
    if entries.is_empty() {
        let (a, aaaa) = collector.address_sets(domain).await;
        let addresses = a
            .addresses()
            .into_iter()
            .chain(aaaa.addresses())
            .collect::<Vec<_>>();
        if !addresses.is_empty() {
            out.push(finding(domain, "Implicit MX", Pass, "No MX record; valid implicit address fallback exists", "SMTP may deliver to the domain's A/AAAA addresses; missing explicit MX alone is not an error.", "If this domain should never receive mail, publish a sole MX 0 . to disable fallback.", set.evidence()));
            out.extend(destination_findings(domain, "Implicit MX", &a, &aaaa));
        } else if a.error.is_none() && aaaa.error.is_none() {
            out.push(finding(domain, "Mail routing", Recommendation, "No explicit or implicit mail destination was found", "This domain cannot receive mail through the observed DNS records.", "If receiving mail, publish valid MX destinations; otherwise explicitly declare a non-receiving domain with MX 0 .", set.evidence()));
        } else {
            for set in [&a, &aaaa] {
                if let Some(item) = unavailable(domain, "Implicit MX", set) {
                    out.push(item);
                }
            }
        }
    }
    let mut seen = HashSet::new();
    for (_, target) in entries {
        if target.is_empty() || !seen.insert(target.clone()) || collector.cancel.is_cancelled() {
            continue;
        }
        let (a, aaaa) = collector.address_sets(&target).await;
        if !a.aliases.is_empty() || !aaaa.aliases.is_empty() {
            out.push(finding(
                &target,
                "MX target alias",
                Error,
                "MX target is a CNAME alias",
                "SMTP MX destinations must be canonical hosts, not aliases.",
                "Point the MX record directly at a host with A/AAAA records.",
                a.evidence().into_iter().chain(aaaa.evidence()).collect(),
            ));
        }
        out.extend(destination_findings(&target, "MX destination", &a, &aaaa));
    }
    out
}

pub(super) fn destination_findings(
    subject: &str,
    check: &str,
    a: &Rrset,
    aaaa: &Rrset,
) -> Vec<DnsObservation> {
    let mut out = Vec::new();
    let addresses = a
        .addresses()
        .into_iter()
        .chain(aaaa.addresses())
        .collect::<Vec<_>>();
    if addresses.is_empty() && a.error.is_none() && aaaa.error.is_none() {
        out.push(finding(
            subject,
            check,
            Error,
            "Destination has no A or AAAA addresses",
            "This advertised host cannot be reached using the observed DNS destinations.",
            "Correct the target name and publish its address records.",
            a.evidence().into_iter().chain(aaaa.evidence()).collect(),
        ));
    }
    for set in [a, aaaa] {
        if let Some(item) = unavailable(subject, check, set) {
            out.push(item);
        }
    }
    let non_public = addresses
        .iter()
        .filter_map(|ip| non_public_reason(*ip).map(|reason| format!("{ip}: {reason}")))
        .collect::<Vec<_>>();
    if !non_public.is_empty() {
        out.push(finding(subject, check, Warning, "Destination includes non-public addresses", "Public clients may be unable to reach some or all advertised destinations; split-horizon DNS may be intentional.", "Publish publicly reachable addresses for public services or confirm the private DNS view is intentional.", non_public));
    }
    if !addresses.is_empty() && out.is_empty() {
        out.push(finding(
            subject,
            check,
            Pass,
            "Public address destinations were resolved",
            "Address publication was checked; service availability is assessed separately.",
            "Keep destination records synchronized with the service.",
            addresses.iter().map(ToString::to_string).collect(),
        ));
    }
    out
}
