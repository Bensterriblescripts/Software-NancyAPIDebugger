use super::*;
use DnsObservationStatus::*;
use sha2::Digest;

pub(super) async fn resolution(hostname: &str, collector: &Collector<'_>) -> Vec<DnsObservation> {
    let (a, aaaa) = collector.address_sets(hostname).await;
    let mut out = mail::destination_findings(hostname, "Resolution", &a, &aaaa);
    if (a.nxdomain || aaaa.nxdomain) && a.addresses().is_empty() && aaaa.addresses().is_empty() {
        out.push(finding(
            hostname,
            "Resolution existence",
            Error,
            if a.aliases.is_empty() && aaaa.aliases.is_empty() {
                "Target returned NXDOMAIN"
            } else {
                "CNAME destination returned NXDOMAIN"
            },
            "The resolver reported that the target or an alias destination does not exist.",
            "Correct the hostname or restore the missing DNS destination; remove obsolete aliases.",
            a.evidence().into_iter().chain(aaaa.evidence()).collect(),
        ));
    }
    for set in [&a, &aaaa] {
        if set.error.as_deref() == Some("Confirmed CNAME cycle") {
            out.push(finding(
                hostname,
                "CNAME cycle",
                Error,
                "A CNAME edge returns to an earlier owner",
                "This actual alias cycle prevents address resolution.",
                "Remove the cyclic alias and point each CNAME toward a terminal address host.",
                set.evidence(),
            ));
        }
        if set.aliases.len() > 5 {
            out.push(finding(
                hostname,
                "CNAME depth",
                Warning,
                "CNAME chain exceeds five aliases",
                "Long alias chains add latency and dependencies; collection stops after ten edges.",
                "Shorten the alias chain by pointing to a stable terminal service name.",
                set.evidence(),
            ));
        }
    }
    if (!a.aliases.is_empty() || !aaaa.aliases.is_empty())
        && a.addresses().is_empty()
        && aaaa.addresses().is_empty()
        && a.error.is_none()
        && aaaa.error.is_none()
    {
        out.push(finding(hostname, "Broken CNAME destination", Error, "CNAME chain has no address destination", "Clients cannot reach the target through the published alias chain; takeover exploitability was not tested.", "Restore the destination or remove the obsolete CNAME.", a.evidence().into_iter().chain(aaaa.evidence()).collect()));
    }
    out
}

pub(super) async fn authority(domain: &str, collector: &Collector<'_>) -> Vec<DnsObservation> {
    let mut out = Vec::new();
    let recursive = collector.rrset(domain, RecordType::NS).await;
    if let Some(item) = unavailable(domain, "Nameserver discovery", &recursive) {
        out.push(item);
    }
    let recursive_names = {
        let (records, owner): (&[Record], &str) = (&recursive.records, domain);
        let inlined_result: Vec<String> = {
            let mut names = owned_records(records, owner, RecordType::NS)
                .iter()
                .map(|record| {
                    (&record.data.to_string())
                        .trim_end_matches('.')
                        .to_ascii_lowercase()
                })
                .collect::<Vec<_>>();
            names.sort();
            names.dedup();
            names
        };
        inlined_result
    };
    let (parent, ds) = ({
let (domain, collector, out,): (& str, & Collector < '_ >, & mut Vec < DnsObservation >,) = (domain, collector, &mut out,);
async move {

    let mut parent = domain.split_once('.').map(|(_, parent)| parent).unwrap_or("").to_owned();
    for _ in 0..DEPTH_LIMIT {
        let ns = collector.rrset(&parent, RecordType::NS).await;
        if let Some(item) = unavailable(domain, "Parent authority discovery", &ns) { out.push(item); return (None, None); }
        let names = {
let (records, owner,): (& [Record], & str,) = (&ns.records, &parent,);
let inlined_result: Vec < String > = {

    let mut names = owned_records(records, owner, RecordType::NS).iter().map(|record| (&record.data.to_string()).trim_end_matches('.').to_ascii_lowercase()).collect::<Vec<_>>();
    names.sort();
    names.dedup();
    names

};
inlined_result
};
        if !names.is_empty() {
            let mut errors = Vec::new();
            for server in names.iter().take(8) {
                let (a, aaaa) = collector.address_sets(server).await;
                for ip in {
let (a, aaaa,): (& Rrset, & Rrset,) = (&a, &aaaa,);

    [a, aaaa].iter().filter_map(|set| set.addresses().into_iter().find(|ip| non_public_reason(*ip).is_none())).collect::<Vec<_>>()

} {
                    let remote = SocketAddr::new(ip, 53);
                    let response = collector.query(domain, RecordType::NS, Some((remote, false))).await;
                    match response {
                        Ok(message) => {
                            let delegated = ({
let (records, owner,): (& [Record], & str,) = (&message.authorities, domain,);
let inlined_result: Vec < String > = {

    let mut names = owned_records(records, owner, RecordType::NS).iter().map(|record| (&record.data.to_string()).trim_end_matches('.').to_ascii_lowercase()).collect::<Vec<_>>();
    names.sort();
    names.dedup();
    names

};
inlined_result
}).into_iter().chain({
let (records, owner,): (& [Record], & str,) = (&message.answers, domain,);
let inlined_result: Vec < String > = {

    let mut names = owned_records(records, owner, RecordType::NS).iter().map(|record| (&record.data.to_string()).trim_end_matches('.').to_ascii_lowercase()).collect::<Vec<_>>();
    names.sort();
    names.dedup();
    names

};
inlined_result
}).collect::<Vec<_>>();
                            if delegated.is_empty() {
                                errors.push(format!("Parent {server} ({ip}) returned no delegation for {domain}"));
                                continue;
                            }
                            let ds = match collector.query(domain, RecordType::DS, Some((remote, false))).await {
                                Ok(ds) if ds.metadata.authoritative => Some(ds),
                                Ok(_) => { errors.push("Parent DS answer was not authoritative".to_owned()); None }
                                Err(error) => { errors.push(format!("Parent DS: {error}")); None }
                            };
                            if ds.is_none() {
                                out.push(finding(domain, "Parent DS collection", Inconclusive, "Parent DS could not be established", "DNSSEC delegation cannot be assessed from a child-side DS query.", "Retry an authoritative DS query against the parent zone.", errors));
                            }
                            out.push(finding(domain, "Parent delegation coverage", Informational, "Delegation sampled from one responding parent nameserver", "Parent/child comparison is a point-in-time sample, not a test of every parent replica.", "Recheck disagreements after zone propagation.", vec![format!("Parent zone: {parent}; server: {server} ({ip})")]));
                            return (Some(message), ds);
                        }
                        Err(error) => errors.push(format!("{server} ({ip}): {error}")),
                    }
                }
                if collector.cancel.is_cancelled() || collector.limited.load(Ordering::Relaxed) != 0 { break; }
            }
            out.push(finding(domain, "Parent delegation", Inconclusive, "No usable parent delegation response was obtained", "Parent/child NS and glue consistency cannot be established.", "Retry from a network with authoritative DNS access and inspect the registrar delegation.", errors));
            return (None, None);
        }
        if parent.is_empty() { break; }
        parent = parent.split_once('.').map(|(_, parent)| parent).unwrap_or("").to_owned();
    }
    out.push(finding(domain, "Parent delegation", Inconclusive, "Parent zone discovery reached its coverage limit", "The parent delegation was not inspected.", "Inspect parent authority and delegation manually.", Vec::new()));
    (None, None)

}
}).await;
    let parent_names = parent.as_ref().map(|message| {
        let mut names = {
            let (records, owner): (&[Record], &str) = (&message.authorities, domain);
            let inlined_result: Vec<String> = {
                let mut names = owned_records(records, owner, RecordType::NS)
                    .iter()
                    .map(|record| {
                        (&record.data.to_string())
                            .trim_end_matches('.')
                            .to_ascii_lowercase()
                    })
                    .collect::<Vec<_>>();
                names.sort();
                names.dedup();
                names
            };
            inlined_result
        };
        names.extend({
            let (records, owner): (&[Record], &str) = (&message.answers, domain);
            let inlined_result: Vec<String> = {
                let mut names = owned_records(records, owner, RecordType::NS)
                    .iter()
                    .map(|record| {
                        (&record.data.to_string())
                            .trim_end_matches('.')
                            .to_ascii_lowercase()
                    })
                    .collect::<Vec<_>>();
                names.sort();
                names.dedup();
                names
            };
            inlined_result
        });
        names.sort();
        names.dedup();
        names
    });
    let mut advertised = recursive_names.clone();
    if let Some(names) = &parent_names {
        advertised.extend(names.clone());
    }
    advertised.sort();
    advertised.dedup();
    if advertised.is_empty() {
        if recursive.error.is_none() {
            out.push(finding(domain, "Nameserver publication", Warning, "No apex nameservers were returned", "The assessed domain may not have its own delegated zone or may have missing NS publication.", "Confirm the zone boundary and publish matching registrar and apex NS records.", recursive.evidence()));
        }
    } else if advertised.len() < 2 {
        out.push(finding(
            domain,
            "Nameserver redundancy",
            Warning,
            "Only one nameserver is advertised",
            "A single nameserver creates a DNS availability dependency.",
            "Advertise at least two independently operated authoritative nameservers.",
            advertised.clone(),
        ));
    }
    if let Some(names) = &parent_names
        && recursive.error.is_none()
        && *names != recursive_names
    {
        out.push(finding(domain, "Delegation NS consistency", Warning, "Parent delegation and recursive apex NS sets differ", "Resolvers may select different servers during changes; disagreement can be transient.", "Synchronize registrar delegation and child apex NS records, then recheck after propagation.", vec![format!("Parent: {}", names.join(", ")), format!("Recursive apex: {}", recursive_names.join(", "))]));
    }
    if advertised.len() > 8 {
        out.push(finding(
            domain,
            "Nameserver coverage",
            Inconclusive,
            "More than eight nameservers are advertised",
            "Only eight servers, with one address per available family, are probed.",
            "Check the remaining advertised nameservers separately.",
            vec![format!("Advertised server count: {}", advertised.len())],
        ));
    }
    let mut destinations: HashMap<IpAddr, Vec<String>> = HashMap::new();
    let mut serials = Vec::new();
    let mut ns_sets: Vec<(String, Vec<String>)> = Vec::new();
    let mut child_key_server = None;
    for server in advertised.iter().take(8) {
        if collector.cancel.is_cancelled() {
            break;
        }
        let (a, aaaa) = collector.address_sets(server).await;
        out.extend(mail::destination_findings(
            server,
            "Nameserver destination",
            &a,
            &aaaa,
        ));
        if !a.aliases.is_empty() || !aaaa.aliases.is_empty() {
            out.push(finding(
                server,
                "Nameserver alias",
                Error,
                "NS destination is an alias",
                "Nameserver targets must be canonical names with address records.",
                "Replace the NS target with the canonical authoritative server name.",
                a.evidence().into_iter().chain(aaaa.evidence()).collect(),
            ));
        }
        let addresses = a
            .addresses()
            .into_iter()
            .chain(aaaa.addresses())
            .collect::<Vec<_>>();
        for ip in &addresses {
            destinations.entry(*ip).or_default().push(server.clone());
        }
        if let Some(message) = &parent
            && within_domain(server, domain)
            && parent_names
                .as_ref()
                .is_some_and(|names| names.contains(server))
        {
            let glue = message
                .additionals
                .iter()
                .filter(|record| {
                    (&record.name.to_string())
                        .trim_end_matches('.')
                        .to_ascii_lowercase()
                        == *server
                })
                .filter_map(|record| match &record.data {
                    RData::A(ip) => Some(IpAddr::V4(ip.0)),
                    RData::AAAA(ip) => Some(IpAddr::V6(ip.0)),
                    _ => None,
                })
                .collect::<Vec<_>>();
            if glue.is_empty() {
                out.push(finding(server, "Delegation glue", Warning, "In-bailiwick nameserver glue is missing from the parent referral", "Resolvers may be unable to bootstrap this nameserver.", "Register the nameserver's host addresses as glue at the registrar and recheck parent referrals.", vec![format!("Parent referral for {domain} contained no address glue for this server")]));
            } else if a.error.is_none()
                && aaaa.error.is_none()
                && (glue.iter().any(|ip| !addresses.contains(ip))
                    || addresses.iter().any(|ip| !glue.contains(ip)))
            {
                out.push(finding(server, "Delegation glue consistency", Warning, "Parent glue and resolved nameserver addresses differ", "Stale or incomplete glue can route DNS queries to old destinations; propagation may be transient.", "Synchronize registrar host glue and authoritative A/AAAA records.", vec![format!("Glue: {glue:?}; resolved: {addresses:?}")]));
            }
        }
        for ip in {
            let (a, aaaa): (&Rrset, &Rrset) = (&a, &aaaa);

            [a, aaaa]
                .iter()
                .filter_map(|set| {
                    set.addresses()
                        .into_iter()
                        .find(|ip| non_public_reason(*ip).is_none())
                })
                .collect::<Vec<_>>()
        } {
            let remote = SocketAddr::new(ip, 53);
            let probes = [
                (RecordType::SOA, false),
                (RecordType::SOA, true),
                (RecordType::NS, false),
            ];
            let results = futures_util::stream::iter(probes)
                .map(|(kind, tcp)| async move {
                    (
                        kind,
                        tcp,
                        collector.query(domain, kind, Some((remote, tcp))).await,
                    )
                })
                .buffer_unordered(collector.concurrency)
                .collect::<Vec<_>>()
                .await;
            for (kind, tcp, result) in results {
                let label = format!("{server} ({ip}) {} {kind}", if tcp { "TCP" } else { "UDP" });
                match result {
                    Err(error) => out.push(finding(server, "Authoritative DNS reachability", Inconclusive, &format!("{} {kind} query did not complete", if tcp { "TCP" } else { "UDP" }), "This endpoint did not provide a usable response from this network; record absence or global failure is not established.", "Check UDP and TCP port 53 routing, firewall rules and authoritative service health, then retry.", vec![label, error])),
                    Ok(message) if !message.metadata.authoritative => out.push(finding(server, "Authoritative DNS service", Error, &format!("{} {kind} response was not authoritative", if tcp { "TCP" } else { "UDP" }), "This advertised server returned a non-authoritative response for the zone (a lame delegation).", "Load the zone on this server or remove it from both delegation and apex NS sets.", vec![label])),
                    Ok(message) => {
                        let records = owned_records(&message.answers, domain, kind);
                        if records.is_empty() {
                            out.push(finding(server, "Authoritative apex records", Error, &format!("Authoritative {kind} response has no apex {kind} record"), "A delegated zone requires consistent apex NS and SOA records.", "Repair the zone apex on this nameserver and synchronize replicas.", vec![label]));
                            continue;
                        }
                        if kind == RecordType::NS {
                            let names = {
let (records, owner,): (& [Record], & str,) = (&records, domain,);
let inlined_result: Vec < String > = {

    let mut names = owned_records(records, owner, RecordType::NS).iter().map(|record| (&record.data.to_string()).trim_end_matches('.').to_ascii_lowercase()).collect::<Vec<_>>();
    names.sort();
    names.dedup();
    names

};
inlined_result
};
                            if parent_names.as_ref().is_some_and(|parent| *parent != names) {
                                out.push(finding(server, "Parent/child delegation", Warning, "Child authority NS set differs from parent delegation", "Parent and child advertise different authoritative servers; changes may still be propagating.", "Align parent delegation and child apex NS records, then recheck after propagation.", vec![label.clone(), format!("Child NS: {}", names.join(", "))]));
                            }
                            ns_sets.push((label, names));
                        } else {
                            child_key_server.get_or_insert(remote);
                            for record in records {
                                if let RData::SOA(soa) = &record.data {
                                    serials.push((label.clone(), soa.serial));
                                    out.extend({
let (server, soa, label,): (& str, & hickory_resolver :: proto :: rr :: rdata :: SOA, & str,) = (server, soa, &label,);
let inlined_result: Vec < DnsObservation > = {

    let evidence = vec![format!("{label}: serial {}; refresh {}; retry {}; expire {}; minimum {}; contact redacted", soa.serial, soa.refresh, soa.retry, soa.expire, soa.minimum)];
    let mut out = Vec::new();
    if soa.refresh <= 0 || soa.retry <= 0 || soa.expire <= 0 {
        out.push(finding(server, "SOA timers", Warning, "SOA contains non-positive maintenance timers", "Secondary refresh, retry or expiry behavior may be unusable.", "Use positive refresh, retry and expire intervals appropriate for zone operations.", evidence.clone()));
    }
    if soa.expire <= soa.refresh || soa.expire <= soa.retry {
        out.push(finding(server, "SOA expiry relationship", Warning, "SOA expire is not greater than refresh and retry", "Secondaries may expire the zone before normal refresh or recovery completes.", "Set expire substantially above both refresh and retry.", evidence.clone()));
    }
    if soa.retry > soa.refresh {
        out.push(finding(server, "SOA retry relationship", Warning, "SOA retry is greater than refresh", "Recovery after a failed refresh may be slower than normal refresh cadence.", "Usually set retry below refresh, accounting for your authoritative provider's requirements.", evidence));
    }
    out

};
inlined_result
});
                                }
                            }
                            out.push(finding(server, "Authoritative DNS reachability", Pass, &format!("Authoritative SOA answered over {}", if tcp { "TCP" } else { "UDP" }), "This sampled address and transport served an authoritative SOA answer.", "Keep both UDP and TCP port 53 available on advertised addresses.", vec![label]));
                        }
                    }
                }
            }
        }
    }
    for (ip, mut servers) in destinations {
        servers.sort();
        servers.dedup();
        if servers.len() > 1 {
            out.push(finding(domain, "Nameserver address redundancy", Warning, "Multiple nameservers share a destination address", "Different NS names do not provide independent address-level redundancy at this destination.", "Use authoritative nameservers on independent addresses and failure domains.", vec![format!("{ip}: {}", servers.join(", "))]));
        }
    }
    if serials
        .iter()
        .map(|(_, serial)| serial)
        .collect::<HashSet<_>>()
        .len()
        > 1
    {
        out.push(finding(domain, "SOA serial consistency", Warning, "Authoritative servers report different SOA serials", "Zone replicas may be out of sync; a recent update can cause transient differences.", "Recheck after the refresh interval; investigate failed replication if disagreement persists.", serials.iter().map(|(server, serial)| format!("{server}: serial {serial}")).collect()));
    } else if serials.len() > 1 {
        out.push(finding(
            domain,
            "SOA serial consistency",
            Pass,
            "Sampled authoritative SOA serials agree",
            "Only sampled servers and transports were compared.",
            "Monitor zone synchronization after changes.",
            serials
                .iter()
                .map(|(server, serial)| format!("{server}: serial {serial}"))
                .collect(),
        ));
    }
    if ns_sets
        .iter()
        .map(|(_, names)| names)
        .collect::<HashSet<_>>()
        .len()
        > 1
    {
        out.push(finding(domain, "Child NS consistency", Warning, "Authoritative servers publish different apex NS sets", "Clients can receive inconsistent authority information during propagation or replication failures.", "Synchronize the zone across all authoritative servers and recheck.", ns_sets.into_iter().map(|(server, names)| format!("{server}: {}", names.join(", "))).collect()));
    }
    out.extend({
let (domain, parent, child_server, collector,): (& str, Option < & Message >, Option < SocketAddr >, & Collector < '_ >,) = (domain, ds.as_ref(), child_key_server, collector,);
async move {

    let mut out = vec![finding(domain, "DNSSEC validation scope", Inconclusive, "DNSSEC cryptographic validation was not performed", "Record presence, DS digest matches and signature dates do not establish a validated chain of trust or authenticated denial of existence.", "Use a validating resolver or dedicated DNSSEC validator to verify the complete chain and signatures.", Vec::new())];
    let Some(parent) = parent else { return out; };
    let ds = owned_records(&parent.answers, domain, RecordType::DS);
    if ds.is_empty() {
        out.push(finding(domain, "DNSSEC delegation", Recommendation, "No DS record was returned by the parent authority", "The observed delegation is unsigned; absence was not cryptographically authenticated.", "If supported by your provider, sign the zone and publish its DS through the registrar after verifying key rollover procedures.", vec![format!("Parent response: {}", parent.metadata.response_code)]));
        return out;
    }
    let Some(remote) = child_server else {
        out.push(finding(domain, "DNSSEC child material", Inconclusive, "No reachable child authority was available for DNSKEY inspection", "The published parent DS could not be compared with child keys.", "Restore authoritative DNS reachability and recheck DNSSEC delegation.", Vec::new()));
        return out;
    };
    let message = match collector.query(domain, RecordType::DNSKEY, Some((remote, true))).await {
        Ok(message) if message.metadata.authoritative => message,
        result => {
            out.push(finding(domain, "DNSSEC child material", Inconclusive, "Authoritative DNSKEY collection failed", "The parent DS cannot be compared with an unavailable key set.", "Check authoritative TCP DNS and DNSKEY publication, then retry.", vec![match result { Err(error) => error, _ => "Non-authoritative DNSKEY answer".to_owned() }]));
            return out;
        }
    };
    let keys = owned_records(&message.answers, domain, RecordType::DNSKEY);
    out.extend({
let (domain, ds, keys,): (& str, & [Record], & [Record],) = (domain, &ds, &keys,);
let inlined_result: Vec < DnsObservation > = {
'inlined_dnssec_material: {

    if keys.is_empty() {
        break 'inlined_dnssec_material vec![finding(domain, "DNSSEC DS/DNSKEY", Error, "Parent DS exists but child authority returned no DNSKEY", "Validating resolvers cannot build the delegated chain of trust.", "Restore the matching child DNSKEY and signing, or coordinate DS removal with the registrar if intentionally disabling DNSSEC.", Vec::new())];
    }
    let mut out = Vec::new();
    let wire_keys = keys.iter().filter_map(|record| wire(&record.data).ok()).collect::<Vec<_>>();
    let mut supported = 0;
    let mut matched = 0;
    let mut unsupported = 0;
    let owner = Name::from_ascii(domain).ok().and_then(|name| wire(&name).ok()).unwrap_or_default();
    for record in ds {
        let bytes = wire(&record.data).unwrap_or_default();
        if bytes.len() < 4 {
            out.push(finding(domain, "DNSSEC DS syntax", Error, "Parent DS record is too short", "The digest record cannot be interpreted.", "Replace the DS with a valid digest from the authoritative DNS provider.", Vec::new()));
            continue;
        }
        let tag = u16::from_be_bytes([bytes[0], bytes[1]]);
        let expected_len = match bytes[3] { 1 => 20, 2 => 32, 4 => 48, _ => { unsupported += 1; continue; } };
        if bytes.len() != expected_len + 4 {
            out.push(finding(domain, "DNSSEC DS digest", Error, "Parent DS digest length is invalid", "This DS cannot authenticate a DNSKEY using its advertised digest algorithm.", "Replace the DS with the provider's exact digest, algorithm and key tag.", vec![format!("Key tag: {tag}; digest type: {}; digest redacted", bytes[3])]));
            continue;
        }
        if !matches!(bytes[2], 5 | 7 | 8 | 10 | 13 | 14 | 15 | 16) { unsupported += 1; continue; }
        supported += 1;
        let matches = wire_keys.iter().any(|key| {
            if key.len() < 4 || key[2] != 3 || key[3] != bytes[2] || key[0] & 1 == 0 || ({
let (key,): (& [u8],) = (key,);
let inlined_result: u16 = {

    let mut sum = key.iter().enumerate().map(|(index, byte)| if index % 2 == 0 { u32::from(*byte) << 8 } else { u32::from(*byte) }).sum::<u32>();
    sum += (sum >> 16) & 0xffff;
    (sum & 0xffff) as u16

};
inlined_result
}) != tag { return false; }
            let material = owner.iter().chain(key.iter()).copied().collect::<Vec<_>>();
            let digest = match bytes[3] { 1 => sha1::Sha1::digest(&material).to_vec(), 2 => sha2::Sha256::digest(&material).to_vec(), 4 => sha2::Sha384::digest(&material).to_vec(), _ => return false };
            digest == bytes[4..]
        });
        if matches { matched += 1; }
    }
    if wire_keys.iter().any(|key| key.len() <= 4 || key[2] != 3) {
        out.push(finding(domain, "DNSKEY syntax", Error, "DNSKEY has invalid protocol or empty key material", "Malformed DNSKEY records cannot be used to authenticate the zone.", "Regenerate and publish valid protocol-3 DNSKEY records.", Vec::new()));
    }
    if supported > 0 && matched == 0 {
        out.push(finding(domain, "DNSSEC DS/DNSKEY", if unsupported == 0 { Error } else { Inconclusive }, "No supported parent DS digest matches child DNSKEY material", "A supported DS-to-key link was not found; rollover or stale delegation can break validating resolution.", "Synchronize parent DS and child DNSKEY material with the DNS provider's current signing keys.", vec![format!("Supported DS: {supported}; matched: {matched}; unsupported DS: {unsupported}; key material redacted")]));
    } else if matched > 0 {
        out.push(finding(domain, "DNSSEC DS/DNSKEY structure", Pass, "At least one parent DS digest matches a child zone key", "This is a structural digest match only, not cryptographic validation of signatures or the trust chain.", "Maintain coordinated key rollovers and verify with a full DNSSEC validator.", vec![format!("Matching DS entries: {matched}; key material redacted")]));
        if matched < supported {
            out.push(finding(domain, "DNSSEC rollover consistency", Warning, "Some supported parent DS entries do not match current child keys", "This can occur during a rollover; stale records should be reviewed.", "Confirm rollover timing and remove stale DS records when it is safe to do so.", Vec::new()));
        }
    }
    if unsupported > 0 {
        out.push(finding(domain, "DNSSEC algorithm coverage", Inconclusive, "Some DS algorithms or digest types are unsupported", "These DS entries were not compared with child key material.", "Check them with a DNSSEC validator supporting the published algorithms.", vec![format!("Unsupported entries: {unsupported}")]));
    }
    out

}
};
inlined_result
});
    let mut signatures = owned_records(&message.answers, domain, RecordType::RRSIG);
    signatures.retain(|record| wire(&record.data).is_ok_and(|bytes| bytes.len() >= 2 && u16::from_be_bytes([bytes[0], bytes[1]]) == 48));
    if signatures.is_empty() {
        match collector.query(domain, RecordType::RRSIG, Some((remote, true))).await {
            Ok(message) if message.metadata.authoritative => {
                signatures = owned_records(&message.answers, domain, RecordType::RRSIG);
                signatures.retain(|record| wire(&record.data).is_ok_and(|bytes| bytes.len() >= 2 && u16::from_be_bytes([bytes[0], bytes[1]]) == 48));
                if signatures.is_empty() {
                    out.push(finding(domain, "DNSSEC signatures", Error, "Signed delegation has no observed DNSKEY-covering RRSIG", "The child DNSKEY RRset cannot form a valid signed chain without its signature.", "Repair zone signing and publish DNSKEY signatures before retaining the parent DS.", Vec::new()));
                }
            }
            _ => out.push(finding(domain, "DNSSEC signatures", Inconclusive, "DNSKEY signature collection did not complete", "Signature presence and timing could not be established.", "Retry authoritative DNSKEY/RRSIG collection with DNSSEC records enabled.", Vec::new())),
        }
    }
    out.extend({
let (domain, signatures, now,): (& str, & [Record], u32,) = (domain, &signatures, SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as u32,);
let inlined_result: Vec < DnsObservation > = {

    let mut out = Vec::new();
    let mut current = 0;
    let mut expired = 0;
    let mut future = 0;
    for signature in signatures {
        let bytes = wire(&signature.data).unwrap_or_default();
        if bytes.len() < 19 {
            out.push(finding(domain, "DNSSEC signature syntax", Error, "RRSIG is too short", "The signature record cannot be interpreted.", "Repair zone signing and republish valid signatures.", Vec::new()));
            continue;
        }
        let expiration = u32::from_be_bytes(bytes[8..12].try_into().unwrap());
        let inception = u32::from_be_bytes(bytes[12..16].try_into().unwrap());
        if (now.wrapping_sub(inception) as i32) < 0 { future += 1; }
        else if (expiration.wrapping_sub(now) as i32) < 0 { expired += 1; }
        else { current += 1; }
    }
    for (count, summary) in [(expired, "DNSKEY signatures include expired signatures"), (future, "DNSKEY signatures include signatures not yet valid")] {
        if count > 0 {
            out.push(finding(domain, "DNSSEC signature timing", if current == 0 { Error } else { Warning }, summary, "Out-of-window signatures cannot validate at the local clock time; another current signature may preserve service.", "Check signer and local clock synchronization, refresh signatures and review rollover timing.", vec![format!("Affected signatures: {count}; current signatures: {current}; local Unix time: {now}; signatures redacted")]));
        }
    }
    if current > 0 {
        out.push(finding(domain, "DNSSEC signature timing", Pass, "At least one DNSKEY signature is within its advertised time window", "Signature dates alone do not prove cryptographic validity.", "Continue signature renewal monitoring and verify signatures with a DNSSEC validator.", vec![format!("Current signatures: {current}")]));
    }
    out

};
inlined_result
});
    out

}
}.await);
    out
}
