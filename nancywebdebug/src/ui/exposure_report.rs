use super::*;
use crate::UdpEndpointState;
use crate::diagnostics::TraceOutcome;
use crate::{ExposureFinding, TechnologyComponentKind, TransportProtocol};

pub(in crate::ui) fn show_report(
    ui: &mut egui::Ui,
    report: &ExposureScanReport,
    tab: ExposureDetailTab,
    diagnostic_view: &mut DiagnosticViewState,
) {
    egui::ScrollArea::vertical().show(ui, |ui| match tab {
        ExposureDetailTab::Diagnostics => {
            show_summary(ui, report);
            ui.separator();
            show_diagnostics(ui, report, diagnostic_view);
        }
        ExposureDetailTab::Ports => show_ports(ui, report),
        ExposureDetailTab::NetworkPosture => show_network_posture(ui, report),
        ExposureDetailTab::Discovery => show_discovery(ui, report),
        ExposureDetailTab::HttpTls => show_http_tls(ui, report),
        ExposureDetailTab::Crawl => show_crawl(ui, report),
        ExposureDetailTab::ExternalSources => show_external_sources(ui, report),
        ExposureDetailTab::JavaScript => show_technology(ui, report),
        ExposureDetailTab::SecuritySummary => show_security_summary(ui, report),
    });
}

fn show_diagnostics(
    ui: &mut egui::Ui,
    report: &ExposureScanReport,
    view: &mut DiagnosticViewState,
) {
    show_confirmed_products(ui, report);
    ui.separator();
    show_detected_language_file_types(ui, report);
    ui.separator();
    ui.heading("Endpoint Diagnostics");
    let endpoint_indices = report
        .endpoints
        .iter()
        .enumerate()
        .filter_map(|(index, endpoint)| (!endpoint.diagnostics.is_empty()).then_some(index))
        .collect::<Vec<_>>();
    if endpoint_indices.is_empty() {
        ui.weak("No HTTP or HTTPS endpoints were discovered.");
        return;
    }
    if view
        .endpoint_index
        .is_none_or(|index| !endpoint_indices.contains(&index))
    {
        view.endpoint_index = Some(
            endpoint_indices
                .iter()
                .copied()
                .find(|&index| {
                    report.endpoints[index]
                        .diagnostics
                        .last()
                        .is_some_and(|trace| trace.outcome == TraceOutcome::Success)
                })
                .unwrap_or(endpoint_indices[0]),
        );
        view.hop_index = 0;
    }
    let previous_endpoint = view.endpoint_index;
    ui.horizontal_wrapped(|ui| {
        ui.label("Endpoint");
        egui::ComboBox::from_id_salt("diagnostic_endpoint")
            .selected_text(
                view.endpoint_index
                    .map(|index| {
                        let endpoint = &report.endpoints[index];
                        format!("{}:{}", endpoint.ip, endpoint.port)
                    })
                    .unwrap_or_default(),
            )
            .show_ui(ui, |ui| {
                for &index in &endpoint_indices {
                    let endpoint = &report.endpoints[index];
                    ui.selectable_value(
                        &mut view.endpoint_index,
                        Some(index),
                        format!("{}:{} — {}", endpoint.ip, endpoint.port, endpoint.service),
                    );
                }
            });
    });
    if view.endpoint_index != previous_endpoint {
        view.hop_index = 0;
    }
    let endpoint_index = view.endpoint_index.unwrap_or(endpoint_indices[0]);
    let endpoint = &report.endpoints[endpoint_index];
    view.hop_index = view.hop_index.min(endpoint.diagnostics.len() - 1);
    ui.horizontal_wrapped(|ui| {
        ui.label("Hop");
        egui::ComboBox::from_id_salt("diagnostic_hop")
            .selected_text(format!(
                "{} — {}",
                view.hop_index + 1,
                display_url(&endpoint.diagnostics[view.hop_index])
            ))
            .show_ui(ui, |ui| {
                for (index, trace) in endpoint.diagnostics.iter().enumerate() {
                    ui.selectable_value(
                        &mut view.hop_index,
                        index,
                        format!("{} — {}", index + 1, display_url(trace)),
                    );
                }
            });
    });
    ui.horizontal_wrapped(|ui| {
        for tab in DetailTab::ALL {
            ui.selectable_value(&mut view.tab, tab, tab.label());
        }
    });
    ui.separator();
    let trace = &endpoint.diagnostics[view.hop_index];
    let chain = endpoint.diagnostics.iter().collect::<Vec<_>>();
    match view.tab {
        DetailTab::Summary => show_diagnostic_summary(ui, trace, &chain),
        DetailTab::Network => show_network(ui, trace),
        DetailTab::Tls => show_tls(ui, trace),
        DetailTab::Http => show_http(ui, trace),
        DetailTab::Body => show_body(ui, trace, &mut view.body_view),
    }
}

struct ConfirmedProduct {
    name: String,
    layer: ProductLayer,
    versions: BTreeSet<String>,
    confidence: Confidence,
}

fn confirmed_products(report: &ExposureScanReport) -> Vec<ConfirmedProduct> {
    let mut products = BTreeMap::<(u8, String), ConfirmedProduct>::new();
    for product in report
        .endpoints
        .iter()
        .flat_map(|endpoint| &endpoint.products)
        .filter(|product| matches!(product.confidence, Confidence::Medium | Confidence::High))
    {
        let key = (
            product_layer_order(product.layer),
            product.name.to_ascii_lowercase(),
        );
        let confirmed = products.entry(key).or_insert_with(|| ConfirmedProduct {
            name: product.name.clone(),
            layer: product.layer,
            versions: BTreeSet::new(),
            confidence: product.confidence,
        });
        if product.name < confirmed.name {
            confirmed.name.clone_from(&product.name);
        }
        if let Some(version) = &product.version {
            confirmed.versions.insert(version.clone());
        }
        confirmed.confidence = confirmed.confidence.max(product.confidence);
    }
    products.into_values().collect()
}

fn show_confirmed_products(ui: &mut egui::Ui, report: &ExposureScanReport) {
    ui.heading("Confirmed Products");
    let products = confirmed_products(report);
    if products.is_empty() {
        ui.weak("No confirmed products detected.");
        return;
    }

    for product in products {
        let versions = if product.versions.is_empty() {
            String::new()
        } else {
            format!(
                " {}",
                product.versions.into_iter().collect::<Vec<_>>().join(", ")
            )
        };
        ui.label(format!(
            "{} [{}]{} — {} confidence",
            product.name, product.layer, versions, product.confidence
        ));
    }
}

fn product_layer_order(layer: ProductLayer) -> u8 {
    match layer {
        ProductLayer::Protocol => 0,
        ProductLayer::Server => 1,
        ProductLayer::Proxy => 2,
        ProductLayer::Cdn => 3,
        ProductLayer::Cloud => 4,
        ProductLayer::Framework => 5,
        ProductLayer::Runtime => 6,
        ProductLayer::Cms => 7,
        ProductLayer::Ecommerce => 8,
    }
}

struct ConfirmedFindingGroup<'a> {
    ip: std::net::IpAddr,
    title: &'a str,
    description: &'a str,
    endpoints: BTreeMap<TransportProtocol, BTreeSet<u16>>,
    evidence: Vec<&'a str>,
    collapsed: bool,
}

fn confirmed_finding_groups(findings: &[ExposureFinding]) -> Vec<ConfirmedFindingGroup<'_>> {
    let mut groups = BTreeMap::<(std::net::IpAddr, &str), ConfirmedFindingGroup<'_>>::new();
    for finding in findings {
        let collapsed = matches!(
            finding.component_kind,
            Some(TechnologyComponentKind::Package | TechnologyComponentKind::Plugin)
        );
        let group = groups
            .entry((finding.ip, finding.title.as_str()))
            .or_insert_with(|| ConfirmedFindingGroup {
                ip: finding.ip,
                title: &finding.title,
                description: &finding.description,
                endpoints: BTreeMap::new(),
                evidence: Vec::new(),
                collapsed,
            });
        group.collapsed &= collapsed;
        group
            .endpoints
            .entry(finding.transport)
            .or_default()
            .insert(finding.port);
        group
            .evidence
            .extend(finding.evidence.iter().map(String::as_str));
    }
    let mut groups = groups.into_values().collect::<Vec<_>>();
    for group in &mut groups {
        group.evidence.sort();
        group.evidence.dedup();
    }
    groups
}

fn confirmed_finding_count(findings: &[ExposureFinding]) -> usize {
    findings
        .iter()
        .map(|finding| (finding.ip, finding.title.as_str()))
        .collect::<BTreeSet<_>>()
        .len()
}

fn show_summary(ui: &mut egui::Ui, report: &ExposureScanReport) {
    ui.heading("Public Exposure Summary");
    egui::Grid::new("exposure_summary")
        .striped(true)
        .show(ui, |ui| {
            row(ui, "Target", &report.request.diagnostic_request.url);
            row(ui, "Hostname / SNI", &report.hostname);
            row(ui, "Status", &report.status.to_string());
            row(
                ui,
                "Public IPv4 addresses",
                &report
                    .resolved_addresses
                    .iter()
                    .filter(|address| address.is_ipv4())
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", "),
            );
            row(
                ui,
                "Public IPv6 addresses",
                &report
                    .resolved_addresses
                    .iter()
                    .filter(|address| address.is_ipv6())
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", "),
            );
            row(
                ui,
                "Open endpoints",
                &state_count(report, PortState::Open).to_string(),
            );
            row(
                ui,
                "Security Summary",
                &confirmed_finding_count(&report.findings).to_string(),
            );
            row(
                ui,
                "Total time",
                &format!("{:.2} s", report.timings.total_ms / 1_000.0),
            );
        });
    if let Some(error) = &report.error {
        ui.colored_label(egui::Color32::RED, error);
    }
    for warning in &report.warnings {
        ui.colored_label(egui::Color32::YELLOW, warning);
    }
}

fn show_ports(ui: &mut egui::Ui, report: &ExposureScanReport) {
    ui.heading("TCP Ports");
    ui.horizontal_wrapped(|ui| {
        ui.label(format!("Open: {}", state_count(report, PortState::Open)));
        ui.weak(format!(
            "Closed: {}",
            state_count(report, PortState::Closed)
        ));
        ui.weak(format!(
            "Filtered/no response: {}",
            state_count(report, PortState::FilteredOrNoResponse)
        ));
        ui.weak(format!("Errors: {}", state_count(report, PortState::Error)));
        ui.weak(format!(
            "Cancelled: {}",
            state_count(report, PortState::Cancelled)
        ));
    });
    let mut ports_by_ip = Vec::<(std::net::IpAddr, Vec<u16>)>::new();
    for endpoint in open_endpoints(report) {
        if let Some((_, ports)) = ports_by_ip.iter_mut().find(|(ip, _)| *ip == endpoint.ip) {
            ports.push(endpoint.port);
        } else {
            ports_by_ip.push((endpoint.ip, vec![endpoint.port]));
        }
    }
    ui.separator();
    ui.strong("Open ports by IP");
    for (ip, mut ports) in ports_by_ip {
        ports.sort_unstable();
        ports.dedup();
        let ports = ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        ui.label(format!("{ip}: {ports}"));
    }
    for endpoint in open_endpoints(report) {
        ui.separator();
        egui::CollapsingHeader::new(format!("{}:{}", endpoint.ip, endpoint.port))
            .default_open(false)
            .show(ui, |ui| {
                ui.label(format!(
                    "{} ({}) — {:.2} ms",
                    endpoint.service, endpoint.service_confidence, endpoint.connect_duration_ms
                ));
                if endpoint.products.is_empty() {
                    ui.weak("Product undisclosed");
                } else {
                    for product in &endpoint.products {
                        ui.label(format!(
                            "{} [{}]{} — {} confidence",
                            product.name,
                            product.layer,
                            product
                                .version
                                .as_ref()
                                .map(|version| format!(" {version}"))
                                .unwrap_or_default(),
                            product.confidence
                        ));
                    }
                }
            });
    }
}

fn show_network_posture(ui: &mut egui::Ui, report: &ExposureScanReport) {
    ui.heading("UDP Endpoints");
    if !report.request.udp_scanning {
        ui.weak("UDP scanning was disabled.");
    } else if report.udp_endpoints.is_empty() {
        ui.weak("No UDP endpoint results were recorded.");
    } else {
        for state in [
            UdpEndpointState::Responsive,
            UdpEndpointState::Closed,
            UdpEndpointState::OpenOrFiltered,
            UdpEndpointState::Error,
            UdpEndpointState::Cancelled,
        ] {
            let count = report
                .udp_endpoints
                .iter()
                .filter(|endpoint| endpoint.state == state)
                .count();
            if count > 0 {
                ui.label(format!("{state}: {count}"));
            }
        }
        for endpoint in &report.udp_endpoints {
            ui.separator();
            ui.strong(format!(
                "{}:{} / {} — {} — {}",
                endpoint.ip, endpoint.port, endpoint.transport, endpoint.service, endpoint.state
            ));
            for evidence in &endpoint.evidence {
                ui.weak(evidence);
            }
            if let Some(error) = &endpoint.error {
                ui.weak(error);
            }
        }
    }

    ui.separator();
    ui.heading("Service Access");
    ui.weak("Handshake-only checks never enumerate content, test credentials, or perform writes.");
    if !report.request.service_access_checks {
        ui.weak("Service access checks were disabled.");
    } else if report.service_access.is_empty() {
        ui.weak("No eligible service access checks were recorded.");
    } else {
        for access in &report.service_access {
            ui.separator();
            ui.strong(format!(
                "{}:{} / {} — {} — {}",
                access.ip, access.port, access.transport, access.service, access.status
            ));
            ui.label(format!("{}: {}", access.method, access.summary));
            for evidence in &access.evidence {
                ui.weak(evidence);
            }
        }
    }

    ui.separator();
    ui.heading("DNS Posture");
    if !report.request.dns_assessment {
        ui.weak("DNS posture assessment was disabled.");
    } else if report.dns_observations.is_empty() {
        ui.weak("No DNS posture observations were recorded.");
    } else {
        for observation in &report.dns_observations {
            show_dns_observation(ui, observation);
        }
    }

    if !report.stream_observations.is_empty() {
        ui.separator();
        ui.heading("Streaming & Signalling Inventory");
        for status in [
            crate::StreamStatus::Confirmed,
            crate::StreamStatus::Protected,
            crate::StreamStatus::Candidate,
            crate::StreamStatus::Inconclusive,
        ] {
            let entries = report
                .stream_observations
                .iter()
                .filter(|observation| observation.status == status)
                .collect::<Vec<_>>();
            if entries.is_empty() {
                continue;
            }
            ui.separator();
            ui.strong(status.to_string());
            for observation in entries {
                ui.label(format!(
                    "{} — {} confidence — {}",
                    observation.kind, observation.confidence, observation.source_url
                ));
                for evidence in &observation.evidence {
                    ui.weak(evidence);
                }
                for endpoint in &observation.endpoints {
                    ui.weak(endpoint);
                }
            }
        }
    }
}

fn show_discovery(ui: &mut egui::Ui, report: &ExposureScanReport) {
    ui.heading("Discovered Assets");
    ui.weak(
        "When enabled, this section queries the public crt.sh service. CT-derived hosts are inventory-only and are never port-scanned or requested over HTTP.",
    );
    if !report.request.asset_discovery {
        ui.weak("Certificate-transparency asset discovery was disabled.");
    } else if report.discovered_assets.is_empty() {
        ui.weak("No CT-derived assets were retained.");
    } else {
        for (heading, resolved) in [("Resolved", true), ("Unresolved", false)] {
            let mut assets = report
                .discovered_assets
                .iter()
                .filter(|asset| !asset.addresses.is_empty() == resolved)
                .peekable();
            if assets.peek().is_none() {
                continue;
            }
            ui.separator();
            ui.heading(heading);
            for asset in assets {
                ui.separator();
                ui.strong(format!("{} — {}", asset.hostname, asset.state));
                ui.label(&asset.detail);
                if !asset.addresses.is_empty() {
                    ui.weak(format!(
                        "DNS addresses: {}",
                        asset
                            .addresses
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                }
                if !asset.cname_chain.is_empty() {
                    ui.weak(format!("CNAME chain: {}", asset.cname_chain.join(" → ")));
                }
            }
        }
    }
}

fn show_http_tls(ui: &mut egui::Ui, report: &ExposureScanReport) {
    ui.heading("HTTP / TLS Observations");
    for endpoint in open_endpoints(report) {
        if endpoint.tls.is_empty() && endpoint.http.is_empty() {
            continue;
        }
        ui.separator();
        egui::CollapsingHeader::new(
            egui::RichText::new(format!("{}:{}", endpoint.ip, endpoint.port)).strong(),
        )
        .default_open(false)
        .show(ui, |ui| {
            for tls in &endpoint.tls {
                if tls.supported {
                    ui.label(format!(
                        "{}: {}; {}; ALPN {}; cipher {}",
                        tls.requested_version,
                        tls.negotiated_version.as_deref().unwrap_or("negotiated"),
                        if tls.verified { "valid" } else { "UNVERIFIED" },
                        tls.alpn.as_deref().unwrap_or("none"),
                        tls.cipher.as_deref().unwrap_or("undisclosed")
                    ));
                    if let Some(error) = &tls.validation_error {
                        ui.colored_label(egui::Color32::YELLOW, error);
                    }
                    ui.weak(format!(
                        "Client authentication: {}; CertificateRequest: {}{}",
                        tls.client_auth.status,
                        if tls.client_auth.certificate_requested {
                            "observed"
                        } else {
                            "not observed"
                        },
                        tls.client_auth
                            .profile_name
                            .as_ref()
                            .map(|profile| format!("; profile {profile}"))
                            .unwrap_or_default()
                    ));
                    for evidence in &tls.client_auth.evidence {
                        ui.weak(evidence);
                    }
                    for certificate in &tls.certificates {
                        ui.weak(format!(
                            "Certificate: {}; issuer: {}; valid {} to {}",
                            certificate.subject,
                            certificate.issuer,
                            certificate.not_before,
                            certificate.not_after
                        ));
                    }
                }
            }
            for http in &endpoint.http {
                ui.label(format!(
                    "{} {} → {} {}{}",
                    http.method,
                    http.url,
                    http.status,
                    http.reason,
                    if http.tls_unverified {
                        " [UNVERIFIED TLS]"
                    } else {
                        ""
                    }
                ));
                for (name, value) in &http.headers {
                    ui.weak(format!("{name}: {value}"));
                }
            }
        });
    }
}

fn show_crawl(ui: &mut egui::Ui, report: &ExposureScanReport) {
    ui.heading("Crawl Inventory");
    ui.label(format!(
        "{} origins; {} reported URLs; {} forms; {} contacts; {} skipped URLs",
        report.crawl_origins.len(),
        report.crawled_resources.len(),
        report.crawl_forms.len(),
        report.crawl_contacts.len(),
        report.crawl_skipped_urls.len()
    ));
    for origin in &report.crawl_origins {
        ui.separator();
        ui.strong(format!(
            "{}://{}:{} ({}) — {}/{} completed",
            origin.scheme, origin.hostname, origin.port, origin.ip, origin.completed, origin.queued
        ));
        ui.weak(format!("Seed: {}", origin.seed_url));
        for exclusion in &origin.robots_exclusions {
            ui.weak(format!("robots.txt exclusion (informational): {exclusion}"));
        }
        for sitemap in &origin.sitemap_urls {
            ui.weak(format!("Sitemap: {sitemap}"));
        }
    }
    let mut visible_resources = report.crawled_resources.iter().peekable();
    if visible_resources.peek().is_some() {
        ui.separator();
        ui.heading("Discovered URLs");
        for resource in visible_resources {
            let result = resource
                .status
                .map(|status| format!("HTTP {status}"))
                .or_else(|| resource.error.clone())
                .unwrap_or_else(|| "No result".to_owned());
            ui.label(format!(
                "Depth {} — {} — {} — {} bytes{}",
                resource.depth,
                resource.url,
                result,
                resource.bytes_inspected,
                if resource.body_truncated {
                    " (truncated)"
                } else {
                    ""
                }
            ));
            if !resource.detected_file_types.is_empty() {
                ui.weak(format!(
                    "Detected: {}",
                    resource
                        .detected_file_types
                        .iter()
                        .map(|detected| format!(
                            "{} ({} confidence)",
                            detected.file_type, detected.confidence
                        ))
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
        }
    }
    if !report.crawl_forms.is_empty() {
        ui.separator();
        ui.heading("Forms");
        for form in &report.crawl_forms {
            ui.label(format!(
                "{} {} — source {}{}{}",
                form.method,
                form.action_url,
                form.source_url,
                if form.has_password {
                    " — password field"
                } else {
                    ""
                },
                if form.enqueued { " — GET queued" } else { "" }
            ));
        }
    }
    if !report.crawl_skipped_urls.is_empty() {
        ui.separator();
        ui.heading("Skipped URLs");
        for skipped in &report.crawl_skipped_urls {
            ui.weak(format!("{} — {}", skipped.url, skipped.reason));
        }
    }
}

fn show_external_sources(ui: &mut egui::Ui, report: &ExposureScanReport) {
    ui.heading("External Sources");
    let mut sources = BTreeMap::<&str, BTreeSet<&str>>::new();
    for source in report
        .crawl_external_indicators
        .iter()
        .filter(|indicator| indicator.kind == "URL")
    {
        sources
            .entry(&source.value)
            .or_default()
            .insert(&source.source_url);
    }
    if sources.is_empty() {
        ui.weak("No external sources discovered.");
        return;
    }
    ui.weak("Report-only; these URLs were not requested.");
    egui::Grid::new("external_sources")
        .striped(true)
        .show(ui, |ui| {
            ui.strong("Endpoint");
            ui.strong("Called By");
            ui.end_row();
            for (endpoint, callers) in sources {
                ui.add(egui::Label::new(endpoint).selectable(true));
                ui.add(
                    egui::Label::new(callers.into_iter().collect::<Vec<_>>().join(", "))
                        .selectable(true),
                );
                ui.end_row();
            }
        });
}

fn show_evidence_disclosure(
    ui: &mut egui::Ui,
    id_salt: impl std::hash::Hash,
    evidence_urls: &[String],
    evidence: &[String],
) {
    let count = evidence_urls.len() + evidence.len();
    if count == 0 {
        return;
    }

    egui::CollapsingHeader::new(format!("Evidence ({count})"))
        .id_salt(id_salt)
        .default_open(false)
        .show(ui, |ui| {
            for url in evidence_urls {
                ui.weak(format!("Evidence URL: {url}"));
            }
            for item in evidence {
                ui.weak(format!("Evidence: {item}"));
            }
        });
}

fn show_technology(ui: &mut egui::Ui, report: &ExposureScanReport) {
    ui.heading("Technology Versions");
    show_technology_inventory(ui, report);
    ui.separator();
    ui.heading("Evidence and Details");
    ui.heading("Detected Web Technologies");
    let mut technologies =
        BTreeMap::<String, Vec<(&EndpointScan, &crate::WebTechnologyDetection)>>::new();
    for endpoint in open_endpoints(report) {
        for technology in &endpoint.web_technologies {
            technologies
                .entry(technology.name.to_ascii_lowercase())
                .or_default()
                .push((endpoint, technology));
        }
    }
    if technologies.is_empty() {
        ui.weak("No passive web technology signatures matched.");
    } else {
        for matches in technologies.into_values() {
            let name = &matches[0].1.name;
            ui.separator();
            ui.strong(name);
            for (endpoint, technology) in matches {
                ui.label(format!(
                    "{} — {} confidence — {}:{}",
                    technology
                        .version
                        .as_deref()
                        .unwrap_or("version not observed"),
                    technology.confidence,
                    endpoint.ip,
                    endpoint.port
                ));
                ui.weak(format!(
                    "Categories: {}",
                    if technology.category_names.is_empty() {
                        "Uncategorized".to_owned()
                    } else {
                        technology.category_names.join(", ")
                    }
                ));
                show_evidence_disclosure(
                    ui,
                    (
                        "web-technology-evidence",
                        endpoint.ip,
                        endpoint.port,
                        &technology.name,
                        &technology.version,
                    ),
                    &technology.evidence_urls,
                    &technology.evidence,
                );
            }
        }
    }
    ui.separator();
    show_detected_language_file_types(ui, report);
    ui.separator();
    ui.heading("Servers, Frameworks, Plugins, Runtimes, and Packages");
    let mut components_found = false;
    for endpoint in open_endpoints(report) {
        for component in &endpoint.technology_components {
            components_found = true;
            ui.label(format!(
                "{}: {} {} — {} — latest stable {}",
                component.kind,
                component.name,
                component
                    .installed_version
                    .as_deref()
                    .unwrap_or("(version not observed)"),
                component.status,
                component.latest_version.as_deref().unwrap_or("not checked")
            ));
            ui.weak(format!(
                "{}; {} confidence{}{}",
                component.ecosystem,
                component.confidence,
                component
                    .package_identifier
                    .as_deref()
                    .map(|package| format!("; registry identifier: {package}"))
                    .unwrap_or_default(),
                if component.support_status == crate::TechnologySupportStatus::NotApplicable {
                    String::new()
                } else {
                    format!("; lifecycle: {}", component.support_status)
                }
            ));
            if let Some(source) = &component.release_source_url {
                ui.hyperlink_to("Upstream release/lifecycle source", source);
            }
            show_evidence_disclosure(
                ui,
                (
                    "technology-component-evidence",
                    endpoint.ip,
                    endpoint.port,
                    component.ecosystem,
                    component.kind,
                    &component.name,
                    &component.package_identifier,
                    &component.installed_version,
                ),
                &component.evidence_urls,
                &component.evidence,
            );
            if let Some(error) = &component.check_error {
                ui.weak(format!("Version check: {error}"));
            }
        }
    }
    if !components_found {
        ui.weak("No servers, frameworks, plugins, runtimes, or packages were identified.");
    }
    ui.separator();
    ui.heading("JavaScript Sources");
    let mut found = false;
    for endpoint in open_endpoints(report) {
        for source in &endpoint.javascript_sources {
            found = true;
            ui.separator();
            egui::CollapsingHeader::new(egui::RichText::new(&source.source_url).strong())
                .id_salt((endpoint.ip, endpoint.port, &source.source_url))
                .default_open(false)
                .show(ui, |ui| {
                    ui.weak(format!("Endpoint: {}:{}", endpoint.ip, endpoint.port));
                    if let Some(final_url) = source
                        .final_url
                        .as_deref()
                        .filter(|final_url| *final_url != source.source_url)
                    {
                        ui.label(format!("Final URL: {final_url}"));
                    }
                    if let Some(status) = source.http_status {
                        ui.label(format!(
                            "HTTP {} {} — {} bytes{}",
                            status,
                            source.http_reason.as_deref().unwrap_or_default(),
                            source.captured_size,
                            if source.truncated { " (truncated)" } else { "" }
                        ));
                    }
                    if let Some(hash) = &source.sha256 {
                        ui.weak(format!("SHA-256: {hash}"));
                    }
                    if let Some(error) = &source.retrieval_error {
                        ui.colored_label(egui::Color32::YELLOW, format!("Retrieval: {error}"));
                    }
                    if let Some(error) = &source.analysis_error {
                        ui.colored_label(egui::Color32::YELLOW, format!("Analysis: {error}"));
                    }
                    if source.libraries.is_empty() && source.retrieval_error.is_none() {
                        ui.weak("No JavaScript library or version signature matched this source");
                    }
                    for library in &source.libraries {
                        ui.label(format!(
                            "{} {} — {} — npm newest stable {}",
                            library.name,
                            library
                                .installed_version
                                .as_deref()
                                .unwrap_or("version unknown"),
                            library.status,
                            library.latest_version.as_deref().unwrap_or("not checked")
                        ));
                        if let Some(package) = &library.npm_package {
                            ui.weak(format!("npm package: {package}"));
                        }
                        show_evidence_disclosure(
                            ui,
                            (
                                "javascript-library-evidence",
                                endpoint.ip,
                                endpoint.port,
                                &source.source_url,
                                &library.name,
                                &library.npm_package,
                                &library.installed_version,
                            ),
                            &[],
                            &library.evidence,
                        );
                        if let Some(error) = &library.check_error {
                            ui.weak(format!("Version check: {error}"));
                        }
                    }
                });
        }
    }
    if !found {
        ui.weak("No HTTP(S) script sources were discovered on root pages or during crawling.");
    }
}

fn show_technology_inventory(ui: &mut egui::Ui, report: &ExposureScanReport) {
    let mut web_technologies = BTreeSet::new();
    let languages = detected_languages_and_file_types(report);
    let mut components = BTreeSet::new();
    let mut libraries = BTreeSet::new();

    for endpoint in open_endpoints(report) {
        for technology in &endpoint.web_technologies {
            web_technologies.insert(format!(
                "{} {} — {} confidence",
                technology.name,
                technology
                    .version
                    .as_deref()
                    .unwrap_or("(version not observed)"),
                technology.confidence
            ));
        }
        for component in &endpoint.technology_components {
            components.insert(format!(
                "{}: {} {} — {}",
                component.kind,
                component.name,
                component
                    .installed_version
                    .as_deref()
                    .unwrap_or("(version not observed)"),
                component.status
            ));
        }
        for source in &endpoint.javascript_sources {
            for library in &source.libraries {
                libraries.insert(format!(
                    "{} {} — {}",
                    library.name,
                    library
                        .installed_version
                        .as_deref()
                        .unwrap_or("(version not observed)"),
                    library.status
                ));
            }
        }
    }

    ui.heading("Concise Inventory");
    if web_technologies.is_empty()
        && languages.is_empty()
        && components.is_empty()
        && libraries.is_empty()
    {
        ui.weak("No technologies, file types, components, or JavaScript libraries were detected.");
        return;
    }

    if !web_technologies.is_empty() {
        egui::CollapsingHeader::new(egui::RichText::new("Web Technologies").strong())
            .id_salt("technology-inventory-web-technologies")
            .default_open(true)
            .show(ui, |ui| {
                for entry in &web_technologies {
                    ui.label(format!("• {entry}"));
                }
            });
    }

    if !languages.is_empty() {
        egui::CollapsingHeader::new(egui::RichText::new("Languages / File Types").strong())
            .id_salt("technology-inventory-file-types")
            .default_open(true)
            .show(ui, |ui| {
                for (language, detection) in &languages {
                    ui.label(format!(
                        "• {}",
                        language_detection_label(language, detection)
                    ));
                }
            });
    }

    if !components.is_empty() || !libraries.is_empty() {
        egui::CollapsingHeader::new(egui::RichText::new("Components and Packages").strong())
            .id_salt("technology-inventory-components-and-packages")
            .default_open(false)
            .show(ui, |ui| {
                if !components.is_empty() {
                    ui.strong("Components");
                    for entry in &components {
                        ui.label(format!("• {entry}"));
                    }
                }

                if !libraries.is_empty() {
                    ui.strong("JavaScript Libraries");
                    for entry in &libraries {
                        ui.label(format!("• {entry}"));
                    }
                }
            });
    }
}

#[derive(Default)]
struct LanguageDetection {
    confidence: Confidence,
    runtime_confidence: Confidence,
    file_types: BTreeMap<crate::TechnologyFileType, Confidence>,
}

fn detected_languages_and_file_types(
    report: &ExposureScanReport,
) -> BTreeMap<&'static str, LanguageDetection> {
    let mut languages = BTreeMap::<&'static str, LanguageDetection>::new();
    for item in report
        .crawled_resources
        .iter()
        .flat_map(|resource| &resource.detected_file_types)
        .filter(|item| item.file_type != crate::TechnologyFileType::JavaScript)
    {
        let detection = languages.entry(item.file_type.language()).or_default();
        detection.confidence = detection.confidence.max(item.confidence);
        detection
            .file_types
            .entry(item.file_type)
            .and_modify(|confidence| *confidence = (*confidence).max(item.confidence))
            .or_insert(item.confidence);
    }
    for component in report
        .endpoints
        .iter()
        .flat_map(|endpoint| &endpoint.technology_components)
        .filter(|component| component.kind == TechnologyComponentKind::Runtime)
    {
        let Some(language) = runtime_language(&component.name) else {
            continue;
        };
        let detection = languages.entry(language).or_default();
        detection.confidence = detection.confidence.max(component.confidence);
        detection.runtime_confidence = detection.runtime_confidence.max(component.confidence);
    }
    languages
}

fn runtime_language(runtime: &str) -> Option<&'static str> {
    if runtime.eq_ignore_ascii_case("php") {
        Some("PHP")
    } else if runtime.eq_ignore_ascii_case("python") {
        Some("Python")
    } else if runtime.eq_ignore_ascii_case("ruby") {
        Some("Ruby")
    } else if runtime.eq_ignore_ascii_case("java") || runtime.eq_ignore_ascii_case("jvm") {
        Some("JVM")
    } else if runtime.eq_ignore_ascii_case(".net") || runtime.eq_ignore_ascii_case("dotnet") {
        Some(".NET")
    } else if runtime.eq_ignore_ascii_case("go") {
        Some("Go")
    } else if runtime.eq_ignore_ascii_case("rust") {
        Some("Rust")
    } else if runtime.eq_ignore_ascii_case("elixir") {
        Some("Elixir")
    } else if runtime.eq_ignore_ascii_case("erlang") {
        Some("Erlang")
    } else if runtime.eq_ignore_ascii_case("haskell") {
        Some("Haskell")
    } else {
        None
    }
}

fn language_detection_label(language: &str, detection: &LanguageDetection) -> String {
    let mut details = Vec::new();
    if detection.runtime_confidence != Confidence::None {
        details.push(format!(
            "runtime evidence: {} confidence",
            detection.runtime_confidence
        ));
    }
    if !detection.file_types.is_empty() {
        details.push(format!(
            "file types: {}",
            detection
                .file_types
                .iter()
                .map(|(file_type, confidence)| {
                    format!("{file_type} — {confidence} confidence")
                })
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    format!(
        "{language} — {} confidence ({})",
        detection.confidence,
        details.join("; ")
    )
}

fn show_detected_language_file_types(ui: &mut egui::Ui, report: &ExposureScanReport) {
    ui.heading("Languages / File Types");
    let detected = detected_languages_and_file_types(report);
    if detected.is_empty() {
        ui.weak("No supported backend languages or remotely observable file types were detected.");
        return;
    }

    for (language, detection) in detected {
        ui.label(language_detection_label(language, &detection));
    }
}

fn show_dns_observation(ui: &mut egui::Ui, observation: &crate::DnsObservation) {
    ui.separator();
    ui.strong(format!(
        "{} — {} — {}",
        observation.subject, observation.check, observation.status
    ));
    ui.label(&observation.summary);
    for evidence in &observation.evidence {
        ui.weak(evidence);
    }
}

fn show_security_summary(ui: &mut egui::Ui, report: &ExposureScanReport) {
    let grouped_findings = confirmed_finding_groups(&report.findings);
    let collapsed_findings = grouped_findings
        .iter()
        .filter(|finding| finding.collapsed)
        .collect::<Vec<_>>();
    let prominent_findings = grouped_findings
        .iter()
        .filter(|finding| !finding.collapsed)
        .collect::<Vec<_>>();
    show_security_checks(ui, report);
    ui.separator();
    ui.heading(format!("Confirmed Findings ({})", grouped_findings.len()));
    if grouped_findings.is_empty() {
        ui.weak("No confirmed security findings were observed by the bounded checks.");
    } else if prominent_findings.is_empty() {
        ui.weak("No prominent confirmed findings were observed; outdated packages and plugins are listed below.");
    } else {
        for finding in prominent_findings {
            show_confirmed_finding(ui, finding);
        }
    }

    let dns_warnings = report
        .dns_observations
        .iter()
        .filter(|observation| observation.status == crate::DnsObservationStatus::Warning)
        .collect::<Vec<_>>();
    if !dns_warnings.is_empty() {
        ui.separator();
        ui.heading(format!("DNS Posture ({})", dns_warnings.len()));
        for observation in dns_warnings {
            show_dns_observation(ui, observation);
        }
    }

    let mut exposed_services = open_endpoints(report)
        .filter(|endpoint| !matches!(endpoint.service, ServiceKind::Http | ServiceKind::Https))
        .collect::<Vec<_>>();
    exposed_services.sort_by(|left, right| left.ip.cmp(&right.ip).then(left.port.cmp(&right.port)));
    if !exposed_services.is_empty() {
        ui.separator();
        ui.heading(format!(
            "Publicly Exposed Services ({})",
            exposed_services.len()
        ));
        for endpoint in exposed_services {
            ui.label(format!(
                "{}:{} — {}",
                endpoint.ip,
                endpoint.port,
                exposed_service_label(endpoint)
            ));
        }
    }

    let mut surfaces = open_endpoints(report)
        .flat_map(|endpoint| {
            endpoint
                .observed_web_surfaces
                .iter()
                .map(move |surface| (endpoint, surface))
        })
        .collect::<Vec<_>>();
    surfaces.sort_by(|(left_endpoint, left), (right_endpoint, right)| {
        left_endpoint
            .ip
            .cmp(&right_endpoint.ip)
            .then(left_endpoint.port.cmp(&right_endpoint.port))
            .then(left.url.cmp(&right.url))
            .then(left.surface_type.cmp(&right.surface_type))
    });
    let crawl_surfaces = report
        .crawl_observed_web_surfaces
        .iter()
        .filter(|surface| {
            !(surface.surface_type == crate::WebSurfaceType::Login
                && (300..400).contains(&surface.status)
                && surface
                    .evidence
                    .iter()
                    .any(|evidence| evidence.starts_with("authentication redirect to ")))
        })
        .collect::<Vec<_>>();
    if !surfaces.is_empty() || !crawl_surfaces.is_empty() {
        ui.separator();
        ui.heading(format!(
            "Observed Web Surfaces ({})",
            surfaces.len() + crawl_surfaces.len()
        ));
        for (endpoint, surface) in surfaces {
            ui.strong(format!(
                "{} {} — {} — HTTP {} — {} confidence",
                surface.technology,
                surface.surface_type,
                surface.url,
                surface.status,
                surface.confidence
            ));
            ui.weak(format!(
                "Scanned endpoint: {}:{}",
                endpoint.ip, endpoint.port
            ));
            for evidence in &surface.evidence {
                ui.weak(format!("Evidence: {evidence}"));
            }
        }
        for surface in crawl_surfaces {
            ui.strong(format!(
                "{} — {} — HTTP {} — {} confidence",
                surface.surface_type, surface.url, surface.status, surface.confidence
            ));
            ui.weak(format!(
                "Scanned endpoint: {}:{} — anonymous crawl observation",
                surface.ip, surface.port
            ));
            for evidence in &surface.evidence {
                ui.weak(format!("Evidence: {evidence}"));
            }
        }
    }

    if !report.crawl_contacts.is_empty() {
        ui.separator();
        egui::CollapsingHeader::new(format!("Public Contacts ({})", report.crawl_contacts.len()))
            .default_open(false)
            .show(ui, |ui| {
                for (contact_type, heading) in [
                    (CrawlContactType::Email, "Email addresses"),
                    (CrawlContactType::Telephone, "Telephone numbers"),
                ] {
                    let contacts = report
                        .crawl_contacts
                        .iter()
                        .filter(|contact| contact.contact_type == contact_type)
                        .collect::<Vec<_>>();
                    if contacts.is_empty() {
                        continue;
                    }
                    ui.strong(heading);
                    for contact in contacts {
                        ui.label(format!(
                            "{} — {}",
                            contact.value,
                            contact.endpoints.join(", ")
                        ));
                    }
                }
            });
    }
    if !collapsed_findings.is_empty() {
        ui.separator();
        egui::CollapsingHeader::new(format!(
            "Outdated Components ({})",
            collapsed_findings.len()
        ))
        .default_open(false)
        .show(ui, |ui| {
            for finding in collapsed_findings {
                show_confirmed_finding(ui, finding);
            }
        });
    }
}

fn show_security_checks(ui: &mut egui::Ui, report: &ExposureScanReport) {
    let grouped_checks = grouped_security_checks(&report.security_checks);
    if grouped_checks.is_empty() {
        return;
    }
    let vulnerable = grouped_checks
        .iter()
        .filter(|group| group.check.outcome == crate::CheckOutcome::Vulnerable)
        .count();
    let potential = grouped_checks.len() - vulnerable;
    ui.separator();
    ui.heading(format!("Security Checks ({})", grouped_checks.len()));
    ui.weak(format!("{vulnerable} vulnerable • {potential} potential"));
    egui::CollapsingHeader::new("Check details")
        .default_open(true)
        .show(ui, |ui| {
            for group in grouped_checks {
                let check = group.check;
                ui.separator();
                ui.strong(format!(
                    "{} — {} — {}",
                    check.outcome, check.title, check.class
                ));
                if group.endpoints.len() == 1
                    && group
                        .endpoints
                        .values()
                        .next()
                        .is_some_and(|ports| ports.len() == 1)
                {
                    ui.label(format!(
                        "Endpoint: {}:{} • Severity: {} • Confidence: {} • ID: {}",
                        check.ip, check.port, check.severity, check.confidence, check.check_id
                    ));
                } else {
                    ui.label(format!(
                        "Endpoints: {}",
                        security_check_endpoint_summary(&group.endpoints)
                    ));
                    ui.label(format!(
                        "Severity: {} • Confidence: {} • ID: {}",
                        check.severity, check.confidence, check.check_id
                    ));
                }
                if let Some(url) = &check.probe_url {
                    ui.label(format!("Probe URL: {url}"));
                }
                if let Some(request) = &check.request_evidence {
                    ui.weak(format!("Request: {request}"));
                }
                for evidence in &check.evidence {
                    ui.weak(format!("Evidence: {evidence}"));
                }
                if let Some(reason) = &check.reason {
                    ui.weak(format!("Qualification: {reason}"));
                }
            }
        });
}

struct SecurityCheckGroup<'a> {
    check: &'a crate::SecurityCheckResult,
    endpoints: BTreeMap<std::net::IpAddr, BTreeSet<u16>>,
}

fn grouped_security_checks(checks: &[crate::SecurityCheckResult]) -> Vec<SecurityCheckGroup<'_>> {
    let mut groups = Vec::<SecurityCheckGroup<'_>>::new();
    for check in checks.iter().filter(|check| {
        matches!(
            check.outcome,
            crate::CheckOutcome::Vulnerable | crate::CheckOutcome::Potential
        )
    }) {
        let group = groups
            .iter_mut()
            .find(|group| equivalent_security_checks(group.check, check));
        if let Some(group) = group {
            group
                .endpoints
                .entry(check.ip)
                .or_default()
                .insert(check.port);
        } else {
            groups.push(SecurityCheckGroup {
                check,
                endpoints: BTreeMap::from([(check.ip, BTreeSet::from([check.port]))]),
            });
        }
    }
    groups
}

fn equivalent_security_checks(
    left: &crate::SecurityCheckResult,
    right: &crate::SecurityCheckResult,
) -> bool {
    left.check_id == right.check_id
        && left.class == right.class
        && left.title == right.title
        && left.severity == right.severity
        && left.confidence == right.confidence
        && left.outcome == right.outcome
        && left.probe_url == right.probe_url
        && left.request_evidence == right.request_evidence
        && left.evidence == right.evidence
        && left.reason == right.reason
}

fn security_check_endpoint_summary(
    endpoints: &BTreeMap<std::net::IpAddr, BTreeSet<u16>>,
) -> String {
    endpoints
        .iter()
        .map(|(ip, ports)| {
            let port_label = if ports.len() == 1 { "port" } else { "ports" };
            let ports = ports
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            format!("{ip} — {port_label}: {ports}")
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn show_confirmed_finding(ui: &mut egui::Ui, finding: &ConfirmedFindingGroup<'_>) {
    ui.separator();
    ui.strong(finding.title);
    ui.label(finding.description);
    ui.label(confirmed_finding_endpoint(finding));
    if finding.title == "Browser security headers are missing" {
        show_missing_browser_header_evidence(ui, &finding.evidence);
    } else {
        for evidence in &finding.evidence {
            ui.weak(format!("Evidence: {evidence}"));
        }
        if finding.title == "TLS certificate chain or key weakness" {
            ui.weak("Remediation: Serve a complete, correctly ordered leaf and intermediate certificate chain with server-auth usage; reissue weak certificates using SHA-256 or stronger signatures and at least RSA-2048 or ECDSA P-256 keys.");
        }
    }
}

fn confirmed_finding_endpoint(finding: &ConfirmedFindingGroup<'_>) -> String {
    let endpoints = finding
        .endpoints
        .iter()
        .map(|(transport, ports)| {
            let port_label = if ports.len() == 1 { "port" } else { "ports" };
            let ports = ports
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            format!("{transport} {port_label}: {ports}")
        })
        .collect::<Vec<_>>()
        .join("; ");
    format!("Endpoint: {} — {endpoints}", finding.ip)
}

fn show_missing_browser_header_evidence(ui: &mut egui::Ui, evidence: &[&str]) {
    let mut groups = BTreeMap::<Vec<String>, (Option<&str>, Option<&str>, usize)>::new();
    let mut ungrouped = Vec::new();
    for &value in evidence {
        let Some((headers, page)) = missing_browser_header_set(value) else {
            ungrouped.push(value);
            continue;
        };
        let group = groups.entry(headers).or_default();
        if page {
            group.0.get_or_insert(value);
            group.2 += 1;
        } else {
            group.1.get_or_insert(value);
        }
    }
    for (_, (page_evidence, generic_evidence, page_count)) in groups {
        if let Some(value) = page_evidence {
            let page_label = if page_count == 1 { "page" } else { "pages" };
            ui.weak(format!(
                "Evidence: {value} ({page_count} {page_label} with this header set)"
            ));
        } else if let Some(value) = generic_evidence {
            ui.weak(format!("Evidence: {value}"));
        }
    }
    for value in ungrouped {
        ui.weak(format!("Evidence: {value}"));
    }
}

fn missing_browser_header_set(evidence: &str) -> Option<(Vec<String>, bool)> {
    let (headers, page) = if let Some(headers) = evidence.strip_prefix("Missing: ") {
        (headers, false)
    } else {
        let (_, headers) = evidence.rsplit_once(" missing ")?;
        (headers, true)
    };
    let mut headers = headers
        .split(',')
        .map(str::trim)
        .filter(|header| !header.is_empty())
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>();
    if headers.is_empty() {
        return None;
    }
    headers.sort();
    headers.dedup();
    Some((headers, page))
}

fn exposed_service_label(endpoint: &EndpointScan) -> String {
    if endpoint.service != ServiceKind::Unknown {
        return endpoint.service.to_string();
    }
    if endpoint.service_confidence == Confidence::Low
        && let Some(metadata) = curated_tcp_port_metadata(endpoint.port)
    {
        return format!("{} (unconfirmed)", metadata.service_name);
    }
    "Unknown service".to_owned()
}

fn state_count(report: &ExposureScanReport, state: PortState) -> usize {
    report
        .endpoints
        .iter()
        .filter(|endpoint| endpoint.state == state)
        .count()
}

fn open_endpoints(report: &ExposureScanReport) -> impl Iterator<Item = &EndpointScan> {
    report
        .endpoints
        .iter()
        .filter(|endpoint| endpoint.state == PortState::Open)
}

fn row(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.strong(label);
    ui.label(if value.is_empty() { "None" } else { value });
    ui.end_row();
}
