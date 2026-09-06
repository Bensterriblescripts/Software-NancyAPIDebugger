use super::*;
use crate::EndpointHealthResolution;
use crate::UdpEndpointState;
use crate::diagnostics::TraceOutcome;
use crate::product_catalog::inventory_product_name;
use crate::{ExposureFinding, TechnologyComponentKind, TransportProtocol};

fn show_technology_component_details(
    ui: &mut egui::Ui,
    endpoint: &EndpointScan,
    component: &crate::TechnologyComponent,
) {
    ui.label(format!(
        "{} — {} confidence — {}:{}",
        component.installed_version.as_deref().unwrap_or("version not observed"),
        component.confidence,
        endpoint.ip,
        endpoint.port
    ));
    ui.weak(format!(
        "{} — latest stable {}",
        component.status,
        component.latest_version.as_deref().unwrap_or("not checked")
    ));
    ui.weak(format!(
        "{}; {}{}{}",
        component.kind,
        component.ecosystem,
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
    let count = component.evidence_urls.len() + component.evidence.len();
    if count > 0 {
        egui::CollapsingHeader::new(format!("Evidence ({count})"))
            .id_salt((
                "technology-component-evidence",
                endpoint.ip,
                endpoint.port,
                component.ecosystem,
                component.kind,
                &component.name,
                &component.package_identifier,
                &component.installed_version,
            ))
            .default_open(false)
            .show(ui, |ui| {
                for url in &component.evidence_urls {
                    ui.weak(format!("Evidence URL: {url}"));
                }
                for item in &component.evidence {
                    ui.weak(format!("Evidence: {item}"));
                }
            });
    }
    if let Some(error) = &component.check_error {
        ui.weak(format!("Version check: {error}"));
    }
}

pub(in crate::ui) fn show_report(
    ui: &mut egui::Ui,
    report: &ExposureScanReport,
    tab: ExposureDetailTab,
    diagnostic_view: &mut DiagnosticViewState,
) {
    egui::ScrollArea::vertical().show(ui, |ui| match tab {
        ExposureDetailTab::Summary => {
            ({
let (ui, report,): (& mut egui :: Ui, & ExposureScanReport,) = (ui, report,);

    ui.heading("Public Exposure Summary");
    egui::Grid::new("exposure_summary")
        .striped(true)
        .show(ui, |ui| {
            ({
let (ui, label, value,): (& mut egui :: Ui, & str, & str,) = (ui, "Target", &report.request.diagnostic_request.url,);

    ui.strong(label);
    ui.label(if value.is_empty() { "None" } else { value });
    ui.end_row();

});
            ({
let (ui, label, value,): (& mut egui :: Ui, & str, & str,) = (ui, "Hostname / SNI", &report.hostname,);

    ui.strong(label);
    ui.label(if value.is_empty() { "None" } else { value });
    ui.end_row();

});
            ({
let (ui, label, value,): (& mut egui :: Ui, & str, & str,) = (ui, "Status", &report.status.to_string(),);

    ui.strong(label);
    ui.label(if value.is_empty() { "None" } else { value });
    ui.end_row();

});
            ({
let (ui, label, value,): (& mut egui :: Ui, & str, & str,) = (ui, "Public IPv4 addresses", &report
                    .resolved_addresses
                    .iter()
                    .filter(|address| address.is_ipv4())
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", "),);

    ui.strong(label);
    ui.label(if value.is_empty() { "None" } else { value });
    ui.end_row();

});
            ({
let (ui, label, value,): (& mut egui :: Ui, & str, & str,) = (ui, "Public IPv6 addresses", &report
                    .resolved_addresses
                    .iter()
                    .filter(|address| address.is_ipv6())
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", "),);

    ui.strong(label);
    ui.label(if value.is_empty() { "None" } else { value });
    ui.end_row();

});
            ({
let (ui, label, value,): (& mut egui :: Ui, & str, & str,) = (ui, "Open endpoints", &({
let (report, state,): (& ExposureScanReport, PortState,) = (report, PortState::Open,);
let inlined_result: usize = {

    report
        .endpoints
        .iter()
        .filter(|endpoint| endpoint.state == state)
        .count()

};
inlined_result
}).to_string(),);

    ui.strong(label);
    ui.label(if value.is_empty() { "None" } else { value });
    ui.end_row();

});
            ({
let (ui, label, value,): (& mut egui :: Ui, & str, & str,) = (ui, "Security Summary", &({
let (findings,): (& [ExposureFinding],) = (&report.findings,);
let inlined_result: usize = {

    findings
        .iter()
        .map(|finding| {
let (title,): (& str,) = (&finding.title,);
let inlined_result: & str = {

    match title {
        "Session-like cookie attributes are missing"
        | "Security-sensitive cookie lacks Secure"
        | "Security-sensitive cookie lacks HttpOnly"
        | "Security-sensitive cookie lacks SameSite" => "Cookie security attributes are missing",
        _ => title,
    }

};
inlined_result
})
        .collect::<BTreeSet<_>>()
        .len()

};
inlined_result
}).to_string(),);

    ui.strong(label);
    ui.label(if value.is_empty() { "None" } else { value });
    ui.end_row();

});
            ({
let (ui, label, value,): (& mut egui :: Ui, & str, & str,) = (ui, "Total time", &format!("{:.2} s", report.timings.total_ms / 1_000.0),);

    ui.strong(label);
    ui.label(if value.is_empty() { "None" } else { value });
    ui.end_row();

});
        });
    if let Some(error) = &report.error {
        ui.colored_label(egui::Color32::RED, error);
    }
    for warning in &report.warnings {
        ui.colored_label(egui::Color32::YELLOW, warning);
    }
    if !report.endpoint_health.is_empty() {
        ui.separator();
        ui.heading("Request blocking / availability");
        if report
            .endpoint_health
            .iter()
            .any(|observation| observation.resolution == EndpointHealthResolution::Stopped)
        {
            ui.colored_label(egui::Color32::YELLOW, "Partial coverage: remaining probes were skipped on affected endpoints. Other endpoints continued.");
        }
        for observation in &report.endpoint_health {
            ui.add_space(6.0);
            ui.strong(format!(
                "{} ({})",
                std::net::SocketAddr::new(observation.ip, observation.port),
                observation.transport
            ));
            ui.label(&observation.detail);
            ui.label(format!(
                "From monitored attempt #{} at {:.1} s: {} timed out, {} rejected",
                observation.request_number,
                observation.elapsed_ms / 1000.0,
                observation.timeouts,
                observation.rejections,
            ));
            if !observation.had_baseline {
                ui.weak(
                    "No previously working safe baseline; a mid-scan block cannot be established.",
                );
            }
            for check in &observation.connectivity {
                ui.label(format!("{}: {}", check.label, check.detail));
            }
            for retry in &observation.retries {
                ui.label(retry);
            }
        }
    }
    let attempted: Vec<_> = report
        .endpoints
        .iter()
        .filter(|endpoint| endpoint.attempted)
        .collect();
    if !attempted.is_empty()
        && attempted
            .iter()
            .all(|endpoint| endpoint.state == PortState::FilteredOrNoResponse)
    {
        ui.colored_label(egui::Color32::YELLOW, "All attempted TCP endpoints timed out or gave no response. No working baseline was established; filtering versus unavailability is inconclusive.");
    }

});
            ui.separator();
            ({
let (ui, report,): (& mut egui :: Ui, & ExposureScanReport,) = (ui, report,);

    let products = {
let (report,): (& ExposureScanReport,) = (report,);
let inlined_result: Vec < DiagnosticProduct > = {

    let mut products = BTreeMap::new();
    for endpoint in &report.endpoints {
        for product in &endpoint.products {
            ({
let (products, name, version, confidence, details,): (& mut BTreeMap < String , DiagnosticProduct >, & str, Option < & str >, Confidence, _,) = (&mut products, &product.name, product.version.as_deref(), product.confidence, product.evidence.clone(),);
'inlined_add_inventory_product: {

    let Some(name) = inventory_product_name(name) else {
        break 'inlined_add_inventory_product;
    };
    if confidence == Confidence::None {
        break 'inlined_add_inventory_product;
    }
    let product = products
        .entry(name.to_ascii_lowercase())
        .or_insert_with(|| DiagnosticProduct {
            name: name.to_owned(),
            versions: BTreeMap::new(),
            confidence,
            details: BTreeSet::new(),
        });
    if name < product.name.as_str() {
        product.name = name.to_owned();
    }
    if let Some(version) = version.filter(|version| !version.trim().is_empty()) {
        product
            .versions
            .entry(version.to_owned())
            .and_modify(|current| *current = (*current).max(confidence))
            .or_insert(confidence);
    }
    product.confidence = product.confidence.max(confidence);
    product.details.extend(details);

}
});
        }
        for technology in &endpoint.web_technologies {
            ({
let (products, name, version, confidence, details,): (& mut BTreeMap < String , DiagnosticProduct >, & str, Option < & str >, Confidence, _,) = (&mut products, &technology.name, technology.version.as_deref(), technology.confidence, technology
                    .evidence
                    .iter()
                    .chain(&technology.evidence_urls)
                    .cloned(),);
'inlined_add_inventory_product: {

    let Some(name) = inventory_product_name(name) else {
        break 'inlined_add_inventory_product;
    };
    if confidence == Confidence::None {
        break 'inlined_add_inventory_product;
    }
    let product = products
        .entry(name.to_ascii_lowercase())
        .or_insert_with(|| DiagnosticProduct {
            name: name.to_owned(),
            versions: BTreeMap::new(),
            confidence,
            details: BTreeSet::new(),
        });
    if name < product.name.as_str() {
        product.name = name.to_owned();
    }
    if let Some(version) = version.filter(|version| !version.trim().is_empty()) {
        product
            .versions
            .entry(version.to_owned())
            .and_modify(|current| *current = (*current).max(confidence))
            .or_insert(confidence);
    }
    product.confidence = product.confidence.max(confidence);
    product.details.extend(details);

}
});
        }
        for component in &endpoint.technology_components {
            ({
let (products, name, version, confidence, details,): (& mut BTreeMap < String , DiagnosticProduct >, & str, Option < & str >, Confidence, _,) = (&mut products, &component.name, component.installed_version.as_deref(), component.confidence, component
                    .evidence
                    .iter()
                    .chain(&component.evidence_urls)
                    .cloned(),);
'inlined_add_inventory_product: {

    let Some(name) = inventory_product_name(name) else {
        break 'inlined_add_inventory_product;
    };
    if confidence == Confidence::None {
        break 'inlined_add_inventory_product;
    }
    let product = products
        .entry(name.to_ascii_lowercase())
        .or_insert_with(|| DiagnosticProduct {
            name: name.to_owned(),
            versions: BTreeMap::new(),
            confidence,
            details: BTreeSet::new(),
        });
    if name < product.name.as_str() {
        product.name = name.to_owned();
    }
    if let Some(version) = version.filter(|version| !version.trim().is_empty()) {
        product
            .versions
            .entry(version.to_owned())
            .and_modify(|current| *current = (*current).max(confidence))
            .or_insert(confidence);
    }
    product.confidence = product.confidence.max(confidence);
    product.details.extend(details);

}
});
        }
        for source in &endpoint.javascript_sources {
            for library in &source.libraries {
                ({
let (products, name, version, confidence, details,): (& mut BTreeMap < String , DiagnosticProduct >, & str, Option < & str >, Confidence, _,) = (&mut products, &library.name, library.installed_version.as_deref(), Confidence::Medium, library
                        .evidence
                        .iter()
                        .chain(std::iter::once(&source.source_url))
                        .cloned(),);
'inlined_add_inventory_product: {

    let Some(name) = inventory_product_name(name) else {
        break 'inlined_add_inventory_product;
    };
    if confidence == Confidence::None {
        break 'inlined_add_inventory_product;
    }
    let product = products
        .entry(name.to_ascii_lowercase())
        .or_insert_with(|| DiagnosticProduct {
            name: name.to_owned(),
            versions: BTreeMap::new(),
            confidence,
            details: BTreeSet::new(),
        });
    if name < product.name.as_str() {
        product.name = name.to_owned();
    }
    if let Some(version) = version.filter(|version| !version.trim().is_empty()) {
        product
            .versions
            .entry(version.to_owned())
            .and_modify(|current| *current = (*current).max(confidence))
            .or_insert(confidence);
    }
    product.confidence = product.confidence.max(confidence);
    product.details.extend(details);

}
});
            }
        }
    }
    for (language, detection) in {
let (report,): (& ExposureScanReport,) = (report,);
let inlined_result: BTreeMap < & 'static str , LanguageDetection > = {

    let mut languages = BTreeMap::<&'static str, LanguageDetection>::new();
    for resource in &report.crawled_resources {
        for item in resource
            .detected_file_types
            .iter()
            .filter(|item| item.file_type != crate::TechnologyFileType::JavaScript)
        {
            let detection = languages.entry(item.file_type.language()).or_default();
            detection.confidence = detection.confidence.max(item.confidence);
            detection
                .file_types
                .entry(item.file_type)
                .and_modify(|confidence| *confidence = (*confidence).max(item.confidence))
                .or_insert(item.confidence);
            detection.evidence_urls.push(resource.url.clone());
            detection.evidence.extend(item.evidence.iter().cloned());
        }
    }
    for component in report
        .endpoints
        .iter()
        .flat_map(|endpoint| &endpoint.technology_components)
        .filter(|component| component.kind == TechnologyComponentKind::Runtime)
    {
        let Some(language) = ({
let (runtime,): (& str,) = (&component.name,);
{

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

}) else {
            continue;
        };
        let detection = languages.entry(language).or_default();
        detection.confidence = detection.confidence.max(component.confidence);
        detection.runtime_confidence = detection.runtime_confidence.max(component.confidence);
        detection
            .evidence_urls
            .extend(component.evidence_urls.iter().cloned());
        detection.evidence.extend(component.evidence.iter().cloned());
    }
    for detection in languages.values_mut() {
        detection.evidence_urls.sort();
        detection.evidence_urls.dedup();
        detection.evidence.sort();
        detection.evidence.dedup();
    }
    languages

};
inlined_result
} {
        ({
let (products, name, version, confidence, details,): (& mut BTreeMap < String , DiagnosticProduct >, & str, Option < & str >, Confidence, _,) = (&mut products, language, None, detection.confidence, [({
let (language, detection,): (& str, & LanguageDetection,) = (language, &detection,);
let inlined_result: String = {

    format!(
        "{language} — {} confidence ({})",
        detection.confidence,
        ({
let (detection,): (& LanguageDetection,) = (detection,);
let inlined_result: String = {

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
    details.join("; ")

};
inlined_result
})
    )

};
inlined_result
})],);
'inlined_add_inventory_product: {

    let Some(name) = inventory_product_name(name) else {
        break 'inlined_add_inventory_product;
    };
    if confidence == Confidence::None {
        break 'inlined_add_inventory_product;
    }
    let product = products
        .entry(name.to_ascii_lowercase())
        .or_insert_with(|| DiagnosticProduct {
            name: name.to_owned(),
            versions: BTreeMap::new(),
            confidence,
            details: BTreeSet::new(),
        });
    if name < product.name.as_str() {
        product.name = name.to_owned();
    }
    if let Some(version) = version.filter(|version| !version.trim().is_empty()) {
        product
            .versions
            .entry(version.to_owned())
            .and_modify(|current| *current = (*current).max(confidence))
            .or_insert(confidence);
    }
    product.confidence = product.confidence.max(confidence);
    product.details.extend(details);

}
});
    }
    products.into_values().collect()

};
inlined_result
};
    for (heading, confirmed) in [("Confirmed", true), ("Possible", false)] {
        ui.heading(heading);
        ui.horizontal_wrapped(|ui| {
            let mut found = false;
            for product in products
                .iter()
                .filter(|product| (product.confidence >= Confidence::Medium) == confirmed)
            {
                if found {
                    ui.weak("·");
                }
                found = true;
                let versions = product
                    .versions
                    .iter()
                    .filter(|(_, confidence)| !confirmed || **confidence >= Confidence::Medium)
                    .map(|(version, _)| version.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                let label = if versions.is_empty() {
                    product.name.clone()
                } else {
                    format!("{} {versions}", product.name)
                };
                ui.weak(label).on_hover_text(format!(
                    "{} confidence{}\n{}",
                    product.confidence,
                    if confirmed {
                        ""
                    } else {
                        " — product not confirmed"
                    },
                    product
                        .details
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join("\n")
                ));
            }
            if !found {
                ui.weak(if confirmed {
                    "No confirmed products detected."
                } else {
                    "No possible products detected."
                });
            }
        });
    }

});
        }
        ExposureDetailTab::Diagnostics => {
let (ui, report, view,): (& mut egui :: Ui, & ExposureScanReport, & mut DiagnosticViewState,) = (ui, report, diagnostic_view,);
'inlined_show_diagnostics: {

    ui.heading("Endpoint Diagnostics");
    let endpoint_indices = report
        .endpoints
        .iter()
        .enumerate()
        .filter_map(|(index, endpoint)| (!endpoint.diagnostics.is_empty()).then_some(index))
        .collect::<Vec<_>>();
    if endpoint_indices.is_empty() {
        ui.weak("No HTTP or HTTPS endpoints were discovered.");
        break 'inlined_show_diagnostics;
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
                ({ let trace: &crate::diagnostics::DiagnosticTrace = &endpoint.diagnostics[view.hop_index]; if trace.url.normalized.is_empty() { trace.request.url.as_str() } else { trace.url.normalized.as_str() } })
            ))
            .show_ui(ui, |ui| {
                for (index, trace) in endpoint.diagnostics.iter().enumerate() {
                    ui.selectable_value(
                        &mut view.hop_index,
                        index,
                        format!("{} — {}", index + 1, ({ let trace: &crate::diagnostics::DiagnosticTrace = trace; if trace.url.normalized.is_empty() { trace.request.url.as_str() } else { trace.url.normalized.as_str() } })),
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
},
        ExposureDetailTab::Tcp => {
let (ui, report,): (& mut egui :: Ui, & ExposureScanReport,) = (ui, report,);
'inlined_show_ports: {

    ui.heading("TCP Endpoints");
    let endpoints = report
        .endpoints
        .iter()
        .filter(|endpoint| endpoint.attempted)
        .collect::<Vec<_>>();
    if endpoints.is_empty() {
        ui.weak("No TCP endpoints were tested.");
        break 'inlined_show_ports;
    }
    for state in [
        PortState::Open,
        PortState::Closed,
        PortState::FilteredOrNoResponse,
        PortState::Error,
        PortState::Cancelled,
    ] {
        let count = endpoints
            .iter()
            .filter(|endpoint| endpoint.state == state)
            .count();
        if count > 0 {
            ui.label(format!("{state}: {count}"));
        }
    }
    for endpoint in endpoints {
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
        ui.label(format!(
            "{} confidence — {:.2} ms",
            endpoint.service_confidence, endpoint.connect_duration_ms
        ));
        if endpoint.state == PortState::Open && endpoint.products.is_empty() {
            ui.weak("Product undisclosed");
        }
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

}
},
        ExposureDetailTab::Udp => {
let (ui, report,): (& mut egui :: Ui, & ExposureScanReport,) = (ui, report,);

    ui.heading("UDP Endpoints");
    let endpoints = report
        .udp_endpoints
        .iter()
        .filter(|endpoint| endpoint.attempted)
        .collect::<Vec<_>>();
    if !report.request.udp_scanning {
        ui.weak("UDP scanning was disabled.");
    } else if endpoints.is_empty() {
        ui.weak("No UDP endpoints were tested.");
    } else {
        for state in [
            UdpEndpointState::Responsive,
            UdpEndpointState::Closed,
            UdpEndpointState::Error,
            UdpEndpointState::Cancelled,
        ] {
            let count = endpoints
                .iter()
                .filter(|endpoint| endpoint.state == state)
                .count();
            if count > 0 {
                ui.label(format!("{state}: {count}"));
            }
        }
        let render_endpoint = |ui: &mut egui::Ui, endpoint: &crate::UdpEndpointScan| {
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
        };
        for endpoint in endpoints
            .iter()
            .filter(|endpoint| endpoint.state != UdpEndpointState::OpenOrFiltered)
        {
            render_endpoint(ui, endpoint);
        }
        let inconclusive_count = endpoints
            .iter()
            .filter(|endpoint| endpoint.state == UdpEndpointState::OpenOrFiltered)
            .count();
        if inconclusive_count > 0 {
            egui::CollapsingHeader::new(format!(
                "Inconclusive UDP results ({inconclusive_count})"
            ))
            .id_salt("udp_inconclusive_results")
            .default_open(false)
            .show(ui, |ui| {
                for endpoint in endpoints
                    .iter()
                    .filter(|endpoint| endpoint.state == UdpEndpointState::OpenOrFiltered)
                {
                    render_endpoint(ui, endpoint);
                }
            });
        }
    }

},
        ExposureDetailTab::Services => {
let (ui, report,): (& mut egui :: Ui, & ExposureScanReport,) = (ui, report,);

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

},
        ExposureDetailTab::DnsAndDiscovery => {
            ({
let (ui, report,): (& mut egui :: Ui, & ExposureScanReport,) = (ui, report,);

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

});
            ui.separator();
            ({
let (ui, report,): (& mut egui :: Ui, & ExposureScanReport,) = (ui, report,);
'inlined_show_dns: {

    ui.heading("DNS Posture");
    if !report.request.dns_assessment {
        ui.weak("DNS posture assessment was disabled.");
        break 'inlined_show_dns;
    } else if report.dns_observations.is_empty() {
        ui.weak(if report.status == crate::ExposureScanStatus::Cancelled {
            "DNS assessment was cancelled before findings were recorded."
        } else {
            "DNS assessment is incomplete or has not started; no findings were recorded."
        });
        break 'inlined_show_dns;
    }
    use crate::DnsObservationStatus::*;
    let count = |status| report.dns_observations.iter().filter(|item| item.status == status).count();
    if report.dns_observations.iter().any(|item| item.check == "Assessment coverage" && item.summary.contains("cancelled")) {
        ui.weak("DNS assessment was cancelled; the findings below are partial.");
    }
    for status in [Error, Warning, Inconclusive] {
        if count(status) == 0 { continue; }
        for observation in report.dns_observations.iter().filter(|item| item.status == status) {
            ({
let (ui, observation,): (& mut egui :: Ui, & crate :: DnsObservation,) = (ui, observation,);

    ui.separator();
    ui.strong(format!(
        "{} — {} — {}",
        observation.subject, observation.check, observation.status
    ));
    ui.label(&observation.summary);
    ui.label(format!("Impact: {}", observation.impact));
    ui.label(format!("Recommended fix: {}", observation.remediation));
    if !observation.evidence.is_empty() {
        egui::CollapsingHeader::new("Evidence")
            .id_salt((&observation.subject, &observation.check, &observation.summary, &observation.evidence))
            .default_open(false).show(ui, |ui| {
                for evidence in &observation.evidence { ui.weak(evidence); }
            });
    }

});
        }
    }
    for (status, heading) in [(Informational, "Information and scope"), (Pass, "Passing checks")] {
        if count(status) == 0 { continue; }
        egui::CollapsingHeader::new(format!("{heading} ({})", count(status)))
            .id_salt(("dns_group", heading)).default_open(false).show(ui, |ui| {
                for observation in report.dns_observations.iter().filter(|item| item.status == status) {
                    ({
let (ui, observation,): (& mut egui :: Ui, & crate :: DnsObservation,) = (ui, observation,);

    ui.separator();
    ui.strong(format!(
        "{} — {} — {}",
        observation.subject, observation.check, observation.status
    ));
    ui.label(&observation.summary);
    ui.label(format!("Impact: {}", observation.impact));
    ui.label(format!("Recommended fix: {}", observation.remediation));
    if !observation.evidence.is_empty() {
        egui::CollapsingHeader::new("Evidence")
            .id_salt((&observation.subject, &observation.check, &observation.summary, &observation.evidence))
            .default_open(false).show(ui, |ui| {
                for evidence in &observation.evidence { ui.weak(evidence); }
            });
    }

});
                }
            });
    }

}
});
        }
        ExposureDetailTab::Crawl => {
let (ui, report,): (& mut egui :: Ui, & ExposureScanReport,) = (ui, report,);

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

},
        ExposureDetailTab::ExternalSources => {
let (ui, report,): (& mut egui :: Ui, & ExposureScanReport,) = (ui, report,);
'inlined_show_external_sources: {

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
        break 'inlined_show_external_sources;
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
},
        ExposureDetailTab::JavaScript => {
let (ui, report,): (& mut egui :: Ui, & ExposureScanReport,) = (ui, report,);

    ({
let (ui, report,): (& mut egui :: Ui, & ExposureScanReport,) = (ui, report,);
'inlined_show_technology_inventory: {

    let mut web_technologies = BTreeSet::new();
    let languages = {
let (report,): (& ExposureScanReport,) = (report,);
let inlined_result: BTreeMap < & 'static str , LanguageDetection > = {

    let mut languages = BTreeMap::<&'static str, LanguageDetection>::new();
    for resource in &report.crawled_resources {
        for item in resource
            .detected_file_types
            .iter()
            .filter(|item| item.file_type != crate::TechnologyFileType::JavaScript)
        {
            let detection = languages.entry(item.file_type.language()).or_default();
            detection.confidence = detection.confidence.max(item.confidence);
            detection
                .file_types
                .entry(item.file_type)
                .and_modify(|confidence| *confidence = (*confidence).max(item.confidence))
                .or_insert(item.confidence);
            detection.evidence_urls.push(resource.url.clone());
            detection.evidence.extend(item.evidence.iter().cloned());
        }
    }
    for component in report
        .endpoints
        .iter()
        .flat_map(|endpoint| &endpoint.technology_components)
        .filter(|component| component.kind == TechnologyComponentKind::Runtime)
    {
        let Some(language) = ({
let (runtime,): (& str,) = (&component.name,);
{

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

}) else {
            continue;
        };
        let detection = languages.entry(language).or_default();
        detection.confidence = detection.confidence.max(component.confidence);
        detection.runtime_confidence = detection.runtime_confidence.max(component.confidence);
        detection
            .evidence_urls
            .extend(component.evidence_urls.iter().cloned());
        detection.evidence.extend(component.evidence.iter().cloned());
    }
    for detection in languages.values_mut() {
        detection.evidence_urls.sort();
        detection.evidence_urls.dedup();
        detection.evidence.sort();
        detection.evidence.dedup();
    }
    languages

};
inlined_result
};
    let mut components = BTreeSet::new();
    let mut libraries = BTreeSet::new();

    for endpoint in {
let (report,): (& ExposureScanReport,) = (report,);

    report
        .endpoints
        .iter()
        .filter(|endpoint| endpoint.state == PortState::Open)

} {
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
        break 'inlined_show_technology_inventory;
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
                        ({
let (language, detection,): (& str, & LanguageDetection,) = (language, detection,);
let inlined_result: String = {

    format!(
        "{language} — {} confidence ({})",
        detection.confidence,
        ({
let (detection,): (& LanguageDetection,) = (detection,);
let inlined_result: String = {

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
    details.join("; ")

};
inlined_result
})
    )

};
inlined_result
})
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
});
    ui.separator();
    ui.heading("Web Technologies");
    let mut technologies =
        BTreeMap::<String, Vec<(&EndpointScan, &crate::WebTechnologyDetection)>>::new();
    for endpoint in {
let (report,): (& ExposureScanReport,) = (report,);

    report
        .endpoints
        .iter()
        .filter(|endpoint| endpoint.state == PortState::Open)

} {
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
                ({
let (ui, id_salt, evidence_urls, evidence,): (& mut egui :: Ui, _, & [String], & [String],) = (ui, (
                        "web-technology-evidence",
                        endpoint.ip,
                        endpoint.port,
                        &technology.name,
                        &technology.version,
                    ), &technology.evidence_urls, &technology.evidence,);
'inlined_show_evidence_disclosure: {

    let count = evidence_urls.len() + evidence.len();
    if count == 0 {
        break 'inlined_show_evidence_disclosure;
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
});
            }
        }
    }
    ui.separator();
    ({
let (ui, report,): (& mut egui :: Ui, & ExposureScanReport,) = (ui, report,);
'inlined_show_detected_language_file_types: {

    ui.heading("Languages / File Types");
    let detected = {
let (report,): (& ExposureScanReport,) = (report,);
let inlined_result: BTreeMap < & 'static str , LanguageDetection > = {

    let mut languages = BTreeMap::<&'static str, LanguageDetection>::new();
    for resource in &report.crawled_resources {
        for item in resource
            .detected_file_types
            .iter()
            .filter(|item| item.file_type != crate::TechnologyFileType::JavaScript)
        {
            let detection = languages.entry(item.file_type.language()).or_default();
            detection.confidence = detection.confidence.max(item.confidence);
            detection
                .file_types
                .entry(item.file_type)
                .and_modify(|confidence| *confidence = (*confidence).max(item.confidence))
                .or_insert(item.confidence);
            detection.evidence_urls.push(resource.url.clone());
            detection.evidence.extend(item.evidence.iter().cloned());
        }
    }
    for component in report
        .endpoints
        .iter()
        .flat_map(|endpoint| &endpoint.technology_components)
        .filter(|component| component.kind == TechnologyComponentKind::Runtime)
    {
        let Some(language) = ({
let (runtime,): (& str,) = (&component.name,);
{

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

}) else {
            continue;
        };
        let detection = languages.entry(language).or_default();
        detection.confidence = detection.confidence.max(component.confidence);
        detection.runtime_confidence = detection.runtime_confidence.max(component.confidence);
        detection
            .evidence_urls
            .extend(component.evidence_urls.iter().cloned());
        detection.evidence.extend(component.evidence.iter().cloned());
    }
    for detection in languages.values_mut() {
        detection.evidence_urls.sort();
        detection.evidence_urls.dedup();
        detection.evidence.sort();
        detection.evidence.dedup();
    }
    languages

};
inlined_result
};
    if detected.is_empty() {
        ui.weak("No supported backend languages or remotely observable file types were detected.");
        break 'inlined_show_detected_language_file_types;
    }

    for (language, detection) in detected {
        ui.separator();
        ui.strong(language);
        ui.label(format!("{} confidence", detection.confidence));
        ui.weak({
let (detection,): (& LanguageDetection,) = (&detection,);
let inlined_result: String = {

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
    details.join("; ")

};
inlined_result
});
        ({
let (ui, id_salt, evidence_urls, evidence,): (& mut egui :: Ui, _, & [String], & [String],) = (ui, ("language-file-type-evidence", language), &detection.evidence_urls, &detection.evidence,);
'inlined_show_evidence_disclosure: {

    let count = evidence_urls.len() + evidence.len();
    if count == 0 {
        break 'inlined_show_evidence_disclosure;
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
});
    }

}
});
    ui.separator();
    ui.heading("Servers, Frameworks, Plugins, Runtimes, and Packages");
    let observations = report
        .endpoints
        .iter()
        .filter(|endpoint| endpoint.state == PortState::Open)
        .flat_map(|endpoint| {
            endpoint
                .technology_components
                .iter()
                .map(move |component| (endpoint, component))
        })
        .collect::<Vec<_>>();
    let mut packages = BTreeMap::<_, BTreeMap<Option<&str>, Vec<usize>>>::new();
    for (index, (_, component)) in observations.iter().enumerate() {
        if component.kind == TechnologyComponentKind::Package {
            let key = (
                component.ecosystem,
                component.package_identifier.as_deref().unwrap_or(&component.name),
            );
            packages
                .entry(key)
                .or_default()
                .entry(component.installed_version.as_deref())
                .or_default()
                .push(index);
        }
    }
    for (index, (endpoint, component)) in observations.iter().enumerate() {
        let key = (
            component.ecosystem,
            component.package_identifier.as_deref().unwrap_or(&component.name),
        );
        if let Some(versions) = packages
            .get(&key)
            .filter(|versions| component.kind == TechnologyComponentKind::Package && versions.len() > 1)
        {
            if versions.values().map(|indices| indices[0]).min() != Some(index) {
                continue;
            }
            let mut versions = versions.iter().collect::<Vec<_>>();
            versions.sort_by_key(|(_, indices)| indices[0]);
            let label = versions
                .iter()
                .map(|(version, _)| version.unwrap_or("version not observed"))
                .collect::<Vec<_>>()
                .join(", ");
            ui.separator();
            egui::CollapsingHeader::new(
                egui::RichText::new(format!("{} — {label}", component.name)).strong(),
            )
            .id_salt(("technology-package-versions", key))
            .default_open(false)
            .show(ui, |ui| {
                for (version, indices) in versions {
                    ui.separator();
                    ui.strong(version.unwrap_or("version not observed"));
                    for &observation_index in indices {
                        let (endpoint, component) = observations[observation_index];
                        ui.push_id(observation_index, |ui| {
                            show_technology_component_details(ui, endpoint, component);
                        });
                    }
                }
            });
        } else {
            ui.separator();
            ui.strong(&component.name);
            ui.push_id(index, |ui| {
                show_technology_component_details(ui, endpoint, component);
            });
        }
    }
    if observations.is_empty() {
        ui.weak("No servers, frameworks, plugins, runtimes, or packages were identified.");
    }
    ui.separator();
    ui.heading("JavaScript Sources");
    let mut found = false;
    for endpoint in {
let (report,): (& ExposureScanReport,) = (report,);

    report
        .endpoints
        .iter()
        .filter(|endpoint| endpoint.state == PortState::Open)

} {
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
                        ({
let (ui, id_salt, evidence_urls, evidence,): (& mut egui :: Ui, _, & [String], & [String],) = (ui, (
                                "javascript-library-evidence",
                                endpoint.ip,
                                endpoint.port,
                                &source.source_url,
                                &library.name,
                                &library.npm_package,
                                &library.installed_version,
                            ), &[], &library.evidence,);
'inlined_show_evidence_disclosure: {

    let count = evidence_urls.len() + evidence.len();
    if count == 0 {
        break 'inlined_show_evidence_disclosure;
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
});
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

},
        ExposureDetailTab::SecuritySummary => {
let (ui, report,): (& mut egui :: Ui, & ExposureScanReport,) = (ui, report,);

    let grouped_findings = {
let (findings,): (& [ExposureFinding],) = (&report.findings,);
let inlined_result: Vec < ConfirmedFindingGroup < '_ > > = {

    let mut groups = BTreeMap::<&str, ConfirmedFindingGroup<'_>>::new();
    for finding in findings {
        let title = {
let (title,): (& str,) = (&finding.title,);
let inlined_result: & str = {

    match title {
        "Session-like cookie attributes are missing"
        | "Security-sensitive cookie lacks Secure"
        | "Security-sensitive cookie lacks HttpOnly"
        | "Security-sensitive cookie lacks SameSite" => "Cookie security attributes are missing",
        _ => title,
    }

};
inlined_result
};
        let collapsed = matches!(
            finding.component_kind,
            Some(TechnologyComponentKind::Package | TechnologyComponentKind::Plugin)
        );
        let group = groups
            .entry(title)
            .or_insert_with(|| ConfirmedFindingGroup {
                title,
                description: if title == "Cookie security attributes are missing" {
                    "Session-like or security-sensitive cookies omit applicable browser protections"
                } else {
                    &finding.description
                },
                endpoints: BTreeMap::new(),
                collapsed,
            });
        group.collapsed &= collapsed;
        let endpoint = group.endpoints.entry(finding.ip).or_default();
        endpoint
            .ports
            .entry(finding.transport)
            .or_default()
            .insert(finding.port);
        endpoint
            .evidence
            .extend(finding.evidence.iter().map(String::as_str));
    }
    let mut groups = groups.into_values().collect::<Vec<_>>();
    for group in &mut groups {
        for endpoint in group.endpoints.values_mut() {
            endpoint.evidence.sort();
            endpoint.evidence.dedup();
        }
    }
    groups

};
inlined_result
};
    let collapsed_findings = grouped_findings
        .iter()
        .filter(|finding| finding.collapsed)
        .collect::<Vec<_>>();
    let prominent_findings = grouped_findings
        .iter()
        .filter(|finding| !finding.collapsed)
        .collect::<Vec<_>>();
    ui.separator();
    ui.heading(format!("Confirmed Findings ({})", grouped_findings.len()));
    if grouped_findings.is_empty() {
        ui.weak("No confirmed security findings were observed by the bounded checks.");
    } else if prominent_findings.is_empty() {
        ui.weak("No prominent confirmed findings were observed; outdated packages and plugins are listed below.");
    } else {
        for finding in prominent_findings {
            ({
let (ui, finding, checks,): (& mut egui :: Ui, & ConfirmedFindingGroup < '_ >, & [crate :: SecurityCheckResult],) = (ui, finding, &report.security_checks,);

    ui.separator();
    ui.strong(finding.title);
    ui.label(finding.description);
    let count = finding.endpoints.len();
    let endpoint_label = if count == 1 { "endpoint" } else { "endpoints" };
    egui::CollapsingHeader::new(format!("Evidence ({count} {endpoint_label})"))
        .id_salt(("confirmed_finding_evidence", finding.title))
        .default_open(false)
        .show(ui, |ui| {
            for (index, (ip, endpoint)) in finding.endpoints.iter().enumerate() {
                if index > 0 {
                    ui.separator();
                }
                ui.label({
let (ip, endpoint,): (std :: net :: IpAddr, & ConfirmedFindingEndpoint < '_ >,) = (*ip, endpoint,);
let inlined_result: String = {

    let endpoints = endpoint
        .ports
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
    format!("Endpoint: {ip} — {endpoints}")

};
inlined_result
});
                if finding.title == "Browser security headers are missing" {
                    ({
let (ui, evidence,): (& mut egui :: Ui, & [& str],) = (ui, &endpoint.evidence,);

    let mut groups = BTreeMap::<Vec<String>, (Option<&str>, Option<&str>, usize)>::new();
    let mut ungrouped = Vec::new();
    for &value in evidence {
        let Some((headers, page)) = ({
let (evidence,): (& str,) = (value,);
let inlined_result: Option < (Vec < String > , bool) > = {
'inlined_missing_browser_header_set: {

    let (headers, page) = if let Some(headers) = evidence.strip_prefix("Missing: ") {
        (headers, false)
    } else {
        let (_, headers) = match evidence.rsplit_once(" missing ") { Some(value) => value, None => break 'inlined_missing_browser_header_set None };
        (headers, true)
    };
    let mut headers = headers
        .split(',')
        .map(str::trim)
        .filter(|header| !header.is_empty())
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>();
    if headers.is_empty() {
        break 'inlined_missing_browser_header_set None;
    }
    headers.sort();
    headers.dedup();
    Some((headers, page))

}
};
inlined_result
}) else {
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

});
                } else {
                    for evidence in &endpoint.evidence {
                        ui.weak(format!("Evidence: {evidence}"));
                    }
                }
            }
            for group in {
let (finding, checks,): (& ConfirmedFindingGroup < '_ >, & '_ [crate :: SecurityCheckResult],) = (finding, checks,);
let inlined_result: Vec < SecurityCheckGroup < '_ > > = {

    {
let (checks,): (_,) = (checks.iter().filter(|check| {
        check.outcome == crate::CheckOutcome::Vulnerable
            && ({
let (title,): (& str,) = (&check.title,);
let inlined_result: & str = {

    match title {
        "Session-like cookie attributes are missing"
        | "Security-sensitive cookie lacks Secure"
        | "Security-sensitive cookie lacks HttpOnly"
        | "Security-sensitive cookie lacks SameSite" => "Cookie security attributes are missing",
        _ => title,
    }

};
inlined_result
}) == finding.title
            && finding
                .endpoints
                .get(&check.ip)
                .and_then(|endpoint| endpoint.ports.get(&TransportProtocol::Tcp))
                .is_some_and(|ports| ports.contains(&check.port))
    }),);
let inlined_result: Vec < SecurityCheckGroup < '_ > > = {

    let mut groups = Vec::<SecurityCheckGroup<'_>>::new();
    for check in checks {
        let group = groups
            .iter_mut()
            .find(|group| {
let (left, right,): (& crate :: SecurityCheckResult, & crate :: SecurityCheckResult,) = (group.check, check,);
{

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

});
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

};
inlined_result
}

};
inlined_result
} {
                ({
let (ui, group,): (& mut egui :: Ui, & SecurityCheckGroup < '_ >,) = (ui, &group,);

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
            ({
let (endpoints,): (& BTreeMap < std :: net :: IpAddr , BTreeSet < u16 > >,) = (&group.endpoints,);
let inlined_result: String = {

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

};
inlined_result
})
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

});
            }
            if finding.title == "TLS certificate chain or key weakness" {
                ui.weak("Remediation: Serve a complete, correctly ordered leaf and intermediate certificate chain with server-auth usage; reissue weak certificates using SHA-256 or stronger signatures and at least RSA-2048 or ECDSA P-256 keys.");
            }
        });

});
        }
    }
    ui.separator();
    ({
let (ui, report,): (& mut egui :: Ui, & ExposureScanReport,) = (ui, report,);
'inlined_show_dns: {

    if !report.request.dns_assessment {
        ui.weak("DNS posture assessment was disabled.");
        break 'inlined_show_dns;
    } else if report.dns_observations.is_empty() {
        ui.weak(if report.status == crate::ExposureScanStatus::Cancelled {
            "DNS assessment was cancelled before findings were recorded."
        } else {
            "DNS assessment is incomplete or has not started; no findings were recorded."
        });
        break 'inlined_show_dns;
    }
    use crate::DnsObservationStatus::*;
    let count = |status| report.dns_observations.iter().filter(|item| item.status == status).count();
    if report.dns_observations.iter().any(|item| item.check == "Assessment coverage" && item.summary.contains("cancelled")) {
        ui.weak("DNS assessment was cancelled; the findings below are partial.");
    }
    for status in [Error, Warning, Recommendation] {
        if count(status) == 0 { continue; }
        for observation in report.dns_observations.iter().filter(|item| item.status == status) {
            ({
let (ui, observation,): (& mut egui :: Ui, & crate :: DnsObservation,) = (ui, observation,);

    ui.separator();
    ui.strong(format!(
        "{} — {} — {}",
        observation.subject, observation.check, observation.status
    ));
    ui.label(&observation.summary);
    ui.label(format!("Impact: {}", observation.impact));
    ui.label(format!("Recommended fix: {}", observation.remediation));
    if !observation.evidence.is_empty() {
        egui::CollapsingHeader::new("Evidence")
            .id_salt((&observation.subject, &observation.check, &observation.summary, &observation.evidence))
            .default_open(false).show(ui, |ui| {
                for evidence in &observation.evidence { ui.weak(evidence); }
            });
    }

});
        }
    }
    for (status, heading) in [(Inconclusive, "Inconclusive"), (Informational, "Information and scope"), (Pass, "Passing checks")] {
        if count(status) == 0 { continue; }
        egui::CollapsingHeader::new(format!("{heading} ({})", count(status)))
            .id_salt(("dns_group", heading)).default_open(false).show(ui, |ui| {
                for observation in report.dns_observations.iter().filter(|item| item.status == status) {
                    ({
let (ui, observation,): (& mut egui :: Ui, & crate :: DnsObservation,) = (ui, observation,);

    ui.separator();
    ui.strong(format!(
        "{} — {} — {}",
        observation.subject, observation.check, observation.status
    ));
    ui.label(&observation.summary);
    ui.label(format!("Impact: {}", observation.impact));
    ui.label(format!("Recommended fix: {}", observation.remediation));
    if !observation.evidence.is_empty() {
        egui::CollapsingHeader::new("Evidence")
            .id_salt((&observation.subject, &observation.check, &observation.summary, &observation.evidence))
            .default_open(false).show(ui, |ui| {
                for evidence in &observation.evidence { ui.weak(evidence); }
            });
    }

});
                }
            });
    }

}
});

    let mut exposed_services = ({
let (report,): (& ExposureScanReport,) = (report,);

    report
        .endpoints
        .iter()
        .filter(|endpoint| endpoint.state == PortState::Open)

})
        .filter(|endpoint| !matches!(endpoint.service, ServiceKind::Http | ServiceKind::Https))
        .collect::<Vec<_>>();
    exposed_services.sort_by(|left, right| left.ip.cmp(&right.ip).then(left.port.cmp(&right.port)));
    if !exposed_services.is_empty() {
        ui.separator();
        egui::CollapsingHeader::new(format!(
            "Publicly Exposed Services ({})",
            exposed_services.len()
        ))
        .default_open(false)
        .show(ui, |ui| {
            for endpoint in exposed_services {
                ui.label(format!(
                    "{}:{} — {}",
                    endpoint.ip,
                    endpoint.port,
                    ({
let (endpoint,): (& EndpointScan,) = (endpoint,);
let inlined_result: String = {
'inlined_exposed_service_label: {

    if endpoint.service != ServiceKind::Unknown {
        break 'inlined_exposed_service_label endpoint.service.to_string();
    }
    if endpoint.service_confidence == Confidence::Low
        && let Some(metadata) = curated_tcp_port_metadata(endpoint.port)
    {
        break 'inlined_exposed_service_label format!("{} (unconfirmed)", metadata.service_name);
    }
    "Unknown service".to_owned()

}
};
inlined_result
})
                ));
            }
        });
    }

    let mut surfaces = ({
let (report,): (& ExposureScanReport,) = (report,);

    report
        .endpoints
        .iter()
        .filter(|endpoint| endpoint.state == PortState::Open)

})
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
    ({
let (ui, report,): (& mut egui :: Ui, & ExposureScanReport,) = (ui, report,);
'inlined_show_checks_needing_verification: {

    let grouped_checks = {
let (checks,): (_,) = (report
            .security_checks
            .iter()
            .filter(|check| check.outcome == crate::CheckOutcome::Potential),);
let inlined_result: Vec < SecurityCheckGroup < '_ > > = {

    let mut groups = Vec::<SecurityCheckGroup<'_>>::new();
    for check in checks {
        let group = groups
            .iter_mut()
            .find(|group| {
let (left, right,): (& crate :: SecurityCheckResult, & crate :: SecurityCheckResult,) = (group.check, check,);
{

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

});
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

};
inlined_result
};
    if grouped_checks.is_empty() {
        break 'inlined_show_checks_needing_verification;
    }
    ui.separator();
    ui.heading(format!("Needs Verification ({})", grouped_checks.len()));
    ui.weak("Potential issues that have not been confirmed.");
    egui::CollapsingHeader::new("Check details")
        .id_salt("security_checks_needing_verification")
        .default_open(true)
        .show(ui, |ui| {
            for group in grouped_checks {
                ({
let (ui, group,): (& mut egui :: Ui, & SecurityCheckGroup < '_ >,) = (ui, &group,);

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
            ({
let (endpoints,): (& BTreeMap < std :: net :: IpAddr , BTreeSet < u16 > >,) = (&group.endpoints,);
let inlined_result: String = {

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

};
inlined_result
})
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

});
            }
        });

}
});

    if !collapsed_findings.is_empty() {
        ui.separator();
        egui::CollapsingHeader::new(format!(
            "Outdated Components ({})",
            collapsed_findings.len()
        ))
        .default_open(false)
        .show(ui, |ui| {
            for finding in collapsed_findings {
                ({
let (ui, finding, checks,): (& mut egui :: Ui, & ConfirmedFindingGroup < '_ >, & [crate :: SecurityCheckResult],) = (ui, finding, &report.security_checks,);

    ui.separator();
    ui.strong(finding.title);
    ui.label(finding.description);
    let count = finding.endpoints.len();
    let endpoint_label = if count == 1 { "endpoint" } else { "endpoints" };
    egui::CollapsingHeader::new(format!("Evidence ({count} {endpoint_label})"))
        .id_salt(("confirmed_finding_evidence", finding.title))
        .default_open(false)
        .show(ui, |ui| {
            for (index, (ip, endpoint)) in finding.endpoints.iter().enumerate() {
                if index > 0 {
                    ui.separator();
                }
                ui.label({
let (ip, endpoint,): (std :: net :: IpAddr, & ConfirmedFindingEndpoint < '_ >,) = (*ip, endpoint,);
let inlined_result: String = {

    let endpoints = endpoint
        .ports
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
    format!("Endpoint: {ip} — {endpoints}")

};
inlined_result
});
                if finding.title == "Browser security headers are missing" {
                    ({
let (ui, evidence,): (& mut egui :: Ui, & [& str],) = (ui, &endpoint.evidence,);

    let mut groups = BTreeMap::<Vec<String>, (Option<&str>, Option<&str>, usize)>::new();
    let mut ungrouped = Vec::new();
    for &value in evidence {
        let Some((headers, page)) = ({
let (evidence,): (& str,) = (value,);
let inlined_result: Option < (Vec < String > , bool) > = {
'inlined_missing_browser_header_set: {

    let (headers, page) = if let Some(headers) = evidence.strip_prefix("Missing: ") {
        (headers, false)
    } else {
        let (_, headers) = match evidence.rsplit_once(" missing ") { Some(value) => value, None => break 'inlined_missing_browser_header_set None };
        (headers, true)
    };
    let mut headers = headers
        .split(',')
        .map(str::trim)
        .filter(|header| !header.is_empty())
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>();
    if headers.is_empty() {
        break 'inlined_missing_browser_header_set None;
    }
    headers.sort();
    headers.dedup();
    Some((headers, page))

}
};
inlined_result
}) else {
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

});
                } else {
                    for evidence in &endpoint.evidence {
                        ui.weak(format!("Evidence: {evidence}"));
                    }
                }
            }
            for group in {
let (finding, checks,): (& ConfirmedFindingGroup < '_ >, & '_ [crate :: SecurityCheckResult],) = (finding, checks,);
let inlined_result: Vec < SecurityCheckGroup < '_ > > = {

    {
let (checks,): (_,) = (checks.iter().filter(|check| {
        check.outcome == crate::CheckOutcome::Vulnerable
            && ({
let (title,): (& str,) = (&check.title,);
let inlined_result: & str = {

    match title {
        "Session-like cookie attributes are missing"
        | "Security-sensitive cookie lacks Secure"
        | "Security-sensitive cookie lacks HttpOnly"
        | "Security-sensitive cookie lacks SameSite" => "Cookie security attributes are missing",
        _ => title,
    }

};
inlined_result
}) == finding.title
            && finding
                .endpoints
                .get(&check.ip)
                .and_then(|endpoint| endpoint.ports.get(&TransportProtocol::Tcp))
                .is_some_and(|ports| ports.contains(&check.port))
    }),);
let inlined_result: Vec < SecurityCheckGroup < '_ > > = {

    let mut groups = Vec::<SecurityCheckGroup<'_>>::new();
    for check in checks {
        let group = groups
            .iter_mut()
            .find(|group| {
let (left, right,): (& crate :: SecurityCheckResult, & crate :: SecurityCheckResult,) = (group.check, check,);
{

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

});
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

};
inlined_result
}

};
inlined_result
} {
                ({
let (ui, group,): (& mut egui :: Ui, & SecurityCheckGroup < '_ >,) = (ui, &group,);

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
            ({
let (endpoints,): (& BTreeMap < std :: net :: IpAddr , BTreeSet < u16 > >,) = (&group.endpoints,);
let inlined_result: String = {

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

};
inlined_result
})
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

});
            }
            if finding.title == "TLS certificate chain or key weakness" {
                ui.weak("Remediation: Serve a complete, correctly ordered leaf and intermediate certificate chain with server-auth usage; reissue weak certificates using SHA-256 or stronger signatures and at least RSA-2048 or ECDSA P-256 keys.");
            }
        });

});
            }
        });
    }

},
    });
}

struct DiagnosticProduct {
    name: String,
    versions: BTreeMap<String, Confidence>,
    confidence: Confidence,
    details: BTreeSet<String>,
}

struct ConfirmedFindingGroup<'a> {
    title: &'a str,
    description: &'a str,
    endpoints: BTreeMap<std::net::IpAddr, ConfirmedFindingEndpoint<'a>>,
    collapsed: bool,
}

#[derive(Default)]
struct ConfirmedFindingEndpoint<'a> {
    ports: BTreeMap<TransportProtocol, BTreeSet<u16>>,
    evidence: Vec<&'a str>,
}

#[derive(Default)]
struct LanguageDetection {
    confidence: Confidence,
    runtime_confidence: Confidence,
    file_types: BTreeMap<crate::TechnologyFileType, Confidence>,
    evidence_urls: Vec<String>,
    evidence: Vec<String>,
}

struct SecurityCheckGroup<'a> {
    check: &'a crate::SecurityCheckResult,
    endpoints: BTreeMap<std::net::IpAddr, BTreeSet<u16>>,
}
