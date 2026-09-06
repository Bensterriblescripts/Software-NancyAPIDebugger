use crate::auth::{ProfileInput, ProfileType};
use eframe::egui;

use super::app::App;

pub(super) fn show(ctx: &egui::Context, app: &mut App) {
    let mut open = app.show_auth_profiles;
    let profiles = app
        .auth_store
        .lock()
        .map(|store| store.summaries())
        .unwrap_or_default();
    let mut edit = None;
    let mut delete = None;
    let mut sign_in = None;
    let mut capture = None;
    let mut save = false;
    let mut cancel_editor = false;
    egui::Window::new("Authentication Profiles")
        .open(&mut open)
        .default_width(680.0)
        .show(ctx, |ui| {
            ui.horizontal(|ui| {
                if ui.button("New profile").clicked() {
                    app.profile_draft = app.new_profile_draft();
                    app.editing_auth_profile = None;
                    app.profile_editor_open = true;
                }
                if app.auth_busy.is_some() {
                    ui.spinner();
                    if ui.button("Cancel authentication").clicked() {
                        if let Some(cancel) = &app.auth_cancel {
                            cancel.cancel();
                        }
                        app.auth_notice = Some("Cancelling authentication...".to_owned());
                    }
                }
            });
            ui.separator();
            if profiles.is_empty() {
                ui.weak("No authentication profiles configured.");
            }
            for profile in &profiles {
                ui.group(|ui| {
                    ui.horizontal(|ui| {
                        ui.vertical(|ui| {
                            ui.strong(&profile.name);
                            ui.label(profile.profile_type.label());
                            ui.weak(&profile.status);
                        });
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui
                                .add_enabled(app.auth_busy.is_none(), egui::Button::new("Delete"))
                                .clicked()
                            {
                                delete = Some(profile.id);
                            }
                            if ui
                                .add_enabled(app.auth_busy.is_none(), egui::Button::new("Edit"))
                                .clicked()
                            {
                                edit = Some(profile.id);
                            }
                            match profile.profile_type {
                                ProfileType::AzureInteractive
                                    if ui
                                        .add_enabled(
                                            app.auth_busy.is_none(),
                                            egui::Button::new("Sign in"),
                                        )
                                        .clicked() =>
                                {
                                    sign_in = Some(profile.id);
                                }
                                ProfileType::BrowserCookies
                                    if ui
                                        .add_enabled(
                                            app.auth_busy.is_none(),
                                            egui::Button::new("Open Login & Capture"),
                                        )
                                        .clicked() =>
                                {
                                    capture = Some(profile.id);
                                }
                                _ => {}
                            }
                        });
                    });
                });
                ui.add_space(4.0);
            }

            if app.profile_editor_open {
                ui.separator();
                ui.heading(if app.editing_auth_profile.is_some() {
                    "Edit profile"
                } else {
                    "New profile"
                });
                egui::Grid::new("profile_editor")
                    .num_columns(2)
                    .show(ui, |ui| {
                        ui.label("Name");
                        ui.add(
                            egui::TextEdit::singleline(&mut app.profile_draft.name)
                                .desired_width(420.0),
                        );
                        ui.end_row();

                        ui.label("Type");
                        let previous_type = app.profile_draft.profile_type;
                        egui::ComboBox::from_id_salt("profile_type")
                            .selected_text(app.profile_draft.profile_type.label())
                            .show_ui(ui, |ui| {
                                for profile_type in ProfileType::ALL {
                                    ui.selectable_value(
                                        &mut app.profile_draft.profile_type,
                                        profile_type,
                                        profile_type.label(),
                                    );
                                }
                            });
                        if app.profile_draft.profile_type != previous_type {
                            app.profile_draft.clear_sensitive();
                        }
                        ui.end_row();

                        match app.profile_draft.profile_type {
                            ProfileType::AzureInteractive => {
                                ({
                                    let (ui, label, value, password): (
                                        &mut egui::Ui,
                                        &str,
                                        &mut String,
                                        bool,
                                    ) = (ui, "Tenant", &mut app.profile_draft.tenant, false);

                                    ui.label(label);
                                    ui.add(
                                        egui::TextEdit::singleline(value)
                                            .password(password)
                                            .desired_width(420.0),
                                    );
                                    ui.end_row();
                                });
                                ({
                                    let (ui, label, value, password): (
                                        &mut egui::Ui,
                                        &str,
                                        &mut String,
                                        bool,
                                    ) = (ui, "Client ID", &mut app.profile_draft.client_id, false);

                                    ui.label(label);
                                    ui.add(
                                        egui::TextEdit::singleline(value)
                                            .password(password)
                                            .desired_width(420.0),
                                    );
                                    ui.end_row();
                                });
                                ({
                                    let (ui, label, value, password): (
                                        &mut egui::Ui,
                                        &str,
                                        &mut String,
                                        bool,
                                    ) = (ui, "Scopes", &mut app.profile_draft.scopes, false);

                                    ui.label(label);
                                    ui.add(
                                        egui::TextEdit::singleline(value)
                                            .password(password)
                                            .desired_width(420.0),
                                    );
                                    ui.end_row();
                                });
                            }
                            ProfileType::AzureClientCredentials => {
                                ({
                                    let (ui, label, value, password): (
                                        &mut egui::Ui,
                                        &str,
                                        &mut String,
                                        bool,
                                    ) = (ui, "Tenant", &mut app.profile_draft.tenant, false);

                                    ui.label(label);
                                    ui.add(
                                        egui::TextEdit::singleline(value)
                                            .password(password)
                                            .desired_width(420.0),
                                    );
                                    ui.end_row();
                                });
                                ({
                                    let (ui, label, value, password): (
                                        &mut egui::Ui,
                                        &str,
                                        &mut String,
                                        bool,
                                    ) = (ui, "Client ID", &mut app.profile_draft.client_id, false);

                                    ui.label(label);
                                    ui.add(
                                        egui::TextEdit::singleline(value)
                                            .password(password)
                                            .desired_width(420.0),
                                    );
                                    ui.end_row();
                                });
                                ({
                                    let (ui, label, value, password): (
                                        &mut egui::Ui,
                                        &str,
                                        &mut String,
                                        bool,
                                    ) = (
                                        ui,
                                        "Client secret",
                                        &mut app.profile_draft.client_secret,
                                        true,
                                    );

                                    ui.label(label);
                                    ui.add(
                                        egui::TextEdit::singleline(value)
                                            .password(password)
                                            .desired_width(420.0),
                                    );
                                    ui.end_row();
                                });
                                ({
                                    let (ui, label, value, password): (
                                        &mut egui::Ui,
                                        &str,
                                        &mut String,
                                        bool,
                                    ) = (ui, "Scope", &mut app.profile_draft.scopes, false);

                                    ui.label(label);
                                    ui.add(
                                        egui::TextEdit::singleline(value)
                                            .password(password)
                                            .desired_width(420.0),
                                    );
                                    ui.end_row();
                                });
                            }
                            ProfileType::BrowserCookies => {
                                ({
                                    let (ui, label, value, password): (
                                        &mut egui::Ui,
                                        &str,
                                        &mut String,
                                        bool,
                                    ) = (ui, "Login URL", &mut app.profile_draft.login_url, false);

                                    ui.label(label);
                                    ui.add(
                                        egui::TextEdit::singleline(value)
                                            .password(password)
                                            .desired_width(420.0),
                                    );
                                    ui.end_row();
                                });
                                ({
                                    let (ui, label, value, password): (
                                        &mut egui::Ui,
                                        &str,
                                        &mut String,
                                        bool,
                                    ) = (
                                        ui,
                                        "Host scope",
                                        &mut app.profile_draft.host_scope,
                                        false,
                                    );

                                    ui.label(label);
                                    ui.add(
                                        egui::TextEdit::singleline(value)
                                            .password(password)
                                            .desired_width(420.0),
                                    );
                                    ui.end_row();
                                });
                            }
                            ProfileType::ManualCookie => {
                                ({
                                    let (ui, label, value, password): (
                                        &mut egui::Ui,
                                        &str,
                                        &mut String,
                                        bool,
                                    ) = (
                                        ui,
                                        "Host scope",
                                        &mut app.profile_draft.host_scope,
                                        false,
                                    );

                                    ui.label(label);
                                    ui.add(
                                        egui::TextEdit::singleline(value)
                                            .password(password)
                                            .desired_width(420.0),
                                    );
                                    ui.end_row();
                                });
                                ({
                                    let (ui, label, value, password): (
                                        &mut egui::Ui,
                                        &str,
                                        &mut String,
                                        bool,
                                    ) = (ui, "Cookie", &mut app.profile_draft.cookie, true);

                                    ui.label(label);
                                    ui.add(
                                        egui::TextEdit::singleline(value)
                                            .password(password)
                                            .desired_width(420.0),
                                    );
                                    ui.end_row();
                                });
                            }
                            ProfileType::ClientCertificate => {
                                ({
                                    let (ui, label, value, password): (
                                        &mut egui::Ui,
                                        &str,
                                        &mut String,
                                        bool,
                                    ) = (
                                        ui,
                                        "Exact host scope",
                                        &mut app.profile_draft.host_scope,
                                        false,
                                    );

                                    ui.label(label);
                                    ui.add(
                                        egui::TextEdit::singleline(value)
                                            .password(password)
                                            .desired_width(420.0),
                                    );
                                    ui.end_row();
                                });
                                ({
                                    let (ui, label, value, password): (
                                        &mut egui::Ui,
                                        &str,
                                        &mut String,
                                        bool,
                                    ) = (
                                        ui,
                                        "PEM certificate chain",
                                        &mut app.profile_draft.certificate_chain_path,
                                        false,
                                    );

                                    ui.label(label);
                                    ui.add(
                                        egui::TextEdit::singleline(value)
                                            .password(password)
                                            .desired_width(420.0),
                                    );
                                    ui.end_row();
                                });
                                ({
                                    let (ui, label, value, password): (
                                        &mut egui::Ui,
                                        &str,
                                        &mut String,
                                        bool,
                                    ) = (
                                        ui,
                                        "PEM private key",
                                        &mut app.profile_draft.private_key_path,
                                        true,
                                    );

                                    ui.label(label);
                                    ui.add(
                                        egui::TextEdit::singleline(value)
                                            .password(password)
                                            .desired_width(420.0),
                                    );
                                    ui.end_row();
                                });
                            }
                        }
                    });
                ui.horizontal(|ui| {
                    if ui.button("Save").clicked() {
                        save = true;
                    }
                    if ui.button("Cancel").clicked() {
                        cancel_editor = true;
                    }
                });
            }
        });
    app.show_auth_profiles = open;

    if let Some(id) = edit {
        let input = app
            .auth_store
            .lock()
            .ok()
            .and_then(|store| store.profile_input(id));
        if let Some(input) = input {
            app.profile_draft = input;
            app.editing_auth_profile = Some(id);
            app.profile_editor_open = true;
        } else {
            app.ui_error = Some("Authentication profile no longer exists".to_owned());
        }
    }
    if save {
        let result = app
            .auth_store
            .lock()
            .map_err(|_| "Authentication profile store is unavailable".to_owned())
            .and_then(|mut store| store.save(app.editing_auth_profile, &app.profile_draft));
        match result {
            Ok(id) => {
                if app.profile_draft.profile_type == ProfileType::ClientCertificate {
                    app.scan_form.diagnostic.selected_client_certificate_profile = Some(id);
                } else {
                    app.scan_form.diagnostic.selected_auth_profile = Some(id);
                }
                app.profile_draft = ProfileInput::default();
                app.editing_auth_profile = None;
                app.profile_editor_open = false;
                app.auth_notice = Some("Authentication profile saved".to_owned());
                app.ui_error = None;
            }
            Err(error) => app.ui_error = Some(error),
        }
    }
    if cancel_editor {
        app.profile_draft = ProfileInput::default();
        app.editing_auth_profile = None;
        app.profile_editor_open = false;
    }
    if let Some(id) = delete {
        let deleted = app
            .auth_store
            .lock()
            .map(|mut store| store.delete(id))
            .unwrap_or(false);
        if deleted {
            if app.scan_form.diagnostic.selected_auth_profile == Some(id) {
                app.scan_form.diagnostic.selected_auth_profile = None;
            }
            if app.scan_form.diagnostic.selected_client_certificate_profile == Some(id) {
                app.scan_form.diagnostic.selected_client_certificate_profile = None;
            }
            if app.editing_auth_profile == Some(id) {
                app.profile_draft = ProfileInput::default();
                app.editing_auth_profile = None;
                app.profile_editor_open = false;
            }
            app.auth_notice = Some("Authentication profile deleted".to_owned());
        }
    }
    if let Some(id) = sign_in {
        app.start_interactive_sign_in(id);
    }
    if let Some(id) = capture {
        app.start_browser_cookie_capture(id);
    }
    if !open {
        app.profile_draft = ProfileInput::default();
        app.editing_auth_profile = None;
        app.profile_editor_open = false;
    }
}
