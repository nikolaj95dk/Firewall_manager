use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};

use eframe::egui::{
    self, text::LayoutJob, Align, Color32, CornerRadius, FontId, Frame, Key, Layout, Margin, RichText, Sense, Stroke,
    TextFormat, TextureHandle, Ui, Vec2,
};
use egui_extras::{Column, TableBuilder};
use egui_phosphor::regular as ph;
use raw_window_handle::HasWindowHandle;

use crate::analysis::{self, Analysis, Issue, IssueKind, Severity};
use crate::firewall::{
    self, Action, AppState, Direction, NewRule, OpOutcome, PortSpec, ProfileStatus, Protocol, Rule, Snapshot, Source,
    PROFILE_DOMAIN, PROFILE_PRIVATE, PROFILE_PUBLIC,
};
use crate::ports::Risk;
use crate::theme::*;

// =============================================================================================
// State
// =============================================================================================

#[derive(Clone, Copy, PartialEq, Eq)]
enum View {
    Overview,
    Rules,
    Cleanup,
    Ports,
    Programs,
}

enum Msg {
    Loaded(Result<(Snapshot, Analysis), String>),
    OpDone { title: String, outcome: OpOutcome, backup: Option<Result<PathBuf, String>> },
    Created(Result<(), String>, NewRule),
    BackupDone(Result<PathBuf, String>),
}

#[derive(Clone, Copy, PartialEq)]
enum ToastKind {
    Ok,
    Warn,
    Err,
}

struct Toast {
    text: String,
    kind: ToastKind,
    born: f64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SortCol {
    Name,
    Direction,
    Action,
    Protocol,
    Ports,
    Program,
    Severity,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Col {
    Check,
    Status,
    Name,
    Dir,
    Action,
    Proto,
    Ports,
    Remote,
    Program,
    Profiles,
    Findings,
}

#[derive(Default)]
struct Filters {
    search: String,
    direction: Option<Direction>,
    action: Option<Action>,
    enabled: Option<bool>,
    issue: Option<IssueKind>,
    port: Option<(Protocol, PortSpec)>,
    program: Option<(String, String)>,
    hide_builtin: bool,
    issues_only: bool,
}

struct CreateForm {
    spec: NewRule,
    error: Option<String>,
}

pub struct App {
    rules: Vec<Rule>,
    analysis: Analysis,
    status: ProfileStatus,
    index: HashMap<String, usize>,
    load_error: Option<String>,
    loading: bool,
    busy: Option<String>,
    tx: Sender<Msg>,
    rx: Receiver<Msg>,

    view: View,
    filters: Filters,
    cleanup_kind: IssueKind,
    port_search: String,
    port_sensitive_only: bool,
    program_search: String,
    program_missing_only: bool,
    selected: HashSet<String>,
    focused: Option<String>,
    sort: (SortCol, bool),
    scroll_to_focus: bool,

    toasts: Vec<Toast>,
    confirm_delete: Option<Vec<String>>,
    create: Option<CreateForm>,
    reviewed: HashSet<String>,
    show_reviewed: bool,
    backed_up: bool,
    elevated: bool,
    logo: TextureHandle,
}

fn reviewed_path() -> PathBuf {
    firewall::data_dir().join("reviewed.txt")
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        install(&cc.egui_ctx);
        if let Ok(h) = cc.window_handle() {
            style_title_bar(h.as_raw());
        }
        let logo = cc.egui_ctx.load_texture(
            "logo",
            egui::ColorImage::from_rgba_unmultiplied([64, 64], &crate::icon::render(64)),
            egui::TextureOptions::LINEAR,
        );
        let reviewed = std::fs::read_to_string(reviewed_path())
            .map(|s| s.lines().filter(|l| !l.trim().is_empty()).map(|l| l.trim().to_string()).collect())
            .unwrap_or_default();

        let (tx, rx) = channel();
        let mut app = App {
            rules: Vec::new(),
            analysis: Analysis::default(),
            status: ProfileStatus::default(),
            index: HashMap::new(),
            load_error: None,
            loading: false,
            busy: None,
            tx,
            rx,
            view: View::Overview,
            filters: Filters { hide_builtin: false, ..Default::default() },
            cleanup_kind: IssueKind::ExposedPort,
            port_search: String::new(),
            port_sensitive_only: false,
            program_search: String::new(),
            program_missing_only: false,
            selected: HashSet::new(),
            focused: None,
            sort: (SortCol::Name, true),
            scroll_to_focus: false,
            toasts: Vec::new(),
            confirm_delete: None,
            create: None,
            reviewed,
            show_reviewed: false,
            backed_up: false,
            elevated: firewall::is_elevated(),
            logo,
        };
        app.reload(&cc.egui_ctx);
        app
    }

    // -----------------------------------------------------------------------------------------
    // Background work
    // -----------------------------------------------------------------------------------------

    fn reload(&mut self, ctx: &egui::Context) {
        if self.loading {
            return;
        }
        self.loading = true;
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let result = firewall::load().map(|snap| {
                let analysis = analysis::analyze(&snap.rules);
                (snap, analysis)
            });
            let _ = tx.send(Msg::Loaded(result));
            ctx.request_repaint();
        });
    }

    fn run_op(
        &mut self,
        ctx: &egui::Context,
        busy: String,
        title: String,
        backup_first: bool,
        op: impl FnOnce() -> OpOutcome + Send + 'static,
    ) {
        if self.busy.is_some() {
            return;
        }
        self.busy = Some(busy);
        let do_backup = backup_first && !self.backed_up;
        if do_backup {
            self.backed_up = true;
        }
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let backup = do_backup.then(firewall::backup);
            let outcome = match &backup {
                Some(Err(e)) => OpOutcome { ok: 0, errors: vec![format!("Aborted - backup failed: {e}")] },
                _ => op(),
            };
            let _ = tx.send(Msg::OpDone { title, outcome, backup });
            ctx.request_repaint();
        });
    }

    fn delete(&mut self, ctx: &egui::Context, ids: Vec<String>) {
        let n = ids.len();
        self.run_op(ctx, format!("Deleting {n} rule(s)..."), format!("Deleted {n} rule(s)"), true, move || {
            firewall::delete_rules(&ids)
        });
    }

    fn set_enabled(&mut self, ctx: &egui::Context, ids: Vec<String>, enabled: bool) {
        let n = ids.len();
        let verb = if enabled { "Enabled" } else { "Disabled" };
        self.run_op(
            ctx,
            format!("{} {n} rule(s)...", if enabled { "Enabling" } else { "Disabling" }),
            format!("{verb} {n} rule(s)"),
            false,
            move || firewall::set_enabled(&ids, enabled),
        );
    }

    fn create_rule(&mut self, ctx: &egui::Context, spec: NewRule) {
        if self.busy.is_some() {
            return;
        }
        self.busy = Some("Creating rule...".into());
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let res = firewall::create_rule(&spec);
            let _ = tx.send(Msg::Created(res, spec));
            ctx.request_repaint();
        });
    }

    fn backup_now(&mut self, ctx: &egui::Context) {
        if self.busy.is_some() {
            return;
        }
        self.busy = Some("Exporting firewall policy...".into());
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let _ = tx.send(Msg::BackupDone(firewall::backup()));
            ctx.request_repaint();
        });
    }

    fn toast(&mut self, ctx: &egui::Context, kind: ToastKind, text: impl Into<String>) {
        self.toasts.push(Toast { text: text.into(), kind, born: ctx.input(|i| i.time) });
    }

    fn poll(&mut self, ctx: &egui::Context) {
        while let Ok(msg) = self.rx.try_recv() {
            match msg {
                Msg::Loaded(Ok((snap, analysis))) => {
                    self.loading = false;
                    self.load_error = None;
                    self.rules = snap.rules;
                    self.status = snap.status;
                    self.analysis = analysis;
                    self.index = self.rules.iter().enumerate().map(|(i, r)| (r.id.clone(), i)).collect();
                    self.selected.retain(|id| self.index.contains_key(id));
                    if self.focused.as_ref().is_some_and(|id| !self.index.contains_key(id)) {
                        self.focused = None;
                    }
                }
                Msg::Loaded(Err(e)) => {
                    self.loading = false;
                    self.load_error = Some(e);
                }
                Msg::OpDone { title, outcome, backup } => {
                    self.busy = None;
                    match backup {
                        Some(Ok(p)) => self.toast(ctx, ToastKind::Ok, format!("Backup saved to {}", p.display())),
                        Some(Err(_)) => self.backed_up = false,
                        None => {}
                    }
                    if outcome.errors.is_empty() {
                        self.toast(ctx, ToastKind::Ok, title);
                    } else {
                        let first = outcome.errors.first().cloned().unwrap_or_default();
                        let more = if outcome.errors.len() > 1 {
                            format!(" (+{} more)", outcome.errors.len() - 1)
                        } else {
                            String::new()
                        };
                        let kind = if outcome.ok > 0 { ToastKind::Warn } else { ToastKind::Err };
                        self.toast(ctx, kind, format!("{} succeeded, {} failed: {first}{more}", outcome.ok, outcome.errors.len()));
                    }
                    self.reload(ctx);
                }
                Msg::Created(res, spec) => {
                    self.busy = None;
                    match res {
                        Ok(()) => {
                            self.toast(ctx, ToastKind::Ok, format!("Created rule \"{}\"", spec.name));
                            self.reload(ctx);
                        }
                        Err(e) => self.create = Some(CreateForm { spec, error: Some(e) }),
                    }
                }
                Msg::BackupDone(res) => {
                    self.busy = None;
                    match res {
                        Ok(p) => {
                            self.backed_up = true;
                            self.toast(ctx, ToastKind::Ok, format!("Backup saved to {}", p.display()));
                        }
                        Err(e) => self.toast(ctx, ToastKind::Err, e),
                    }
                }
            }
        }
    }

    // -----------------------------------------------------------------------------------------
    // Queries
    // -----------------------------------------------------------------------------------------

    fn issues(&self, i: usize) -> &[Issue] {
        if !self.show_reviewed && self.reviewed.contains(&self.rules[i].id) {
            &[]
        } else {
            self.analysis.issues.get(i).map(Vec::as_slice).unwrap_or(&[])
        }
    }

    fn max_severity(&self, i: usize) -> Option<Severity> {
        self.issues(i).iter().map(|x| x.severity).max()
    }

    fn count_kind(&self, kind: IssueKind) -> usize {
        (0..self.rules.len()).filter(|&i| self.issues(i).iter().any(|x| x.kind == kind)).count()
    }

    fn focused_index(&self) -> Option<usize> {
        self.focused.as_ref().and_then(|id| self.index.get(id).copied())
    }

    fn filtered_rules(&self) -> Vec<usize> {
        let f = &self.filters;
        let tokens: Vec<String> = f.search.to_lowercase().split_whitespace().map(str::to_string).collect();
        let mut rows: Vec<usize> = (0..self.rules.len())
            .filter(|&i| {
                let r = &self.rules[i];
                tokens.iter().all(|t| r.haystack.contains(t.as_str()))
                    && f.direction.is_none_or(|d| r.direction == d)
                    && f.action.is_none_or(|a| r.action == a)
                    && f.enabled.is_none_or(|e| r.enabled == e)
                    && f.issue.is_none_or(|k| self.issues(i).iter().any(|x| x.kind == k))
                    && f.port.as_ref().is_none_or(|(p, spec)| r.protocol == *p && r.service_ports().contains(spec))
                    && f.program.as_ref().is_none_or(|(key, _)| analysis::program_key(r) == *key)
                    && !(f.hide_builtin && r.builtin)
                    && !(f.issues_only && self.issues(i).is_empty())
            })
            .collect();
        self.sort_rows(&mut rows);
        rows
    }

    fn sort_rows(&self, rows: &mut [usize]) {
        let (col, asc) = self.sort;
        let keyed: HashMap<usize, String> = match col {
            SortCol::Name => rows.iter().map(|&i| (i, self.rules[i].name.to_lowercase())).collect(),
            SortCol::Program => rows.iter().map(|&i| (i, self.rules[i].program_label().to_lowercase())).collect(),
            SortCol::Ports => rows.iter().map(|&i| (i, firewall::ports_label(self.rules[i].service_ports()))).collect(),
            _ => HashMap::new(),
        };
        rows.sort_by(|&a, &b| {
            let (ra, rb) = (&self.rules[a], &self.rules[b]);
            let o = match col {
                SortCol::Name | SortCol::Program => keyed[&a].cmp(&keyed[&b]),
                SortCol::Ports => {
                    let first = |r: &Rule| r.service_ports().first().cloned();
                    first(ra).cmp(&first(rb)).then_with(|| keyed[&a].cmp(&keyed[&b]))
                }
                SortCol::Direction => (ra.direction as u8).cmp(&(rb.direction as u8)),
                SortCol::Action => (ra.action as u8).cmp(&(rb.action as u8)),
                SortCol::Protocol => ra.protocol.number().cmp(&rb.protocol.number()),
                SortCol::Severity => self.max_severity(a).cmp(&self.max_severity(b)),
            };
            let o = o.then_with(|| ra.name.cmp(&rb.name));
            if asc {
                o
            } else {
                o.reverse()
            }
        });
    }

    fn set_reviewed(&mut self, ids: &[String], reviewed: bool) {
        for id in ids {
            if reviewed {
                self.reviewed.insert(id.clone());
            } else {
                self.reviewed.remove(id);
            }
        }
        let _ = std::fs::create_dir_all(firewall::data_dir());
        let mut list: Vec<&String> = self.reviewed.iter().collect();
        list.sort();
        let text = list.into_iter().map(String::as_str).collect::<Vec<_>>().join("\n");
        let _ = std::fs::write(reviewed_path(), text);
    }

    fn focus_rule(&mut self, i: usize) {
        self.focused = Some(self.rules[i].id.clone());
        self.scroll_to_focus = true;
    }

    fn go_rules_with(&mut self, f: impl FnOnce(&mut Filters)) {
        self.filters = Filters::default();
        f(&mut self.filters);
        self.view = View::Rules;
    }
}

// =============================================================================================
// Small widgets
// =============================================================================================

fn card() -> Frame {
    Frame::new()
        .fill(SURFACE)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(14)
        .inner_margin(Margin::same(16))
}

fn pill(ui: &mut Ui, text: impl Into<String>, color: Color32) -> egui::Response {
    let galley = ui.painter().layout_no_wrap(text.into(), FontId::proportional(12.0), color);
    let pad = egui::vec2(8.0, 3.0);
    let (rect, resp) = ui.allocate_exact_size(galley.size() + pad * 2.0, Sense::hover());
    ui.painter().rect_filled(rect, CornerRadius::same((rect.height() / 2.0) as u8), tint(color, 34));
    ui.painter().galley(rect.min + pad, galley, color);
    resp
}

fn dot(ui: &mut Ui, color: Color32) -> egui::Response {
    let (rect, resp) = ui.allocate_exact_size(egui::vec2(10.0, 16.0), Sense::hover());
    ui.painter().circle_filled(rect.center(), 4.0, color);
    resp
}

/// Compact profile badges. Public is amber since it's the most exposed network type.
fn profile_pills(ui: &mut Ui, profiles: u8, dim: bool) {
    ui.spacing_mut().item_spacing.x = 3.0;
    if profiles == PROFILE_DOMAIN | PROFILE_PRIVATE | PROFILE_PUBLIC {
        pill(ui, "All", if dim { TEXT_FAINT } else { TEXT_DIM }).on_hover_text("Domain, Private and Public");
        return;
    }
    for (bit, short, full, color) in [
        (PROFILE_DOMAIN, "Dom", "Domain", BLUE),
        (PROFILE_PRIVATE, "Priv", "Private", GREEN),
        (PROFILE_PUBLIC, "Pub", "Public", AMBER),
    ] {
        if profiles & bit != 0 {
            pill(ui, short, if dim { TEXT_FAINT } else { color }).on_hover_text(full);
        }
    }
}

fn icon_text(icon: &str, text: &str) -> String {
    format!("{icon}  {text}")
}

fn primary_button(text: impl Into<String>) -> egui::Button<'static> {
    egui::Button::new(RichText::new(text.into()).color(Color32::WHITE))
        .fill(ACCENT_DEEP)
        .stroke(Stroke::NONE)
        .corner_radius(9)
}

fn danger_button(text: impl Into<String>) -> egui::Button<'static> {
    egui::Button::new(RichText::new(text.into()).color(RED))
        .fill(tint(RED, 30))
        .stroke(Stroke::new(1.0, tint(RED, 70)))
        .corner_radius(9)
}

fn ghost_button(text: impl Into<String>) -> egui::Button<'static> {
    egui::Button::new(RichText::new(text.into()).color(TEXT)).corner_radius(9)
}

fn segmented<T: PartialEq + Copy>(ui: &mut Ui, value: &mut T, options: &[(T, &str)]) -> bool {
    let mut changed = false;
    Frame::new()
        .fill(SURFACE)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(10)
        .inner_margin(Margin::same(3))
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.x = 2.0;
            ui.horizontal(|ui| {
                for (v, label) in options {
                    let sel = *value == *v;
                    let text = RichText::new(*label).size(13.0).color(if sel { Color32::WHITE } else { TEXT_DIM });
                    let btn = egui::Button::new(text)
                        .fill(if sel { SURFACE_HOVER } else { Color32::TRANSPARENT })
                        .stroke(Stroke::NONE)
                        .corner_radius(7)
                        .min_size(egui::vec2(0.0, 24.0));
                    if ui.add(btn).clicked() && !sel {
                        *value = *v;
                        changed = true;
                    }
                }
            });
        });
    changed
}

fn toggle_chip(ui: &mut Ui, on: &mut bool, label: &str) {
    let color = if *on { ACCENT } else { TEXT_DIM };
    let btn = egui::Button::new(RichText::new(icon_text(if *on { ph::CHECK_CIRCLE } else { ph::CIRCLE }, label)).size(13.0).color(color))
        .fill(if *on { tint(ACCENT, 26) } else { SURFACE })
        .stroke(Stroke::new(1.0, if *on { tint(ACCENT, 90) } else { BORDER }))
        .corner_radius(15)
        .min_size(egui::vec2(0.0, 30.0));
    if ui.add(btn).clicked() {
        *on = !*on;
    }
}

/// Removable chip for an active filter. Returns true when the "x" was clicked.
fn filter_chip(ui: &mut Ui, label: &str) -> bool {
    let btn = egui::Button::new(RichText::new(format!("{label}   {}", ph::X)).size(13.0).color(ACCENT))
        .fill(tint(ACCENT, 26))
        .stroke(Stroke::new(1.0, tint(ACCENT, 90)))
        .corner_radius(15)
        .min_size(egui::vec2(0.0, 30.0));
    ui.add(btn).on_hover_text("Clear filter").clicked()
}

fn search_box(ui: &mut Ui, text: &mut String, hint: &str, width: f32, id: &str) -> egui::Response {
    Frame::new()
        .fill(Color32::from_rgb(0x15, 0x17, 0x1e))
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(10)
        .inner_margin(Margin::symmetric(10, 4))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new(ph::MAGNIFYING_GLASS).color(TEXT_FAINT));
                let resp = ui.add(
                    egui::TextEdit::singleline(text)
                        .id(egui::Id::new(id))
                        .hint_text(RichText::new(hint).color(TEXT_FAINT))
                        .frame(false)
                        .desired_width(width),
                );
                if !text.is_empty() && ui.add(egui::Button::new(RichText::new(ph::X).color(TEXT_DIM)).frame(false)).clicked() {
                    text.clear();
                }
                resp
            })
            .inner
        })
        .inner
}

fn severity_color(s: Severity) -> Color32 {
    match s {
        Severity::High => RED,
        Severity::Medium => AMBER,
        Severity::Low => YELLOW,
        Severity::Info => BLUE,
    }
}

fn risk_color(r: Risk) -> Color32 {
    match r {
        Risk::Critical => RED,
        Risk::Sensitive => AMBER,
        Risk::Notable => BLUE,
    }
}

fn kind_icon(k: IssueKind) -> &'static str {
    match k {
        IssueKind::MissingProgram => ph::FILE_X,
        IssueKind::Duplicate => ph::COPY,
        IssueKind::Covered => ph::STACK,
        IssueKind::ExposedPort => ph::PLUGS,
        IssueKind::BroadInbound => ph::WARNING_OCTAGON,
        IssueKind::SuspiciousPath => ph::WARNING,
        IssueKind::Disabled => ph::TOGGLE_LEFT,
    }
}

fn kind_color(k: IssueKind) -> Color32 {
    match k {
        IssueKind::ExposedPort | IssueKind::BroadInbound => RED,
        IssueKind::MissingProgram | IssueKind::SuspiciousPath => AMBER,
        IssueKind::Duplicate | IssueKind::Covered => VIOLET,
        IssueKind::Disabled => BLUE,
    }
}

fn direction_text(d: Direction) -> RichText {
    match d {
        Direction::In => RichText::new(icon_text(ph::ARROW_DOWN_LEFT, "In")).color(BLUE),
        Direction::Out => RichText::new(icon_text(ph::ARROW_UP_RIGHT, "Out")).color(VIOLET),
    }
}

fn action_color(a: Action) -> Color32 {
    match a {
        Action::Allow => GREEN,
        Action::Block => RED,
    }
}

fn action_label(a: Action) -> &'static str {
    match a {
        Action::Allow => "Allow",
        Action::Block => "Block",
    }
}

/// Port list where sensitive ports on inbound-allow rules are coloured by risk.
fn ports_job(r: &Rule) -> LayoutJob {
    let mut job = LayoutJob::default();
    let font = FontId::proportional(13.5);
    let ports = r.service_ports();
    if ports.is_empty() {
        job.append("Any", 0.0, TextFormat::simple(font, TEXT_FAINT));
        return job;
    }
    let exposed = r.direction == Direction::In && r.action == Action::Allow;
    for (n, spec) in ports.iter().enumerate() {
        if n > 0 {
            job.append(", ", 0.0, TextFormat::simple(font.clone(), TEXT_FAINT));
        }
        let known = match spec {
            PortSpec::Range(a, b) if a == b => crate::ports::lookup(*a),
            _ => None,
        };
        let color = match known {
            Some(k) if exposed => risk_color(k.risk),
            _ => TEXT,
        };
        job.append(&spec.label(), 0.0, TextFormat::simple(font.clone(), color));
    }
    job
}

fn file_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

// =============================================================================================
// eframe
// =============================================================================================

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll(ctx);
        self.shortcuts(ctx);

        egui::SidePanel::left("nav")
            .exact_width(236.0)
            .resizable(false)
            .show_separator_line(false)
            .frame(Frame::new().fill(SIDEBAR).inner_margin(Margin { left: 14, right: 14, top: 18, bottom: 14 }))
            .show(ctx, |ui| self.sidebar(ui));

        let show_details = matches!(self.view, View::Rules | View::Cleanup) && self.focused_index().is_some();
        if show_details {
            egui::SidePanel::right("details")
                .default_width(400.0)
                .width_range(340.0..=620.0)
                .show_separator_line(false)
                .frame(
                    Frame::new()
                        .fill(SIDEBAR)
                        .inner_margin(Margin::same(18))
                        .stroke(Stroke::new(1.0, BORDER)),
                )
                .show(ctx, |ui| self.details(ui));
        }

        egui::CentralPanel::default()
            .frame(Frame::new().fill(BG).inner_margin(Margin { left: 24, right: 24, top: 20, bottom: 16 }))
            .show(ctx, |ui| {
                if let Some(err) = &self.load_error {
                    ui.colored_label(RED, icon_text(ph::WARNING, &format!("Could not read firewall rules: {err}")));
                    ui.add_space(8.0);
                }
                if !self.elevated {
                    Frame::new().fill(tint(AMBER, 24)).corner_radius(10).inner_margin(Margin::same(10)).show(ui, |ui| {
                        ui.colored_label(
                            AMBER,
                            icon_text(ph::WARNING, "Not running as administrator - changes to rules will fail."),
                        );
                    });
                    ui.add_space(8.0);
                }
                if self.rules.is_empty() && self.loading {
                    ui.centered_and_justified(|ui| {
                        ui.horizontal_centered(|ui| {
                            ui.spinner();
                            ui.label(RichText::new("Reading firewall rules...").color(TEXT_DIM));
                        });
                    });
                    return;
                }
                match self.view {
                    View::Overview => self.overview(ui),
                    View::Rules => self.rules_view(ui),
                    View::Cleanup => self.cleanup_view(ui),
                    View::Ports => self.ports_view(ui),
                    View::Programs => self.programs_view(ui),
                }
            });

        self.confirm_modal(ctx);
        self.create_modal(ctx);
        self.busy_overlay(ctx);
        self.toasts_ui(ctx);
    }
}

impl App {
    fn shortcuts(&mut self, ctx: &egui::Context) {
        let typing = ctx.wants_keyboard_input();
        let modal_open = self.confirm_delete.is_some() || self.create.is_some();
        if ctx.input(|i| i.modifiers.command && i.key_pressed(Key::F)) && !modal_open {
            if !matches!(self.view, View::Rules) {
                self.view = View::Rules;
            }
            ctx.memory_mut(|m| m.request_focus(egui::Id::new("rules_search")));
        }
        if ctx.input(|i| i.modifiers.command && i.key_pressed(Key::N)) && !modal_open {
            self.create = Some(CreateForm { spec: NewRule::default(), error: None });
        }
        if ctx.input(|i| i.key_pressed(Key::F5)) {
            self.reload(ctx);
        }
        if !typing && !modal_open && ctx.input(|i| i.key_pressed(Key::Delete)) {
            let ids = self.deletable(&self.selected.iter().cloned().collect::<Vec<_>>());
            if !ids.is_empty() {
                self.confirm_delete = Some(ids);
            }
        }
        if !typing && !modal_open && ctx.input(|i| i.key_pressed(Key::Escape)) {
            if self.focused.is_some() {
                self.focused = None;
            } else {
                self.selected.clear();
            }
        }
    }

    fn deletable(&self, ids: &[String]) -> Vec<String> {
        ids.iter()
            .filter(|id| self.index.get(*id).is_some_and(|&i| self.rules[i].can_modify()))
            .cloned()
            .collect()
    }

    // -----------------------------------------------------------------------------------------
    // Sidebar
    // -----------------------------------------------------------------------------------------

    fn sidebar(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            ui.add(egui::Image::new(&self.logo).fit_to_exact_size(Vec2::splat(36.0)));
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 0.0;
                ui.label(RichText::new("Firewall").family(semibold()).size(16.0).color(TEXT));
                ui.label(RichText::new("Manager").size(13.0).color(TEXT_DIM));
            });
        });
        ui.add_space(22.0);

        let attention = (0..self.rules.len())
            .filter(|&i| self.issues(i).iter().any(|x| x.severity >= Severity::Low))
            .count();
        let nav = [
            (View::Overview, ph::SQUARES_FOUR, "Overview", None),
            (View::Rules, ph::LIST_BULLETS, "All rules", Some((self.rules.len(), TEXT_DIM))),
            (View::Cleanup, ph::BROOM, "Cleanup", Some((attention, AMBER))),
            (View::Ports, ph::PLUGS, "Ports", Some((self.analysis.ports.len(), TEXT_DIM))),
            (View::Programs, ph::APP_WINDOW, "Programs", Some((self.analysis.programs.len(), TEXT_DIM))),
        ];
        for (view, icon, label, badge) in nav {
            if self.nav_item(ui, icon, label, self.view == view, badge).clicked() {
                if view == View::Rules && self.view != View::Rules {
                    self.filters = Filters::default();
                }
                self.view = view;
            }
        }

        ui.with_layout(Layout::bottom_up(Align::Min), |ui| {
            ui.spacing_mut().item_spacing.y = 6.0;
            let busy = self.busy.is_some();
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(!busy, ghost_button(icon_text(ph::DOWNLOAD_SIMPLE, "Backup")).min_size(egui::vec2(100.0, 32.0)))
                    .on_hover_text("Export the full firewall policy (.wfw) - restore with\n`netsh advfirewall import <file>`")
                    .clicked()
                {
                    self.backup_now(ui.ctx());
                }
                if ui
                    .add(ghost_button(ph::FOLDER_OPEN).min_size(egui::vec2(36.0, 32.0)))
                    .on_hover_text("Open backups folder")
                    .clicked()
                {
                    let dir = firewall::backup_dir();
                    let _ = std::fs::create_dir_all(&dir);
                    firewall::open_in_explorer(&dir.to_string_lossy(), false);
                }
                if ui
                    .add_enabled(!self.loading, ghost_button(ph::ARROWS_CLOCKWISE).min_size(egui::vec2(36.0, 32.0)))
                    .on_hover_text("Reload rules (F5)")
                    .clicked()
                {
                    self.reload(ui.ctx());
                }
            });
            ui.add_space(6.0);
            self.profile_status_small(ui);
            ui.add_space(2.0);
            ui.label(RichText::new("FIREWALL STATUS").size(11.0).color(TEXT_FAINT));
        });
    }

    fn nav_item(&self, ui: &mut Ui, icon: &str, label: &str, active: bool, badge: Option<(usize, Color32)>) -> egui::Response {
        let (rect, resp) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 38.0), Sense::click());
        let p = ui.painter();
        if active {
            p.rect_filled(rect, CornerRadius::same(10), tint(ACCENT, 30));
            let bar = egui::Rect::from_min_size(rect.left_top() + egui::vec2(0.0, 10.0), egui::vec2(3.0, 18.0));
            p.rect_filled(bar, CornerRadius::same(2), ACCENT);
        } else if resp.hovered() {
            p.rect_filled(rect, CornerRadius::same(10), tint(Color32::WHITE, 8));
        }
        let fg = if active { Color32::WHITE } else { TEXT_DIM };
        p.text(rect.left_center() + egui::vec2(16.0, 0.0), egui::Align2::LEFT_CENTER, icon, FontId::proportional(17.0), if active { ACCENT } else { fg });
        p.text(rect.left_center() + egui::vec2(44.0, 0.0), egui::Align2::LEFT_CENTER, label, FontId::proportional(14.5), fg);
        if let Some((n, color)) = badge {
            if n > 0 {
                let galley = p.layout_no_wrap(n.to_string(), FontId::proportional(11.5), color);
                let size = galley.size() + egui::vec2(12.0, 4.0);
                let r = egui::Rect::from_center_size(rect.right_center() - egui::vec2(size.x / 2.0 + 8.0, 0.0), size);
                p.rect_filled(r, CornerRadius::same((size.y / 2.0) as u8), tint(color, 30));
                p.galley(r.min + egui::vec2(6.0, 2.0), galley, color);
            }
        }
        resp.on_hover_cursor(egui::CursorIcon::PointingHand)
    }

    /// Drawn inside a bottom-up layout, hence the reversed order.
    fn profile_status_small(&self, ui: &mut Ui) {
        for (n, (name, bit)) in [("Domain", PROFILE_DOMAIN), ("Private", PROFILE_PRIVATE), ("Public", PROFILE_PUBLIC)].into_iter().enumerate().rev() {
            ui.horizontal(|ui| {
                let (color, state) = match self.status.enabled[n] {
                    Some(true) => (GREEN, "On"),
                    Some(false) => (RED, "Off"),
                    None => (TEXT_FAINT, "?"),
                };
                dot(ui, color);
                ui.label(RichText::new(name).color(TEXT_DIM).size(13.0));
                if self.status.active & bit != 0 {
                    pill(ui, "active", ACCENT);
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.label(RichText::new(state).color(color).size(13.0));
                });
            });
        }
    }

    fn page_header(&mut self, ui: &mut Ui, title: &str, subtitle: &str) {
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 2.0;
                ui.heading(title);
                ui.label(RichText::new(subtitle).color(TEXT_DIM));
            });
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui
                    .add_enabled(self.busy.is_none(), primary_button(icon_text(ph::PLUS, "New rule")).min_size(egui::vec2(0.0, 36.0)))
                    .on_hover_text("Ctrl+N")
                    .clicked()
                {
                    self.create = Some(CreateForm { spec: NewRule::default(), error: None });
                }
                if self.loading {
                    ui.spinner();
                }
            });
        });
        ui.add_space(14.0);
    }

    // -----------------------------------------------------------------------------------------
    // Overview
    // -----------------------------------------------------------------------------------------

    fn overview(&mut self, ui: &mut Ui) {
        self.page_header(ui, "Overview", "A quick look at what your firewall lets through and what needs attention.");

        let total = self.rules.len();
        let enabled = self.rules.iter().filter(|r| r.enabled).count();
        let inbound: Vec<&Rule> =
            self.rules.iter().filter(|r| r.enabled && r.direction == Direction::In && r.action == Action::Allow).collect();
        let inbound_allow = inbound.len();
        let open_any = inbound.iter().filter(|r| r.remote_addrs.is_empty()).count();
        let flagged = (0..total).filter(|&i| self.issues(i).iter().any(|x| x.severity >= Severity::Low)).count();
        let high = (0..total).filter(|&i| self.max_severity(i) == Some(Severity::High)).count();
        let missing_programs = self.analysis.programs.iter().filter(|p| p.state == AppState::Missing).count();
        let custom = self.rules.iter().filter(|r| !r.builtin).count();

        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            let mut go: Option<View> = None;
            let mut go_inbound = false;
            ui.columns(4, |cols| {
                if stat_card(&mut cols[0], ph::LIST_BULLETS, ACCENT, total.to_string(), "Rules",
                    &format!("{enabled} enabled · {custom} custom")).clicked() {
                    go = Some(View::Rules);
                }
                if stat_card(&mut cols[1], ph::ARROW_DOWN_LEFT, BLUE, inbound_allow.to_string(), "Inbound allowed",
                    &format!("{open_any} open to any address")).clicked() {
                    go_inbound = true;
                }
                if stat_card(&mut cols[2], ph::BROOM, if high > 0 { RED } else { AMBER }, flagged.to_string(), "Rules to review",
                    &format!("{high} high severity")).clicked() {
                    go = Some(View::Cleanup);
                }
                if stat_card(&mut cols[3], ph::APP_WINDOW, VIOLET, self.analysis.programs.len().to_string(), "Programs",
                    &format!("{missing_programs} no longer installed")).clicked() {
                    go = Some(View::Programs);
                }
            });
            if go_inbound {
                self.go_rules_with(|f| {
                    f.direction = Some(Direction::In);
                    f.action = Some(Action::Allow);
                    f.enabled = Some(true);
                });
            }
            if let Some(v) = go {
                if v == View::Rules {
                    self.filters = Filters::default();
                }
                self.view = v;
            }
            ui.add_space(12.0);

            ui.columns(2, |cols| {
                self.attention_card(&mut cols[0]);
                self.cleanup_summary_card(&mut cols[1]);
                cols[1].add_space(12.0);
                self.exposed_ports_card(&mut cols[1]);
            });
        });
    }

    fn attention_card(&mut self, ui: &mut Ui) {
        let mut items: Vec<(usize, Issue)> = (0..self.rules.len())
            .flat_map(|i| self.issues(i).iter().filter(|x| x.severity >= Severity::Medium).map(move |x| (i, x.clone())))
            .collect();
        items.sort_by(|a, b| b.1.severity.cmp(&a.1.severity).then(self.rules[a.0].name.cmp(&self.rules[b.0].name)));
        let total = items.len();
        let mut clicked = None;
        let mut show_more = false;
        card().show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(RichText::new(icon_text(ph::WARNING, "Needs attention")).family(semibold()).size(16.0));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    pill(ui, format!("{total}"), if total > 0 { AMBER } else { GREEN });
                });
            });
            ui.add_space(6.0);
            if items.is_empty() {
                ui.label(RichText::new(icon_text(ph::SEAL_CHECK, "Nothing important found. Nice and tidy.")).color(GREEN));
                return;
            }
            for (i, issue) in items.iter().take(14) {
                let r = &self.rules[*i];
                let resp = Frame::new()
                    .corner_radius(10)
                    .inner_margin(Margin::symmetric(10, 7))
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(kind_icon(issue.kind)).color(severity_color(issue.severity)).size(16.0));
                            ui.vertical(|ui| {
                                ui.spacing_mut().item_spacing.y = 1.0;
                                ui.add(egui::Label::new(RichText::new(&r.name).color(TEXT)).truncate());
                                ui.add(egui::Label::new(RichText::new(&issue.detail).color(TEXT_DIM).size(12.5)).truncate());
                            });
                        });
                    })
                    .response
                    .interact(Sense::click());
                if resp.hovered() {
                    ui.painter().rect_filled(resp.rect, CornerRadius::same(10), tint(Color32::WHITE, 7));
                }
                if resp.on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
                    clicked = Some(*i);
                }
            }
            if total > 14 {
                ui.add_space(4.0);
                if ui.link(format!("and {} more in Cleanup", total - 14)).clicked() {
                    show_more = true;
                }
            }
        });
        if show_more {
            self.view = View::Cleanup;
        }
        if let Some(i) = clicked {
            self.go_rules_with(|_| {});
            self.focus_rule(i);
        }
    }

    fn cleanup_summary_card(&mut self, ui: &mut Ui) {
        let counts: Vec<(IssueKind, usize)> = IssueKind::ALL.iter().map(|&k| (k, self.count_kind(k))).collect();
        card().show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new(icon_text(ph::BROOM, "Cleanup candidates")).family(semibold()).size(16.0));
            ui.add_space(6.0);
            for (kind, n) in counts {
                let resp = ui
                    .horizontal(|ui| {
                        ui.label(RichText::new(kind_icon(kind)).color(kind_color(kind)).size(15.0));
                        ui.label(RichText::new(kind.title()).color(if n > 0 { TEXT } else { TEXT_FAINT }));
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            ui.label(RichText::new(ph::CARET_UP).color(TEXT_FAINT).size(1.0)); // keeps row height stable
                            pill(ui, n.to_string(), if n > 0 { kind_color(kind) } else { TEXT_FAINT });
                        });
                    })
                    .response
                    .interact(Sense::click());
                if resp.on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
                    self.cleanup_kind = kind;
                    self.view = View::Cleanup;
                }
            }
        });
    }

    fn exposed_ports_card(&mut self, ui: &mut Ui) {
        let mut exposed: Vec<(usize, &analysis::PortEntry)> = self
            .analysis
            .ports
            .iter()
            .enumerate()
            .filter(|(_, p)| p.known.is_some() && p.inbound_allow > 0)
            .collect();
        exposed.sort_by(|a, b| b.1.known.unwrap().risk.cmp(&a.1.known.unwrap().risk).then(a.1.spec.cmp(&b.1.spec)));
        let mut clicked = None;
        card().show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new(icon_text(ph::PLUGS, "Well-known ports open inbound")).family(semibold()).size(16.0));
            ui.add_space(6.0);
            if exposed.is_empty() {
                ui.label(RichText::new("No sensitive ports are open inbound.").color(GREEN));
                return;
            }
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing = egui::vec2(6.0, 6.0);
                for (idx, p) in &exposed {
                    let k = p.known.unwrap();
                    let color = risk_color(k.risk);
                    let text = format!("{} {} · {}", p.spec.label(), k.name, p.inbound_allow);
                    let btn = egui::Button::new(RichText::new(text).size(13.0).color(color))
                        .fill(tint(color, 24))
                        .stroke(Stroke::new(1.0, tint(color, 60)))
                        .corner_radius(14);
                    if ui.add(btn).on_hover_text(format!("{} ({})\n{} enabled inbound allow rule(s)", k.why, p.protocol.label(), p.inbound_allow)).clicked() {
                        clicked = Some(*idx);
                    }
                }
            });
        });
        if let Some(idx) = clicked {
            let p = &self.analysis.ports[idx];
            let key = (p.protocol, p.spec.clone());
            self.go_rules_with(|f| f.port = Some(key));
        }
    }

    // -----------------------------------------------------------------------------------------
    // Rules
    // -----------------------------------------------------------------------------------------

    fn rules_view(&mut self, ui: &mut Ui) {
        self.page_header(ui, "All rules", "Search, filter and manage every firewall rule.");
        let rows = self.filtered_rules();

        // Framed controls can't wrap, so lay them out in two fixed rows.
        ui.horizontal(|ui| {
            search_box(ui, &mut self.filters.search, "Search name, program, port, group...  (Ctrl+F)", 300.0, "rules_search");
            toggle_chip(ui, &mut self.filters.hide_builtin, "Hide built-in");
            toggle_chip(ui, &mut self.filters.issues_only, "Only flagged");
        });
        ui.horizontal(|ui| {
            segmented(ui, &mut self.filters.direction, &[(None, "All"), (Some(Direction::In), "Inbound"), (Some(Direction::Out), "Outbound")]);
            segmented(ui, &mut self.filters.action, &[(None, "All"), (Some(Action::Allow), "Allow"), (Some(Action::Block), "Block")]);
            segmented(ui, &mut self.filters.enabled, &[(None, "All"), (Some(true), "Enabled"), (Some(false), "Disabled")]);
        });

        let has_chips = self.filters.port.is_some() || self.filters.program.is_some() || self.filters.issue.is_some();
        if has_chips {
            ui.add_space(4.0);
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("Filtered by").color(TEXT_DIM));
                if let Some((proto, spec)) = &self.filters.port {
                    if filter_chip(ui, &format!("{} port {}", proto.label(), spec.label())) {
                        self.filters.port = None;
                    }
                }
                if let Some((_, label)) = &self.filters.program {
                    if filter_chip(ui, &format!("Program {}", file_name(label))) {
                        self.filters.program = None;
                    }
                }
                if let Some(kind) = self.filters.issue {
                    if filter_chip(ui, kind.title()) {
                        self.filters.issue = None;
                    }
                }
            });
        }
        ui.add_space(8.0);
        self.selection_bar(ui, &rows);
        self.rules_table(ui, &rows, "rules_table");
    }

    fn selection_bar(&mut self, ui: &mut Ui, rows: &[usize]) {
        let visible_selected = rows.iter().filter(|&&i| self.selected.contains(&self.rules[i].id)).count();
        ui.horizontal(|ui| {
            ui.label(RichText::new(format!("{} rules", rows.len())).color(TEXT_DIM));
            if self.selected.is_empty() {
                ui.label(RichText::new("·  tick rules to act on many at once").color(TEXT_FAINT));
                return;
            }
            ui.label(RichText::new("·").color(TEXT_FAINT));
            ui.label(RichText::new(format!("{} selected", self.selected.len())).color(ACCENT));
            if visible_selected != self.selected.len() {
                ui.label(RichText::new(format!("({} hidden by filters)", self.selected.len() - visible_selected)).color(TEXT_FAINT));
            }
            ui.add_space(8.0);
            let ids: Vec<String> = self.selected.iter().cloned().collect();
            let modifiable = self.deletable(&ids);
            let enabled = self.busy.is_none() && !modifiable.is_empty();
            if ui.add_enabled(enabled, ghost_button(icon_text(ph::TOGGLE_RIGHT, "Enable"))).clicked() {
                self.set_enabled(ui.ctx(), modifiable.clone(), true);
            }
            if ui.add_enabled(enabled, ghost_button(icon_text(ph::TOGGLE_LEFT, "Disable"))).clicked() {
                self.set_enabled(ui.ctx(), modifiable.clone(), false);
            }
            if ui.add_enabled(enabled, danger_button(icon_text(ph::TRASH, "Delete"))).on_hover_text("Del").clicked() {
                self.confirm_delete = Some(modifiable.clone());
            }
            if ui
                .add(ghost_button(icon_text(ph::EYE_SLASH, "Mark reviewed")))
                .on_hover_text("Hide these rules' findings in Cleanup (kept between sessions)")
                .clicked()
            {
                self.set_reviewed(&ids, true);
            }
            if ui.add(egui::Button::new(RichText::new("Clear selection").color(TEXT_DIM)).frame(false)).clicked() {
                self.selected.clear();
            }
        });
        ui.add_space(6.0);
    }

    fn sort_header(&mut self, ui: &mut Ui, label: &str, col: SortCol) {
        let active = self.sort.0 == col;
        let arrow = if active { if self.sort.1 { ph::CARET_UP } else { ph::CARET_DOWN } } else { "" };
        let text = RichText::new(format!("{label} {arrow}")).size(12.5).color(if active { TEXT } else { TEXT_DIM });
        let resp = ui.add(egui::Label::new(text).sense(Sense::click())).on_hover_cursor(egui::CursorIcon::PointingHand);
        if resp.clicked() {
            if active {
                self.sort.1 = !self.sort.1;
            } else {
                self.sort = (col, col != SortCol::Severity);
            }
        }
    }

    fn rules_table(&mut self, ui: &mut Ui, rows: &[usize], id: &str) {
        if rows.is_empty() {
            ui.add_space(40.0);
            ui.vertical_centered(|ui| {
                ui.label(RichText::new(ph::FUNNEL_X).size(36.0).color(TEXT_FAINT));
                ui.label(RichText::new("No rules match.").color(TEXT_DIM));
            });
            return;
        }
        let focus_row = if self.scroll_to_focus {
            self.scroll_to_focus = false;
            self.focused.as_ref().and_then(|f| rows.iter().position(|&i| self.rules[i].id == *f))
        } else {
            None
        };

        let mut toggles: Vec<(String, bool)> = Vec::new();
        let mut focus: Option<String> = None;
        let all_selected = rows.iter().all(|&i| self.selected.contains(&self.rules[i].id));
        let mut select_all: Option<bool> = None;

        Frame::new()
            .fill(SURFACE)
            .stroke(Stroke::new(1.0, BORDER))
            .corner_radius(14)
            .inner_margin(Margin { left: 6, right: 6, top: 6, bottom: 2 })
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                // Drop less important columns when space is tight (e.g. details panel open).
                let w = ui.available_width();
                let cols: Vec<Col> = [
                    (Col::Check, 0.0),
                    (Col::Status, 0.0),
                    (Col::Name, 0.0),
                    (Col::Dir, 700.0),
                    (Col::Action, 0.0),
                    (Col::Proto, 1000.0),
                    (Col::Ports, 0.0),
                    (Col::Remote, 1120.0),
                    (Col::Program, 860.0),
                    (Col::Profiles, 940.0),
                    (Col::Findings, 0.0),
                ]
                .into_iter()
                .filter(|(_, min)| w >= *min)
                .map(|(c, _)| c)
                .collect();

                let mut table = TableBuilder::new(ui)
                    .id_salt((id, cols.len()))
                    .striped(false)
                    .resizable(true)
                    .sense(Sense::click())
                    .cell_layout(Layout::left_to_right(Align::Center))
                    .auto_shrink([false, false]);
                for c in &cols {
                    table = table.column(match c {
                        Col::Check => Column::exact(28.0),
                        Col::Status => Column::exact(16.0),
                        Col::Name => Column::remainder().at_least(160.0).clip(true),
                        Col::Dir => Column::exact(62.0),
                        Col::Action => Column::exact(68.0),
                        Col::Proto => Column::exact(60.0),
                        Col::Ports => Column::initial(110.0).at_least(60.0).clip(true),
                        Col::Remote => Column::initial(110.0).at_least(60.0).clip(true),
                        Col::Program => Column::initial(180.0).at_least(80.0).clip(true),
                        Col::Profiles => Column::initial(130.0).at_least(50.0).clip(true),
                        Col::Findings => Column::initial(140.0).at_least(60.0).clip(true),
                    });
                }
                if let Some(r) = focus_row {
                    table = table.scroll_to_row(r, Some(Align::Center));
                }
                table
                    .header(30.0, |mut h| {
                        for c in &cols {
                            h.col(|ui| match c {
                                Col::Check => {
                                    let mut v = all_selected;
                                    if ui.checkbox(&mut v, "").on_hover_text("Select all shown").changed() {
                                        select_all = Some(v);
                                    }
                                }
                                Col::Status => {}
                                Col::Name => self.sort_header(ui, "Name", SortCol::Name),
                                Col::Dir => self.sort_header(ui, "Dir", SortCol::Direction),
                                Col::Action => self.sort_header(ui, "Action", SortCol::Action),
                                Col::Proto => self.sort_header(ui, "Proto", SortCol::Protocol),
                                Col::Ports => self.sort_header(ui, "Ports", SortCol::Ports),
                                Col::Remote => {
                                    ui.label(RichText::new("Remote").size(12.5).color(TEXT_DIM));
                                }
                                Col::Program => self.sort_header(ui, "Program", SortCol::Program),
                                Col::Profiles => {
                                    ui.label(RichText::new("Profiles").size(12.5).color(TEXT_DIM));
                                }
                                Col::Findings => self.sort_header(ui, "Findings", SortCol::Severity),
                            });
                        }
                    })
                    .body(|body| {
                        body.rows(34.0, rows.len(), |mut row| {
                            let i = rows[row.index()];
                            let r = &self.rules[i];
                            let is_sel = self.selected.contains(&r.id);
                            let is_focus = self.focused.as_deref() == Some(r.id.as_str());
                            row.set_selected(is_focus);
                            let dim = !r.enabled;
                            let text_color = if dim { TEXT_FAINT } else { TEXT };

                            for c in &cols {
                                row.col(|ui| match c {
                                    Col::Check => {
                                        let mut v = is_sel;
                                        if ui.checkbox(&mut v, "").changed() {
                                            toggles.push((r.id.clone(), v));
                                        }
                                    }
                                    Col::Status => {
                                        let c = if r.enabled { GREEN } else { TEXT_FAINT };
                                        dot(ui, c).on_hover_text(if r.enabled { "Enabled" } else { "Disabled" });
                                    }
                                    Col::Name => {
                                        if r.source == Source::GroupPolicy {
                                            ui.label(RichText::new(ph::LOCK_KEY).color(TEXT_DIM))
                                                .on_hover_text("Group Policy rule (read-only)");
                                        }
                                        let tip = if r.group.is_empty() || r.group == r.name {
                                            r.name.clone()
                                        } else {
                                            format!("{}\nGroup: {}", r.name, r.group)
                                        };
                                        ui.add(egui::Label::new(RichText::new(&r.name).color(text_color)).truncate()).on_hover_text(tip);
                                    }
                                    Col::Dir => {
                                        ui.label(direction_text(r.direction).size(13.0));
                                    }
                                    Col::Action => {
                                        pill(ui, action_label(r.action), if dim { TEXT_FAINT } else { action_color(r.action) });
                                    }
                                    Col::Proto => {
                                        ui.label(RichText::new(r.protocol.label()).color(TEXT_DIM).size(13.0));
                                    }
                                    Col::Ports => {
                                        ui.add(egui::Label::new(ports_job(r)).truncate());
                                    }
                                    Col::Remote => {
                                        let c = if r.remote_addrs.is_empty() { TEXT_FAINT } else { TEXT };
                                        ui.add(egui::Label::new(RichText::new(r.remote_label()).color(c).size(13.0)).truncate());
                                    }
                                    Col::Program => match (&r.app_path, r.app_state) {
                                        (Some(p), AppState::Missing) => {
                                            ui.label(RichText::new(ph::FILE_X).color(AMBER));
                                            ui.add(egui::Label::new(RichText::new(file_name(p)).color(AMBER).strikethrough()).truncate())
                                                .on_hover_text(format!("Missing: {p}"));
                                        }
                                        (Some(p), _) => {
                                            ui.add(egui::Label::new(RichText::new(file_name(p)).color(text_color)).truncate())
                                                .on_hover_text(p);
                                        }
                                        (None, state) => {
                                            let label = r.program_label();
                                            let c = if state == AppState::Missing {
                                                AMBER
                                            } else if r.package.is_some() || r.service.is_some() {
                                                TEXT_DIM
                                            } else {
                                                TEXT_FAINT
                                            };
                                            ui.add(egui::Label::new(RichText::new(&label).color(c).size(13.0)).truncate())
                                                .on_hover_text(label);
                                        }
                                    },
                                    Col::Profiles => profile_pills(ui, r.profiles, dim),
                                    Col::Findings => {
                                        ui.spacing_mut().item_spacing.x = 4.0;
                                        let issues = self.issues(i);
                                        for issue in issues.iter().take(2) {
                                            pill(ui, issue.kind.short(), severity_color(issue.severity)).on_hover_text(&issue.detail);
                                        }
                                        if issues.len() > 2 {
                                            ui.label(RichText::new(format!("+{}", issues.len() - 2)).color(TEXT_DIM).size(12.0));
                                        }
                                    }
                                });
                            }

                            if row.response().clicked() {
                                focus = Some(r.id.clone());
                            }
                        });
                    });
            });

        if let Some(v) = select_all {
            for &i in rows {
                if v {
                    self.selected.insert(self.rules[i].id.clone());
                } else {
                    self.selected.remove(&self.rules[i].id);
                }
            }
        }
        for (id, v) in toggles {
            if v {
                self.selected.insert(id);
            } else {
                self.selected.remove(&id);
            }
        }
        if let Some(id) = focus {
            self.focused = if self.focused.as_ref() == Some(&id) { None } else { Some(id) };
        }
    }

    // -----------------------------------------------------------------------------------------
    // Details panel
    // -----------------------------------------------------------------------------------------

    fn details(&mut self, ui: &mut Ui) {
        let Some(i) = self.focused_index() else { return };
        let r = self.rules[i].clone();
        let issues = self.issues(i).to_vec();
        let all_issues = self.analysis.issues[i].len();
        let is_reviewed = self.reviewed.contains(&r.id);

        ui.horizontal(|ui| {
            ui.label(RichText::new("RULE DETAILS").size(11.0).color(TEXT_FAINT));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.add(egui::Button::new(RichText::new(ph::X).color(TEXT_DIM)).frame(false)).on_hover_text("Close (Esc)").clicked() {
                    self.focused = None;
                }
            });
        });
        ui.add_space(4.0);

        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            ui.add(egui::Label::new(RichText::new(&r.name).family(semibold()).size(19.0).color(TEXT)).wrap());
            ui.add_space(4.0);
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing.x = 5.0;
                pill(ui, if r.enabled { "Enabled" } else { "Disabled" }, if r.enabled { GREEN } else { TEXT_DIM });
                pill(ui, if r.direction == Direction::In { "Inbound" } else { "Outbound" }, if r.direction == Direction::In { BLUE } else { VIOLET });
                pill(ui, action_label(r.action), action_color(r.action));
                if r.builtin {
                    pill(ui, "Built-in", TEXT_DIM);
                }
                if r.source == Source::GroupPolicy {
                    pill(ui, "Group Policy", AMBER);
                }
                if is_reviewed {
                    pill(ui, "Reviewed", ACCENT);
                }
            });
            if !r.description.is_empty() && r.description != r.name {
                ui.add_space(6.0);
                ui.add(egui::Label::new(RichText::new(&r.description).color(TEXT_DIM)).wrap());
            }

            if !issues.is_empty() {
                ui.add_space(12.0);
                for issue in &issues {
                    let color = severity_color(issue.severity);
                    Frame::new()
                        .fill(tint(color, 18))
                        .stroke(Stroke::new(1.0, tint(color, 55)))
                        .corner_radius(10)
                        .inner_margin(Margin::same(10))
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(kind_icon(issue.kind)).color(color).size(16.0));
                                ui.label(RichText::new(issue.kind.title()).family(semibold()).color(color));
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    pill(ui, issue.severity.label(), color);
                                });
                            });
                            ui.add(egui::Label::new(RichText::new(&issue.detail).color(TEXT)).wrap());
                            if let Some(rel) = issue.related {
                                if ui.link(icon_text(ph::CROSSHAIR, "Show that rule")).clicked() {
                                    self.focus_rule(rel);
                                }
                            }
                        });
                    ui.add_space(4.0);
                }
            } else if all_issues > 0 && is_reviewed {
                ui.add_space(8.0);
                ui.label(RichText::new(icon_text(ph::EYE_SLASH, &format!("{all_issues} finding(s) hidden - marked as reviewed"))).color(TEXT_DIM));
            }

            ui.add_space(12.0);
            card().inner_margin(Margin::same(12)).show(ui, |ui| {
                ui.set_width(ui.available_width());
                egui::Grid::new("kv").num_columns(2).spacing([14.0, 8.0]).show(ui, |ui| {
                    let kv = |ui: &mut Ui, k: &str, v: String, color: Color32| {
                        ui.label(RichText::new(k).color(TEXT_DIM));
                        ui.add(egui::Label::new(RichText::new(v).color(color)).wrap());
                        ui.end_row();
                    };
                    match (&r.app_path, r.app_state) {
                        (Some(p), AppState::Missing) => kv(ui, "Program", format!("{p}\n(missing)"), AMBER),
                        (Some(p), _) => kv(ui, "Program", p.clone(), TEXT),
                        (None, _) => kv(ui, "Program", "Any".into(), TEXT_FAINT),
                    }
                    if let Some(s) = &r.service {
                        kv(ui, "Service", s.clone(), TEXT);
                    }
                    if let Some(p) = &r.package {
                        kv(ui, "App package", p.clone(), TEXT);
                    }
                    kv(ui, "Protocol", r.protocol.label(), TEXT);
                    kv(ui, "Local ports", firewall::ports_label(&r.local_ports), TEXT);
                    kv(ui, "Remote ports", firewall::ports_label(&r.remote_ports), TEXT);
                    kv(ui, "Local address", if r.local_addrs.is_empty() { "Any".into() } else { r.local_addrs.join(", ") }, TEXT);
                    kv(ui, "Remote address", r.remote_label(), if r.remote_addrs.is_empty() { AMBER.gamma_multiply(0.9) } else { TEXT });
                    kv(ui, "Profiles", firewall::profiles_label(r.profiles), TEXT);
                    if !r.group.is_empty() {
                        kv(ui, "Group", r.group.clone(), TEXT);
                    }
                    if !r.extras.is_empty() {
                        kv(ui, "Conditions", r.extras.replace(';', "\n"), TEXT_DIM);
                    }
                    ui.label(RichText::new("Rule ID").color(TEXT_DIM));
                    ui.horizontal(|ui| {
                        ui.add(egui::Label::new(RichText::new(&r.id).monospace().color(TEXT_DIM)).wrap());
                        if ui.add(egui::Button::new(RichText::new(ph::COPY).color(TEXT_DIM)).frame(false)).on_hover_text("Copy ID").clicked() {
                            ui.ctx().copy_text(r.id.clone());
                        }
                    });
                    ui.end_row();
                });
            });

            ui.add_space(12.0);
            let can = r.can_modify() && self.busy.is_none();
            ui.horizontal_wrapped(|ui| {
                let (label, icon) = if r.enabled { ("Disable", ph::TOGGLE_LEFT) } else { ("Enable", ph::TOGGLE_RIGHT) };
                if ui.add_enabled(can, ghost_button(icon_text(icon, label))).clicked() {
                    self.set_enabled(ui.ctx(), vec![r.id.clone()], !r.enabled);
                }
                if ui.add_enabled(can, danger_button(icon_text(ph::TRASH, "Delete"))).clicked() {
                    self.confirm_delete = Some(vec![r.id.clone()]);
                }
                if ui.add(ghost_button(icon_text(ph::COPY, "Duplicate as new"))).clicked() {
                    self.create = Some(CreateForm { spec: NewRule::from_rule(&r), error: None });
                }
                if let (Some(p), AppState::Exists) = (&r.app_path, r.app_state) {
                    if ui.add(ghost_button(icon_text(ph::FOLDER_OPEN, "Show program"))).clicked() {
                        firewall::open_in_explorer(p, true);
                    }
                }
                if all_issues > 0 {
                    let (label, icon) = if is_reviewed { ("Unmark reviewed", ph::EYE_SLASH) } else { ("Mark reviewed", ph::EYE_SLASH) };
                    if ui
                        .add(ghost_button(icon_text(icon, label)))
                        .on_hover_text("Reviewed rules don't show up in Cleanup")
                        .clicked()
                    {
                        self.set_reviewed(std::slice::from_ref(&r.id), !is_reviewed);
                    }
                }
            });
            if !r.can_modify() {
                ui.add_space(4.0);
                ui.label(RichText::new("Managed by Group Policy - change it in gpedit / your domain policy.").color(TEXT_DIM).size(12.5));
            }
        });
    }

    // -----------------------------------------------------------------------------------------
    // Cleanup
    // -----------------------------------------------------------------------------------------

    fn cleanup_view(&mut self, ui: &mut Ui) {
        self.page_header(ui, "Cleanup", "Rules that are probably useless, redundant or more open than you think.");

        egui::SidePanel::left("cleanup_kinds")
            .exact_width(270.0)
            .resizable(false)
            .show_separator_line(false)
            .frame(Frame::new().inner_margin(Margin { left: 0, right: 16, top: 0, bottom: 0 }))
            .show_inside(ui, |ui| {
                for kind in IssueKind::ALL {
                    let n = self.count_kind(kind);
                    let active = self.cleanup_kind == kind;
                    let color = kind_color(kind);
                    let resp = Frame::new()
                        .fill(if active { tint(color, 22) } else { SURFACE })
                        .stroke(Stroke::new(1.0, if active { tint(color, 90) } else { BORDER }))
                        .corner_radius(12)
                        .inner_margin(Margin::symmetric(12, 10))
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(kind_icon(kind)).color(if n > 0 { color } else { TEXT_FAINT }).size(18.0));
                                ui.label(RichText::new(kind.title()).color(if n > 0 { TEXT } else { TEXT_FAINT }));
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    ui.label(RichText::new(n.to_string()).family(semibold()).color(if n > 0 { color } else { TEXT_FAINT }));
                                });
                            });
                        })
                        .response
                        .interact(Sense::click())
                        .on_hover_cursor(egui::CursorIcon::PointingHand);
                    if resp.clicked() {
                        self.cleanup_kind = kind;
                    }
                    ui.add_space(2.0);
                }
                ui.add_space(8.0);
                toggle_chip(ui, &mut self.show_reviewed, "Include reviewed");
                ui.label(
                    RichText::new(format!("{} rule(s) marked reviewed", self.reviewed.len())).color(TEXT_FAINT).size(12.0),
                );
            });

        egui::CentralPanel::default().frame(Frame::new()).show_inside(ui, |ui| {
            let kind = self.cleanup_kind;
            let mut rows: Vec<usize> = (0..self.rules.len()).filter(|&i| self.issues(i).iter().any(|x| x.kind == kind)).collect();
            if self.sort.0 == SortCol::Name && self.sort.1 {
                // Default for cleanup: most severe first.
                rows.sort_by(|&a, &b| {
                    let sev = |i: usize| self.issues(i).iter().filter(|x| x.kind == kind).map(|x| x.severity).max();
                    sev(b).cmp(&sev(a)).then(self.rules[a].name.cmp(&self.rules[b].name))
                });
            } else {
                self.sort_rows(&mut rows);
            }

            card().show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.label(RichText::new(kind_icon(kind)).color(kind_color(kind)).size(20.0));
                    ui.label(RichText::new(kind.title()).family(semibold()).size(17.0));
                });
                ui.add(egui::Label::new(RichText::new(kind.explanation()).color(TEXT_DIM)).wrap());
                if !rows.is_empty() {
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        let ids: Vec<String> = rows.iter().map(|&i| self.rules[i].id.clone()).collect();
                        if ui.add(ghost_button(icon_text(ph::CHECK_CIRCLE, &format!("Select all {}", rows.len())))).clicked() {
                            self.selected.extend(ids.iter().cloned());
                        }
                        if matches!(kind, IssueKind::MissingProgram | IssueKind::Duplicate | IssueKind::Covered) {
                            let deletable = self.deletable(&ids);
                            if ui
                                .add_enabled(
                                    self.busy.is_none() && !deletable.is_empty(),
                                    danger_button(icon_text(ph::TRASH, &format!("Delete all {}", deletable.len()))),
                                )
                                .clicked()
                            {
                                self.confirm_delete = Some(deletable);
                            }
                        }
                    });
                }
            });
            ui.add_space(10.0);
            self.selection_bar(ui, &rows);
            self.rules_table(ui, &rows, "cleanup_table");
        });
    }

    // -----------------------------------------------------------------------------------------
    // Ports
    // -----------------------------------------------------------------------------------------

    fn ports_view(&mut self, ui: &mut Ui) {
        self.page_header(ui, "Ports", "Every port referenced by a rule - listening port for inbound, destination for outbound.");
        ui.horizontal(|ui| {
            search_box(ui, &mut self.port_search, "Filter by port or service name...", 260.0, "ports_search");
            toggle_chip(ui, &mut self.port_sensitive_only, "Only well-known ports");
        });
        ui.add_space(10.0);

        let q = self.port_search.trim().to_lowercase();
        let rows: Vec<usize> = self
            .analysis
            .ports
            .iter()
            .enumerate()
            .filter(|(_, p)| !self.port_sensitive_only || p.known.is_some())
            .filter(|(_, p)| {
                q.is_empty()
                    || p.spec.label().to_lowercase().contains(&q)
                    || p.known.is_some_and(|k| k.name.to_lowercase().contains(&q))
                    || match (&p.spec, q.parse::<u16>()) {
                        (PortSpec::Range(..), Ok(n)) => p.spec.contains(n),
                        _ => false,
                    }
            })
            .map(|(i, _)| i)
            .collect();

        let mut clicked = None;
        let ports = &self.analysis.ports;
        let rules = &self.rules;
        Frame::new()
            .fill(SURFACE)
            .stroke(Stroke::new(1.0, BORDER))
            .corner_radius(14)
            .inner_margin(Margin { left: 10, right: 10, top: 6, bottom: 2 })
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                TableBuilder::new(ui)
                    .id_salt("ports_table")
                    .sense(Sense::click())
                    .cell_layout(Layout::left_to_right(Align::Center))
                    .auto_shrink([false, false])
                    .column(Column::exact(110.0))
                    .column(Column::exact(70.0))
                    .column(Column::initial(160.0).clip(true))
                    .column(Column::remainder().clip(true))
                    .column(Column::exact(70.0))
                    .column(Column::exact(120.0))
                    .column(Column::exact(80.0))
                    .header(30.0, |mut h| {
                        for t in ["Port", "Proto", "Service", "Used by", "Rules", "Inbound allow", "Risk"] {
                            h.col(|ui| {
                                ui.label(RichText::new(t).size(12.5).color(TEXT_DIM));
                            });
                        }
                    })
                    .body(|body| {
                        body.rows(34.0, rows.len(), |mut row| {
                            let p = &ports[rows[row.index()]];
                            let color = p.known.map(|k| risk_color(k.risk)).filter(|_| p.inbound_allow > 0);
                            row.col(|ui| {
                                ui.label(RichText::new(p.spec.label()).family(semibold()).color(color.unwrap_or(TEXT)));
                            });
                            row.col(|ui| {
                                ui.label(RichText::new(p.protocol.label()).color(TEXT_DIM));
                            });
                            row.col(|ui| match p.known {
                                Some(k) => {
                                    ui.label(RichText::new(k.name).color(TEXT)).on_hover_text(k.why);
                                }
                                None => {
                                    ui.label(RichText::new("-").color(TEXT_FAINT));
                                }
                            });
                            row.col(|ui| {
                                let mut names: Vec<&str> = p.rules.iter().map(|&i| rules[i].name.as_str()).collect();
                                names.sort_unstable();
                                names.dedup();
                                let text = names.iter().take(4).copied().collect::<Vec<_>>().join(", ");
                                let more = if names.len() > 4 { format!("  +{}", names.len() - 4) } else { String::new() };
                                ui.add(egui::Label::new(RichText::new(format!("{text}{more}")).color(TEXT_DIM).size(13.0)).truncate());
                            });
                            row.col(|ui| {
                                let c = if p.rules.len() > 1 { VIOLET } else { TEXT_DIM };
                                pill(ui, p.rules.len().to_string(), c)
                                    .on_hover_text(if p.rules.len() > 1 { "Several rules cover this port" } else { "" });
                            });
                            row.col(|ui| {
                                if p.inbound_allow > 0 {
                                    pill(ui, p.inbound_allow.to_string(), BLUE);
                                } else {
                                    ui.label(RichText::new("-").color(TEXT_FAINT));
                                }
                            });
                            row.col(|ui| {
                                if let Some(k) = p.known {
                                    let label = match k.risk {
                                        Risk::Critical => "Critical",
                                        Risk::Sensitive => "Sensitive",
                                        Risk::Notable => "Notable",
                                    };
                                    // Only loud when something actually lets it in.
                                    let c = if p.inbound_allow > 0 { risk_color(k.risk) } else { TEXT_FAINT };
                                    pill(ui, label, c).on_hover_text(k.why);
                                }
                            });
                            if row.response().clicked() {
                                clicked = Some(rows[row.index()]);
                            }
                        });
                    });
            });
        if let Some(idx) = clicked {
            let p = &self.analysis.ports[idx];
            let key = (p.protocol, p.spec.clone());
            self.go_rules_with(|f| f.port = Some(key));
        }
    }

    // -----------------------------------------------------------------------------------------
    // Programs
    // -----------------------------------------------------------------------------------------

    fn programs_view(&mut self, ui: &mut Ui) {
        self.page_header(ui, "Programs", "Rules grouped by the program, service or app they belong to.");
        let missing: Vec<String> = self
            .analysis
            .programs
            .iter()
            .filter(|p| p.state == AppState::Missing)
            .flat_map(|p| p.rules.iter().map(|&i| self.rules[i].id.clone()))
            .collect();
        ui.horizontal(|ui| {
            search_box(ui, &mut self.program_search, "Filter programs...", 260.0, "programs_search");
            toggle_chip(ui, &mut self.program_missing_only, "Only missing");
            if !missing.is_empty() {
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui
                        .add(ghost_button(icon_text(ph::BROOM, &format!("Review {} rules of missing programs", missing.len()))))
                        .clicked()
                    {
                        self.cleanup_kind = IssueKind::MissingProgram;
                        self.view = View::Cleanup;
                    }
                });
            }
        });
        ui.add_space(10.0);

        let q = self.program_search.trim().to_lowercase();
        let rows: Vec<usize> = self
            .analysis
            .programs
            .iter()
            .enumerate()
            .filter(|(_, p)| !self.program_missing_only || p.state == AppState::Missing)
            .filter(|(_, p)| q.is_empty() || p.label.to_lowercase().contains(&q))
            .map(|(i, _)| i)
            .collect();

        let mut clicked = None;
        let programs = &self.analysis.programs;
        Frame::new()
            .fill(SURFACE)
            .stroke(Stroke::new(1.0, BORDER))
            .corner_radius(14)
            .inner_margin(Margin { left: 10, right: 10, top: 6, bottom: 2 })
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                TableBuilder::new(ui)
                    .id_salt("programs_table")
                    .sense(Sense::click())
                    .cell_layout(Layout::left_to_right(Align::Center))
                    .auto_shrink([false, false])
                    .column(Column::exact(28.0))
                    .column(Column::initial(220.0).clip(true))
                    .column(Column::remainder().clip(true))
                    .column(Column::exact(70.0))
                    .column(Column::exact(120.0))
                    .header(30.0, |mut h| {
                        for t in ["", "Name", "Location", "Rules", "Inbound allow"] {
                            h.col(|ui| {
                                ui.label(RichText::new(t).size(12.5).color(TEXT_DIM));
                            });
                        }
                    })
                    .body(|body| {
                        body.rows(36.0, rows.len(), |mut row| {
                            let p = &programs[rows[row.index()]];
                            let (icon, color, tip) = match p.state {
                                AppState::Missing => (ph::FILE_X, AMBER, "Program no longer exists"),
                                AppState::Exists => (ph::CHECK_CIRCLE, GREEN, "Program found"),
                                AppState::System => (ph::HARD_DRIVES, BLUE, "Windows kernel (System)"),
                                AppState::NotSet => (ph::GLOBE, TEXT_DIM, "Not tied to a program file"),
                            };
                            row.col(|ui| {
                                ui.label(RichText::new(icon).color(color).size(16.0)).on_hover_text(tip);
                            });
                            let name = if p.key.is_empty() || p.key.starts_with("pkg:") || p.key.starts_with("svc:") {
                                p.label.clone()
                            } else {
                                file_name(&p.label).to_string()
                            };
                            row.col(|ui| {
                                let mut t = RichText::new(name).color(if p.state == AppState::Missing { AMBER } else { TEXT });
                                if p.state == AppState::Missing {
                                    t = t.strikethrough();
                                }
                                ui.add(egui::Label::new(t).truncate());
                            });
                            row.col(|ui| {
                                let loc = if p.state == AppState::Exists || p.state == AppState::Missing { p.label.as_str() } else { "" };
                                ui.add(egui::Label::new(RichText::new(loc).color(TEXT_DIM).size(13.0)).truncate()).on_hover_text(loc);
                            });
                            row.col(|ui| {
                                pill(ui, p.rules.len().to_string(), if p.rules.len() > 4 { VIOLET } else { TEXT_DIM });
                            });
                            row.col(|ui| {
                                if p.inbound_allow > 0 {
                                    pill(ui, p.inbound_allow.to_string(), BLUE);
                                } else {
                                    ui.label(RichText::new("-").color(TEXT_FAINT));
                                }
                            });
                            if row.response().clicked() {
                                clicked = Some(rows[row.index()]);
                            }
                        });
                    });
            });
        if let Some(idx) = clicked {
            let p = &self.analysis.programs[idx];
            let key = (p.key.clone(), p.label.clone());
            self.go_rules_with(|f| f.program = Some(key));
        }
    }

    // -----------------------------------------------------------------------------------------
    // Modals & overlays
    // -----------------------------------------------------------------------------------------

    fn confirm_modal(&mut self, ctx: &egui::Context) {
        let Some(ids) = self.confirm_delete.clone() else { return };
        let mut close = false;
        let mut confirmed = false;
        let builtin = ids.iter().filter(|id| self.index.get(*id).is_some_and(|&i| self.rules[i].builtin)).count();
        let names: Vec<String> = ids.iter().filter_map(|id| self.index.get(id)).map(|&i| self.rules[i].name.clone()).collect();

        let modal = egui::Modal::new(egui::Id::new("confirm_delete")).frame(modal_frame()).show(ctx, |ui| {
            ui.set_width(440.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new(ph::TRASH).color(RED).size(22.0));
                ui.label(RichText::new(format!("Delete {} rule{}?", ids.len(), if ids.len() == 1 { "" } else { "s" })).family(semibold()).size(18.0));
            });
            ui.add_space(6.0);
            Frame::new().fill(BG).corner_radius(10).inner_margin(Margin::same(10)).show(ui, |ui| {
                ui.set_width(ui.available_width());
                egui::ScrollArea::vertical().max_height(180.0).show(ui, |ui| {
                    for n in names.iter().take(50) {
                        ui.add(egui::Label::new(RichText::new(format!("•  {n}")).color(TEXT_DIM)).truncate());
                    }
                    if names.len() > 50 {
                        ui.label(RichText::new(format!("... and {} more", names.len() - 50)).color(TEXT_FAINT));
                    }
                });
            });
            ui.add_space(6.0);
            if builtin > 0 {
                ui.label(RichText::new(icon_text(ph::WARNING, &format!(
                    "{builtin} of these are built-in Windows rules. Removing them can break Windows features; disabling is usually safer."
                ))).color(AMBER));
            }
            if !self.backed_up {
                ui.label(RichText::new(icon_text(ph::ARCHIVE, "A full backup of your firewall policy is saved first.")).color(TEXT_DIM));
            }
            ui.label(RichText::new("This cannot be undone from inside the app.").color(TEXT_DIM));
            ui.add_space(10.0);
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.add(danger_button(icon_text(ph::TRASH, "Delete")).min_size(egui::vec2(96.0, 34.0))).clicked() {
                    confirmed = true;
                }
                if ui.add(ghost_button("Cancel").min_size(egui::vec2(84.0, 34.0))).clicked() {
                    close = true;
                }
            });
        });
        if modal.should_close() {
            close = true;
        }
        if confirmed {
            self.confirm_delete = None;
            for id in &ids {
                self.selected.remove(id);
            }
            self.delete(ctx, ids);
        } else if close {
            self.confirm_delete = None;
        }
    }

    fn create_modal(&mut self, ctx: &egui::Context) {
        let Some(form) = &mut self.create else { return };
        let mut close = false;
        let mut submit = false;

        let modal = egui::Modal::new(egui::Id::new("create_rule")).frame(modal_frame()).show(ctx, |ui| {
            ui.set_width(560.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new(ph::SHIELD_CHECK).color(ACCENT).size(22.0));
                ui.label(RichText::new("New firewall rule").family(semibold()).size(18.0));
            });
            ui.add_space(10.0);
            let s = &mut form.spec;
            egui::Grid::new("create_grid").num_columns(2).spacing([14.0, 10.0]).show(ui, |ui| {
                let label = |ui: &mut Ui, t: &str| {
                    ui.label(RichText::new(t).color(TEXT_DIM));
                };
                label(ui, "Name");
                ui.add(egui::TextEdit::singleline(&mut s.name).margin(Margin::symmetric(8, 5)).hint_text("e.g. Plex Media Server").desired_width(f32::INFINITY));
                ui.end_row();

                label(ui, "Description");
                ui.add(egui::TextEdit::singleline(&mut s.description).margin(Margin::symmetric(8, 5)).hint_text("Optional").desired_width(f32::INFINITY));
                ui.end_row();

                label(ui, "Group");
                ui.add(egui::TextEdit::singleline(&mut s.group).margin(Margin::symmetric(8, 5)).hint_text("Optional - handy for finding your own rules").desired_width(f32::INFINITY));
                ui.end_row();

                label(ui, "Direction");
                segmented(ui, &mut s.direction, &[(Direction::In, "Inbound"), (Direction::Out, "Outbound")]);
                ui.end_row();

                label(ui, "Action");
                segmented(ui, &mut s.action, &[(Action::Allow, "Allow"), (Action::Block, "Block")]);
                ui.end_row();

                label(ui, "Protocol");
                segmented(
                    ui,
                    &mut s.protocol,
                    &[(Protocol::Tcp, "TCP"), (Protocol::Udp, "UDP"), (Protocol::Any, "Any"), (Protocol::Icmp4, "ICMPv4"), (Protocol::Icmp6, "ICMPv6")],
                );
                ui.end_row();

                let ports_ok = s.protocol.has_ports();
                label(ui, "Local ports");
                ui.add_enabled(
                    ports_ok,
                    egui::TextEdit::singleline(&mut s.local_ports).margin(Margin::symmetric(8, 5)).hint_text("Any - or e.g. 80, 443, 5000-5010").desired_width(f32::INFINITY),
                );
                ui.end_row();

                label(ui, "Remote ports");
                ui.add_enabled(ports_ok, egui::TextEdit::singleline(&mut s.remote_ports).margin(Margin::symmetric(8, 5)).hint_text("Any").desired_width(f32::INFINITY));
                ui.end_row();

                label(ui, "Remote addresses");
                ui.add(
                    egui::TextEdit::singleline(&mut s.remote_addrs).margin(Margin::symmetric(8, 5))
                        .hint_text("Any - or e.g. LocalSubnet, 192.168.1.0/24")
                        .desired_width(f32::INFINITY),
                );
                ui.end_row();

                label(ui, "Program");
                ui.horizontal(|ui| {
                    ui.add(egui::TextEdit::singleline(&mut s.program).margin(Margin::symmetric(8, 5)).hint_text("Any program").desired_width(ui.available_width() - 90.0));
                    if ui.add(ghost_button(icon_text(ph::FOLDER_OPEN, "Browse"))).clicked() {
                        if let Some(p) = rfd::FileDialog::new().add_filter("Programs", &["exe"]).pick_file() {
                            s.program = p.to_string_lossy().into_owned();
                            if s.name.trim().is_empty() {
                                s.name = p.file_stem().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                            }
                        }
                    }
                });
                ui.end_row();

                label(ui, "Service");
                ui.add(egui::TextEdit::singleline(&mut s.service).margin(Margin::symmetric(8, 5)).hint_text("Optional service short name").desired_width(f32::INFINITY));
                ui.end_row();

                label(ui, "Profiles");
                ui.horizontal(|ui| {
                    for (name, bit) in [("Domain", PROFILE_DOMAIN), ("Private", PROFILE_PRIVATE), ("Public", PROFILE_PUBLIC)] {
                        let mut on = s.profiles & bit != 0;
                        if ui.checkbox(&mut on, name).changed() {
                            s.profiles ^= bit;
                        }
                    }
                });
                ui.end_row();

                label(ui, "Enabled");
                ui.checkbox(&mut s.enabled, "Turn on immediately");
                ui.end_row();
            });

            let exposed: Vec<String> = if s.direction == Direction::In && s.action == Action::Allow && s.protocol.has_ports() {
                s.local_ports
                    .split(',')
                    .filter_map(|p| p.trim().parse::<u16>().ok())
                    .filter_map(crate::ports::lookup)
                    .filter(|k| k.risk >= Risk::Sensitive)
                    .map(|k| format!("{} {}", k.port, k.name))
                    .collect()
            } else {
                Vec::new()
            };
            if !exposed.is_empty() {
                ui.add_space(8.0);
                let hint = if s.remote_addrs.trim().is_empty() { " Consider limiting Remote addresses (e.g. LocalSubnet)." } else { "" };
                ui.label(RichText::new(icon_text(ph::WARNING, &format!("Opens sensitive port(s): {}.{hint}", exposed.join(", ")))).color(AMBER));
            }
            if let Some(err) = &form.error {
                ui.add_space(8.0);
                ui.label(RichText::new(icon_text(ph::WARNING_OCTAGON, err)).color(RED));
            }

            ui.add_space(12.0);
            let valid = !form.spec.name.trim().is_empty() && form.spec.profiles != 0;
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.add_enabled(valid, primary_button(icon_text(ph::PLUS, "Create rule")).min_size(egui::vec2(120.0, 34.0))).clicked() {
                    submit = true;
                }
                if ui.add(ghost_button("Cancel").min_size(egui::vec2(84.0, 34.0))).clicked() {
                    close = true;
                }
                if !valid {
                    ui.label(RichText::new("Name and at least one profile are required").color(TEXT_FAINT).size(12.5));
                }
            });
        });
        if modal.should_close() {
            close = true;
        }
        if submit {
            let spec = self.create.take().unwrap().spec;
            self.create_rule(ctx, spec);
        } else if close {
            self.create = None;
        }
    }

    fn busy_overlay(&self, ctx: &egui::Context) {
        let Some(text) = &self.busy else { return };
        egui::Area::new(egui::Id::new("busy"))
            .anchor(egui::Align2::CENTER_TOP, egui::vec2(0.0, 18.0))
            .order(egui::Order::Foreground)
            .show(ctx, |ui| {
                Frame::new()
                    .fill(SURFACE_HI)
                    .stroke(Stroke::new(1.0, tint(ACCENT, 80)))
                    .corner_radius(20)
                    .inner_margin(Margin::symmetric(16, 8))
                    .shadow(ctx.style().visuals.popup_shadow)
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.spinner();
                            ui.label(RichText::new(text).color(TEXT));
                        });
                    });
            });
    }

    fn toasts_ui(&mut self, ctx: &egui::Context) {
        let now = ctx.input(|i| i.time);
        self.toasts.retain(|t| now - t.born < if t.kind == ToastKind::Ok { 5.0 } else { 10.0 });
        if self.toasts.is_empty() {
            return;
        }
        ctx.request_repaint_after(std::time::Duration::from_millis(250));
        let mut dismiss = None;
        egui::Area::new(egui::Id::new("toasts"))
            .anchor(egui::Align2::RIGHT_BOTTOM, egui::vec2(-20.0, -20.0))
            .order(egui::Order::Foreground)
            .show(ctx, |ui| {
                ui.set_max_width(420.0);
                for (n, t) in self.toasts.iter().enumerate() {
                    let (icon, color) = match t.kind {
                        ToastKind::Ok => (ph::CHECK_CIRCLE, GREEN),
                        ToastKind::Warn => (ph::WARNING, AMBER),
                        ToastKind::Err => (ph::WARNING_OCTAGON, RED),
                    };
                    let resp = Frame::new()
                        .fill(SURFACE_HI)
                        .stroke(Stroke::new(1.0, tint(color, 80)))
                        .corner_radius(12)
                        .inner_margin(Margin::symmetric(14, 10))
                        .shadow(ctx.style().visuals.popup_shadow)
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(icon).color(color).size(17.0));
                                ui.add(egui::Label::new(RichText::new(&t.text).color(TEXT)).wrap());
                            });
                        })
                        .response
                        .interact(Sense::click());
                    if resp.on_hover_text("Click to dismiss").clicked() {
                        dismiss = Some(n);
                    }
                    ui.add_space(6.0);
                }
            });
        if let Some(n) = dismiss {
            self.toasts.remove(n);
        }
    }
}

fn modal_frame() -> Frame {
    Frame::new()
        .fill(SURFACE)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(16)
        .inner_margin(Margin::same(22))
        .shadow(egui::epaint::Shadow { offset: [0, 14], blur: 40, spread: 0, color: Color32::from_black_alpha(160) })
}

fn stat_card(ui: &mut Ui, icon: &str, color: Color32, value: String, label: &str, sub: &str) -> egui::Response {
    let resp = card()
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                let (rect, _) = ui.allocate_exact_size(Vec2::splat(40.0), Sense::hover());
                ui.painter().rect_filled(rect, CornerRadius::same(12), tint(color, 30));
                ui.painter().text(rect.center(), egui::Align2::CENTER_CENTER, icon, FontId::proportional(20.0), color);
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 0.0;
                    ui.label(RichText::new(value).family(semibold()).size(24.0).color(TEXT));
                    ui.label(RichText::new(label).color(TEXT_DIM));
                });
            });
            ui.add_space(4.0);
            ui.add(egui::Label::new(RichText::new(sub).size(12.5).color(TEXT_FAINT)).truncate());
        })
        .response
        .interact(Sense::click());
    if resp.hovered() {
        ui.painter().rect_stroke(resp.rect, CornerRadius::same(14), Stroke::new(1.0, tint(color, 120)), egui::StrokeKind::Inside);
    }
    resp.on_hover_cursor(egui::CursorIcon::PointingHand)
}
