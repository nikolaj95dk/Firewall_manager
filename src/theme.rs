//! Soft dark theme: palette, fonts and egui style.

use eframe::egui::{
    self, epaint::Shadow, style::Selection, Color32, CornerRadius, FontData, FontDefinitions, FontFamily, FontId,
    Margin, Stroke, TextStyle, Visuals,
};
use std::sync::Arc;

pub const BG: Color32 = Color32::from_rgb(0x13, 0x15, 0x1b);
pub const SIDEBAR: Color32 = Color32::from_rgb(0x17, 0x19, 0x20);
pub const SURFACE: Color32 = Color32::from_rgb(0x1c, 0x1f, 0x27);
pub const SURFACE_HI: Color32 = Color32::from_rgb(0x24, 0x28, 0x32);
pub const SURFACE_HOVER: Color32 = Color32::from_rgb(0x2b, 0x30, 0x3c);
pub const BORDER: Color32 = Color32::from_rgb(0x2a, 0x2f, 0x3a);
pub const TEXT: Color32 = Color32::from_rgb(0xe4, 0xe7, 0xee);
pub const TEXT_DIM: Color32 = Color32::from_rgb(0x8d, 0x95, 0xa8);
pub const TEXT_FAINT: Color32 = Color32::from_rgb(0x5f, 0x67, 0x7a);

pub const ACCENT: Color32 = Color32::from_rgb(0x84, 0x9c, 0xff);
pub const ACCENT_DEEP: Color32 = Color32::from_rgb(0x5d, 0x74, 0xe8);
pub const GREEN: Color32 = Color32::from_rgb(0x63, 0xd2, 0x9f);
pub const RED: Color32 = Color32::from_rgb(0xff, 0x70, 0x85);
pub const AMBER: Color32 = Color32::from_rgb(0xf6, 0xb7, 0x6b);
pub const YELLOW: Color32 = Color32::from_rgb(0xe8, 0xd4, 0x7a);
pub const BLUE: Color32 = Color32::from_rgb(0x74, 0xc4, 0xf5);
pub const VIOLET: Color32 = Color32::from_rgb(0xb3, 0x93, 0xf5);

pub const RADIUS: u8 = 10;

/// Background tint of a colour for pills / soft badges.
pub fn tint(c: Color32, alpha: u8) -> Color32 {
    Color32::from_rgba_unmultiplied(c.r(), c.g(), c.b(), alpha)
}

pub fn semibold() -> FontFamily {
    FontFamily::Name("semibold".into())
}

pub fn install(ctx: &egui::Context) {
    install_fonts(ctx);
    ctx.set_theme(egui::Theme::Dark);
    ctx.all_styles_mut(apply_style);
}

fn install_fonts(ctx: &egui::Context) {
    let mut fonts = FontDefinitions::default();
    let windir = std::env::var("WINDIR").unwrap_or_else(|_| r"C:\Windows".into());
    let load = |file: &str| std::fs::read(format!(r"{windir}\Fonts\{file}")).ok();

    let regular = load("segoeui.ttf");
    let semi = load("seguisb.ttf").or_else(|| load("segoeuib.ttf"));

    if let Some(bytes) = regular {
        fonts.font_data.insert("segoe".into(), Arc::new(FontData::from_owned(bytes)));
        fonts.families.entry(FontFamily::Proportional).or_default().insert(0, "segoe".into());
    }
    egui_phosphor::add_to_fonts(&mut fonts, egui_phosphor::Variant::Regular);

    let mut semi_family = Vec::new();
    if let Some(bytes) = semi {
        fonts.font_data.insert("segoe-semibold".into(), Arc::new(FontData::from_owned(bytes)));
        semi_family.push("segoe-semibold".to_string());
    }
    semi_family.extend(fonts.families[&FontFamily::Proportional].iter().cloned());
    fonts.families.insert(semibold(), semi_family);

    let mono = load("CascadiaMono.ttf").or_else(|| load("consola.ttf"));
    if let Some(bytes) = mono {
        fonts.font_data.insert("mono".into(), Arc::new(FontData::from_owned(bytes)));
        fonts.families.entry(FontFamily::Monospace).or_default().insert(0, "mono".into());
    }
    ctx.set_fonts(fonts);
}

fn apply_style(style: &mut egui::Style) {
    style.text_styles = [
        (TextStyle::Small, FontId::new(11.5, FontFamily::Proportional)),
        (TextStyle::Body, FontId::new(14.0, FontFamily::Proportional)),
        (TextStyle::Button, FontId::new(14.0, FontFamily::Proportional)),
        (TextStyle::Heading, FontId::new(22.0, semibold())),
        (TextStyle::Monospace, FontId::new(12.5, FontFamily::Monospace)),
    ]
    .into();

    let s = &mut style.spacing;
    s.item_spacing = egui::vec2(8.0, 8.0);
    s.button_padding = egui::vec2(12.0, 6.0);
    s.interact_size.y = 30.0;
    s.window_margin = Margin::same(18);
    s.menu_margin = Margin::same(8);
    s.combo_width = 140.0;
    s.scroll.bar_width = 8.0;
    s.scroll.floating = true;

    style.interaction.selectable_labels = false;

    let mut v = Visuals::dark();
    v.dark_mode = true;
    v.override_text_color = None;
    v.weak_text_color = Some(TEXT_FAINT);
    v.panel_fill = BG;
    v.window_fill = SURFACE;
    v.window_stroke = Stroke::new(1.0, BORDER);
    v.window_corner_radius = CornerRadius::same(14);
    v.menu_corner_radius = CornerRadius::same(RADIUS);
    v.window_shadow = Shadow { offset: [0, 10], blur: 32, spread: 0, color: Color32::from_black_alpha(140) };
    v.popup_shadow = Shadow { offset: [0, 6], blur: 18, spread: 0, color: Color32::from_black_alpha(120) };
    v.faint_bg_color = SURFACE;
    v.extreme_bg_color = Color32::from_rgb(0x10, 0x12, 0x17);
    v.text_edit_bg_color = Some(Color32::from_rgb(0x15, 0x17, 0x1e));
    v.code_bg_color = SURFACE_HI;
    v.hyperlink_color = ACCENT;
    v.warn_fg_color = AMBER;
    v.error_fg_color = RED;
    v.selection = Selection { bg_fill: tint(ACCENT, 70), stroke: Stroke::new(1.0, ACCENT) };
    v.striped = false;
    v.indent_has_left_vline = false;
    v.collapsing_header_frame = false;
    v.handle_shape = egui::style::HandleShape::Circle;

    let r = CornerRadius::same(8);
    let w = &mut v.widgets;
    w.noninteractive.bg_fill = SURFACE;
    w.noninteractive.weak_bg_fill = SURFACE;
    w.noninteractive.bg_stroke = Stroke::new(1.0, BORDER);
    w.noninteractive.fg_stroke = Stroke::new(1.0, TEXT);
    w.noninteractive.corner_radius = r;

    w.inactive.bg_fill = SURFACE_HI;
    w.inactive.weak_bg_fill = SURFACE_HI;
    w.inactive.bg_stroke = Stroke::new(1.0, Color32::from_rgb(0x30, 0x35, 0x41));
    w.inactive.fg_stroke = Stroke::new(1.0, TEXT);
    w.inactive.corner_radius = r;

    w.hovered.bg_fill = SURFACE_HOVER;
    w.hovered.weak_bg_fill = SURFACE_HOVER;
    w.hovered.bg_stroke = Stroke::new(1.0, Color32::from_rgb(0x44, 0x4b, 0x5c));
    w.hovered.fg_stroke = Stroke::new(1.5, Color32::WHITE);
    w.hovered.corner_radius = r;
    w.hovered.expansion = 0.0;

    w.active.bg_fill = Color32::from_rgb(0x33, 0x39, 0x47);
    w.active.weak_bg_fill = Color32::from_rgb(0x33, 0x39, 0x47);
    w.active.bg_stroke = Stroke::new(1.0, ACCENT);
    w.active.fg_stroke = Stroke::new(1.5, Color32::WHITE);
    w.active.corner_radius = r;
    w.active.expansion = 0.0;

    w.open.bg_fill = SURFACE_HI;
    w.open.weak_bg_fill = SURFACE_HI;
    w.open.bg_stroke = Stroke::new(1.0, ACCENT);
    w.open.corner_radius = r;

    style.visuals = v;
}

/// Colours the native title bar to blend with the app (Windows 11) and forces dark mode on it.
pub fn style_title_bar(handle: raw_window_handle::RawWindowHandle) {
    use windows::Win32::Foundation::HWND;
    use windows::Win32::Graphics::Dwm::{
        DwmSetWindowAttribute, DWMWA_BORDER_COLOR, DWMWA_CAPTION_COLOR, DWMWA_TEXT_COLOR,
        DWMWA_USE_IMMERSIVE_DARK_MODE, DWMWA_WINDOW_CORNER_PREFERENCE, DWMWCP_ROUND,
    };
    let raw_window_handle::RawWindowHandle::Win32(h) = handle else { return };
    let hwnd = HWND(h.hwnd.get() as *mut _);
    let colorref = |c: Color32| u32::from(c.r()) | (u32::from(c.g()) << 8) | (u32::from(c.b()) << 16);
    unsafe {
        let dark: i32 = 1;
        let _ = DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &dark as *const _ as _, 4);
        let caption = colorref(SIDEBAR);
        let _ = DwmSetWindowAttribute(hwnd, DWMWA_CAPTION_COLOR, &caption as *const _ as _, 4);
        let border = colorref(BORDER);
        let _ = DwmSetWindowAttribute(hwnd, DWMWA_BORDER_COLOR, &border as *const _ as _, 4);
        let text = colorref(TEXT);
        let _ = DwmSetWindowAttribute(hwnd, DWMWA_TEXT_COLOR, &text as *const _ as _, 4);
        let corner = DWMWCP_ROUND;
        let _ = DwmSetWindowAttribute(hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, &corner as *const _ as _, 4);
    }
}
