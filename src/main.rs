#![windows_subsystem = "windows"]

use eframe::egui;
use firewall_manager::{app, icon};
use std::sync::Arc;

fn main() -> eframe::Result {
    const ICON_SIZE: u32 = 128;
    let icon = egui::IconData { rgba: icon::render(ICON_SIZE), width: ICON_SIZE, height: ICON_SIZE };

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Firewall Manager")
            .with_app_id("FirewallManager")
            .with_inner_size([1400.0, 880.0])
            .with_min_inner_size([1000.0, 640.0])
            .with_icon(Arc::new(icon)),
        centered: true,
        ..Default::default()
    };

    eframe::run_native("Firewall Manager", options, Box::new(|cc| Ok(Box::new(app::App::new(cc)))))
}
