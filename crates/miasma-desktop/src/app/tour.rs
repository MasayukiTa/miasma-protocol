//! Developer-only "UI tour" (cargo feature `ui-tour`, not part of any release build).
//!
//! With `MIASMA_UI_TOUR=<dir>` set, the running app walks through theme x language x tab
//! (plus a few connection states), asks egui for a screenshot of its own window after each step
//! and writes it to `<dir>/<name>.ppm`. This exists because a GL window cannot be captured with
//! `PrintWindow` from a private desktop; the app renders the frame itself, so what is saved is
//! exactly what egui drew (fonts, colours, clipping).

use std::path::PathBuf;

use eframe::egui;

use super::{MiasmaApp, Tab};
use crate::locale::Locale;
use crate::theme::ThemeMode;
use crate::worker::DaemonState;

struct Step {
    name: String,
    theme: ThemeMode,
    locale: Locale,
    tab: Tab,
    daemon: Option<DaemonState>,
}

pub struct Tour {
    out: PathBuf,
    steps: Vec<Step>,
    idx: usize,
    frames_in_step: u32,
    requested: bool,
}

impl Tour {
    pub fn from_env() -> Option<Self> {
        let out = PathBuf::from(std::env::var_os("MIASMA_UI_TOUR")?);
        let _ = std::fs::create_dir_all(&out);
        let mut steps = Vec::new();
        let tabs = [
            (Tab::Store, "store"),
            (Tab::Retrieve, "retrieve"),
            (Tab::Send, "send"),
            (Tab::Inbox, "inbox"),
            (Tab::Outbox, "outbox"),
            (Tab::Status, "status"),
            (Tab::Settings, "settings"),
        ];
        steps.push(Step {
            name: "system_en_store".to_owned(),
            theme: ThemeMode::System,
            locale: Locale::En,
            tab: Tab::Store,
            daemon: None,
        });
        for (theme, tname) in [(ThemeMode::Dark, "dark"), (ThemeMode::Light, "light")] {
            for (locale, lname) in [(Locale::En, "en"), (Locale::Ja, "ja")] {
                for (tab, name) in tabs {
                    steps.push(Step {
                        name: format!("{tname}_{lname}_{name}"),
                        theme,
                        locale,
                        tab,
                        daemon: None,
                    });
                }
                for (d, dname) in [
                    (DaemonState::Stopped, "stopped"),
                    (DaemonState::Starting, "starting"),
                    (DaemonState::NeedsInit, "needsinit"),
                ] {
                    steps.push(Step {
                        name: format!("{tname}_{lname}_store_{dname}"),
                        theme,
                        locale,
                        tab: Tab::Store,
                        daemon: Some(d),
                    });
                }
            }
        }
        Some(Self {
            out,
            steps,
            idx: 0,
            frames_in_step: 0,
            requested: false,
        })
    }

    /// Call once per frame before drawing. Returns true when the tour is finished.
    pub fn drive(&mut self, app: &mut MiasmaApp, ctx: &egui::Context) -> bool {
        let Some(step) = self.steps.get(self.idx) else {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return true;
        };
        ctx.request_repaint();
        if self.frames_in_step == 0 {
            app.theme_mode = step.theme;
            app.locale = step.locale;
            app.tab = step.tab;
            if let Some(d) = &step.daemon {
                app.daemon_state = d.clone();
            }
        } else if let Some(d) = &step.daemon {
            // The worker may report its own state meanwhile; keep the one being shown.
            app.daemon_state = d.clone();
        }
        self.frames_in_step += 1;
        if !self.requested && self.frames_in_step >= 8 {
            ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot);
            self.requested = true;
        }
        if self.requested {
            let shot = ctx.input(|i| {
                i.events.iter().find_map(|e| match e {
                    egui::Event::Screenshot { image, .. } => Some(image.clone()),
                    _ => None,
                })
            });
            if let Some(img) = shot {
                let path = self.out.join(format!("{}.ppm", step.name));
                let [w, h] = img.size;
                let mut data = format!("P6\n{w} {h}\n255\n").into_bytes();
                for p in &img.pixels {
                    data.extend_from_slice(&[p.r(), p.g(), p.b()]);
                }
                let _ = std::fs::write(&path, data);
                self.idx += 1;
                self.frames_in_step = 0;
                self.requested = false;
            }
        }
        false
    }
}
