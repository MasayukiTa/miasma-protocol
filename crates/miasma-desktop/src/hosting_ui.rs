//! The "Keep encrypted pieces for others" setting in Settings.
//!
//! The value is `storage.hosted_quota_mb` in `config.toml`. It is read and written with
//! `NodeConfig::load_with` / `NodeConfig::save`, the same calls the Network section and
//! `miasma config` use, and the background service reads it when it starts (the same
//! "applies after restart" rule as the Network section). Nothing here writes the file
//! by hand.
//!
//! A packaged (Microsoft Store) install starts with the setting off; that default is
//! written once at the first start by [`miasma_core::config::NodeConfig::seed_first_start`]
//! and never replaces a value that is already in the file.

use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Receiver, Sender};

use miasma_core::config::{NodeConfig, HOSTED_QUOTA_CHOICES_MB};
use miasma_core::update::package::is_packaged;

use crate::a11y::CollapsingExt as _;
use crate::hosting_strings::host_strings;
use crate::locale::Locale;
use crate::ui_kit::{self as kit, Level};

/// Read the saved quota. A missing file gives the default of this kind of install.
pub fn load_quota(data_dir: &Path, packaged: bool) -> Result<u64, String> {
    let mut c = NodeConfig::load_with(data_dir, packaged).map_err(|e| e.to_string())?;
    let mb = c.storage.hosted_quota_mb;
    c.transport.zeroize_secret_copies();
    Ok(mb)
}

/// Save a new quota: load the file, change the one key, save. Other settings stay as
/// they are.
pub fn save_quota(data_dir: &Path, packaged: bool, mb: u64) -> Result<(), String> {
    let mut c = NodeConfig::load_with(data_dir, packaged).map_err(|e| e.to_string())?;
    c.storage.hosted_quota_mb = mb;
    let r = c.save(data_dir).map_err(|e| e.to_string());
    c.transport.zeroize_secret_copies();
    r
}

/// A size as text ("256 MiB", "1 GiB", "5 GiB", else MiB). The sentence under the switch that used it
/// is gone, so only the tests read it now.
#[cfg_attr(not(test), allow(dead_code))]
pub fn size_text(mb: u64) -> String {
    if mb >= 1024 && mb % 1024 == 0 {
        format!("{} GiB", mb / 1024)
    } else {
        format!("{mb} MiB")
    }
}

/// Whether `mb` is one of the offered sizes.
pub fn is_offered(mb: u64) -> bool {
    HOSTED_QUOTA_CHOICES_MB.contains(&mb)
}

enum Msg {
    Saved(Result<u64, String>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SaveState {
    Idle,
    Saved,
    Failed,
}

pub struct HostingUi {
    data_dir: PathBuf,
    packaged: bool,
    /// The quota as saved in the file.
    saved: u64,
    load_failed: bool,
    save: SaveState,
    tx: Sender<Msg>,
    rx: Receiver<Msg>,
}

impl HostingUi {
    pub fn new(data_dir: PathBuf) -> Self {
        Self::with_packaged(data_dir, is_packaged())
    }

    /// The constructor with the kind of install given, so tests need no package.
    pub fn with_packaged(data_dir: PathBuf, packaged: bool) -> Self {
        // First start of a Store install: write its defaults (hosting off). Does nothing
        // for a normal install and never touches a file that exists.
        let _ = NodeConfig::seed_first_start(&data_dir, packaged);
        let (saved, load_failed) = match load_quota(&data_dir, packaged) {
            Ok(mb) => (mb, false),
            Err(_) => (
                miasma_core::config::default_hosted_quota_mb_for(packaged),
                true,
            ),
        };
        let (tx, rx) = channel();
        Self {
            data_dir,
            packaged,
            saved,
            load_failed,
            save: SaveState::Idle,
            tx,
            rx,
        }
    }

    /// The quota as saved (what the control shows as selected).
    pub fn saved_quota_mb(&self) -> u64 {
        self.saved
    }

    fn start_save(&mut self, mb: u64, ctx: &egui::Context) {
        let dir = self.data_dir.clone();
        let packaged = self.packaged;
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        let _ = std::thread::Builder::new()
            .name("hosting-config".into())
            .spawn(move || {
                let r = save_quota(&dir, packaged, mb).map(|()| mb);
                let _ = tx.send(Msg::Saved(r));
                ctx.request_repaint();
            });
    }

    fn drain(&mut self) {
        while let Ok(m) = self.rx.try_recv() {
            match m {
                Msg::Saved(Ok(mb)) => {
                    self.saved = mb;
                    self.save = SaveState::Saved;
                    self.load_failed = false;
                }
                Msg::Saved(Err(_)) => self.save = SaveState::Failed,
            }
        }
    }

    /// Draw the section. `used_mb` is the space in use on this computer when the service
    /// has reported it.
    pub fn section(&mut self, ui: &mut egui::Ui, locale: Locale, used_mb: Option<f64>) {
        self.drain();
        let s = host_strings(locale);
        let ctx = ui.ctx().clone();
        kit::section(ui, s.heading, |ui| {
            if self.load_failed {
                kit::notice(ui, Level::Warn, s.load_failed);
            }
            // Only "off" gets a note (what off means). With a size chosen, the sentence would
            // repeat the selected button (`desc_on` stays in the table).
            let desc = choice_note(s, self.saved);
            let mut choice = self.saved;
            let options = [
                (0, s.choice_off),
                (256, s.choice_256m),
                (1_024, s.choice_1g),
                (5_120, s.choice_5g),
            ];
            kit::form_row(ui, s.switch_label, desc, |ui| {
                let changed = kit::segmented(ui, &mut choice, &options);
                kit::status_dot(ui, Level::Warn, s.restart_tag);
                if changed {
                    self.start_save(choice, &ctx);
                }
            });
            if !is_offered(self.saved) {
                kit::hint(ui, &s.custom_note.replace("{n}", &self.saved.to_string()));
            }
            match used_mb {
                Some(used) => {
                    kit::hint(ui, &s.usage.replace("{used}", &format!("{used:.1}")));
                }
                None => {
                    kit::hint(ui, s.usage_unknown);
                }
            }
            match self.save {
                SaveState::Idle => {}
                SaveState::Saved => kit::notice(ui, Level::Ok, s.saved_notice),
                SaveState::Failed => kit::notice(ui, Level::Error, s.save_failed),
            }
            // What this setting does: opened on request.
            let details_title = crate::uitext::details_of(locale, s.heading);
            egui::CollapsingHeader::new(kit::muted_text(details_title))
                .id_source("settings_hosting_details")
                .default_open(false)
                .show_a11y(ui, |ui| {
                    kit::paragraph_muted(ui, s.intro);
                });
        });
    }
}

/// The note under the switch. Only "off" has one (what off means); with a size chosen the
/// sentence would repeat the selected button.
fn choice_note(
    s: &'static crate::hosting_strings::HostStrings,
    saved: u64,
) -> Option<&'static str> {
    (saved == 0).then_some(s.desc_off)
}

#[cfg(test)]
mod tests {
    use super::*;
    use miasma_core::config::DEFAULT_HOSTED_QUOTA_MB;

    #[test]
    fn a_chosen_size_gets_no_sentence_that_repeats_the_button() {
        for l in [Locale::En, Locale::Ja, Locale::ZhCn] {
            let s = host_strings(l);
            assert_eq!(choice_note(s, 0), Some(s.desc_off));
            for mb in [256, 1_024, 5_120, 300] {
                assert_eq!(choice_note(s, mb), None, "{l:?} {mb}");
            }
        }
    }

    /// The restart sentence is a whole sentence now: at the narrowest widths it wraps inside
    /// the window and never runs past the right edge.
    #[test]
    fn the_restart_sentence_wraps_inside_the_window() {
        for l in [Locale::En, Locale::Ja, Locale::ZhCn] {
            for width in [640.0_f32, 420.0] {
                let ctx = egui::Context::default();
                ctx.enable_accesskit();
                kit::apply_theme(&ctx, false);
                let d = dir();
                let mut u = HostingUi::with_packaged(d.path().to_path_buf(), false);
                let tag = host_strings(l).restart_tag;
                let mut right = f32::NEG_INFINITY;
                for _ in 0..3 {
                    let input = egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(
                            egui::pos2(0.0, 0.0),
                            egui::vec2(width, 900.0),
                        )),
                        ..Default::default()
                    };
                    let out = ctx.run(input, |ctx| {
                        egui::CentralPanel::default().show(ctx, |ui| {
                            kit::column(ui, |ui| u.section(ui, l, None));
                        });
                    });
                    if let Some(update) = out.platform_output.accesskit_update {
                        for (_, n) in &update.nodes {
                            if n.name() == Some(tag) {
                                right = n.bounds().map_or(right, |b| b.x1 as f32);
                            }
                        }
                    }
                }
                assert!(
                    right.is_finite(),
                    "{l:?}: the restart sentence is not drawn"
                );
                assert!(
                    right <= width,
                    "{l:?} at {width}: the restart sentence ends at {right}"
                );
            }
        }
    }

    fn dir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn a_packaged_first_start_shows_off_and_writes_it_once() {
        let d = dir();
        let u = HostingUi::with_packaged(d.path().to_path_buf(), true);
        assert_eq!(u.saved_quota_mb(), 0);
        assert!(miasma_core::paths::config_file(d.path()).exists());
        assert_eq!(load_quota(d.path(), false).unwrap(), 0);
    }

    #[test]
    fn a_normal_install_keeps_todays_default_and_writes_nothing() {
        let d = dir();
        let u = HostingUi::with_packaged(d.path().to_path_buf(), false);
        assert_eq!(u.saved_quota_mb(), DEFAULT_HOSTED_QUOTA_MB);
        assert!(!miasma_core::paths::config_file(d.path()).exists());
    }

    #[test]
    fn a_choice_is_saved_and_read_back_by_both_kinds_of_install() {
        for packaged in [false, true] {
            let d = dir();
            for mb in HOSTED_QUOTA_CHOICES_MB {
                save_quota(d.path(), packaged, mb).unwrap();
                assert_eq!(load_quota(d.path(), packaged).unwrap(), mb);
                assert_eq!(load_quota(d.path(), !packaged).unwrap(), mb);
            }
        }
    }

    #[test]
    fn opening_the_screen_never_overrides_an_explicit_value() {
        for explicit in [0, 256, DEFAULT_HOSTED_QUOTA_MB, 5_120, 777] {
            let d = dir();
            save_quota(d.path(), false, explicit).unwrap();
            for packaged in [false, true] {
                let u = HostingUi::with_packaged(d.path().to_path_buf(), packaged);
                assert_eq!(u.saved_quota_mb(), explicit, "packaged={packaged}");
                assert_eq!(load_quota(d.path(), packaged).unwrap(), explicit);
            }
        }
    }

    #[test]
    fn saving_the_quota_leaves_the_other_settings_alone() {
        let d = dir();
        let mut c = NodeConfig::default();
        c.storage.quota_mb = 4_321;
        c.chat.max_message_bytes = 99;
        c.save(d.path()).unwrap();
        save_quota(d.path(), false, 256).unwrap();
        let back = NodeConfig::load_with(d.path(), false).unwrap();
        assert_eq!(back.storage.hosted_quota_mb, 256);
        assert_eq!(back.storage.quota_mb, 4_321);
        assert_eq!(back.chat.max_message_bytes, 99);
    }

    #[test]
    fn a_value_that_is_not_offered_is_reported_as_custom_and_kept() {
        let d = dir();
        save_quota(d.path(), false, 777).unwrap();
        let u = HostingUi::with_packaged(d.path().to_path_buf(), false);
        assert!(!is_offered(u.saved_quota_mb()));
        assert_eq!(size_text(777), "777 MiB");
        for mb in HOSTED_QUOTA_CHOICES_MB {
            assert!(is_offered(mb));
        }
    }

    #[test]
    fn sizes_are_written_in_plain_units() {
        assert_eq!(size_text(256), "256 MiB");
        assert_eq!(size_text(1_024), "1 GiB");
        assert_eq!(size_text(5_120), "5 GiB");
    }
}
