//! Screen-share target selection and platform capture.
use std::sync::{Arc, Mutex};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShareTarget {
    Display(u32),
    Window(u32),
}
impl ShareTarget {
    pub fn id(self) -> u32 {
        match self {
            Self::Display(id) | Self::Window(id) => id,
        }
    }
    pub fn kind(self) -> ShareTargetKind {
        match self {
            Self::Display(_) => ShareTargetKind::Display,
            Self::Window(_) => ShareTargetKind::Window,
        }
    }
    pub fn from_parts(kind: ShareTargetKind, id: u32) -> Self {
        match kind {
            ShareTargetKind::Display => Self::Display(id),
            ShareTargetKind::Window => Self::Window(id),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShareTargetKind {
    Display,
    Window,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareTargetInfo {
    pub target: ShareTarget,
    pub kind: ShareTargetKind,
    pub title: String,
    pub app: String,
    pub width: u32,
    pub height: u32,
    pub primary: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScreenError {
    NoDisplay,
    PermissionDenied,
    Backend,
}
#[cfg(any(test, all(feature = "call-screen", any(windows, target_os = "macos"))))]
struct Candidate {
    info: ShareTargetInfo,
    minimized: bool,
    own_app: bool,
}
#[cfg(any(test, all(feature = "call-screen", any(windows, target_os = "macos"))))]
fn filter_and_sort(candidates: Vec<Candidate>) -> Vec<ShareTargetInfo> {
    let mut items: Vec<_> = candidates
        .into_iter()
        .filter(|c| match c.info.target {
            ShareTarget::Display(_) => true,
            ShareTarget::Window(_) => {
                !c.minimized
                    && !c.own_app
                    && !c.info.title.trim().is_empty()
                    && c.info.width > 0
                    && c.info.height > 0
            }
        })
        .map(|c| c.info)
        .collect();
    items.sort_by(|a, b| {
        (a.kind == ShareTargetKind::Window)
            .cmp(&(b.kind == ShareTargetKind::Window))
            .then_with(|| a.app.cmp(&b.app))
            .then_with(|| a.title.cmp(&b.title))
            .then_with(|| a.target.id().cmp(&b.target.id()))
    });
    items
}
#[cfg(all(feature = "call-screen", any(windows, target_os = "macos")))]
mod backend;
#[cfg(all(feature = "call-screen", any(windows, target_os = "macos")))]
pub use backend::ScreenSource;
#[cfg(all(feature = "call-screen", any(windows, target_os = "macos")))]
pub fn list_share_targets() -> Result<Vec<ShareTargetInfo>, ScreenError> {
    use backend::classify_error;
    let mut candidates = Vec::new();
    for m in xcap::Monitor::all().map_err(classify_error)? {
        if let (Ok(id), Ok(width), Ok(height)) = (m.id(), m.width(), m.height()) {
            candidates.push(Candidate {
                info: ShareTargetInfo {
                    target: ShareTarget::Display(id),
                    kind: ShareTargetKind::Display,
                    title: m.name().unwrap_or_default(),
                    app: String::new(),
                    width,
                    height,
                    primary: m.is_primary().unwrap_or(false),
                },
                minimized: false,
                own_app: false,
            });
        }
    }
    for w in xcap::Window::all().map_err(classify_error)? {
        if let (Ok(id), Ok(title), Ok(width), Ok(height), Ok(minimized)) =
            (w.id(), w.title(), w.width(), w.height(), w.is_minimized())
        {
            let app = w.app_name().unwrap_or_default();
            // The desktop and daemon can be separate processes.
            let own_app = w.pid().ok() == Some(std::process::id())
                || app.to_ascii_lowercase().contains("miasma");
            candidates.push(Candidate {
                info: ShareTargetInfo {
                    target: ShareTarget::Window(id),
                    kind: ShareTargetKind::Window,
                    title,
                    app,
                    width,
                    height,
                    primary: false,
                },
                minimized,
                own_app,
            });
        }
    }
    Ok(filter_and_sort(candidates))
}
#[cfg(not(all(feature = "call-screen", any(windows, target_os = "macos"))))]
pub fn list_share_targets() -> Result<Vec<ShareTargetInfo>, ScreenError> {
    Ok(Vec::new())
}
pub struct SelectableScreenFactory {
    target: Arc<Mutex<ShareTarget>>,
}
impl SelectableScreenFactory {
    pub fn new(target: ShareTarget) -> Self {
        Self {
            target: Arc::new(Mutex::new(target)),
        }
    }
    pub fn set_target(&self, target: ShareTarget) {
        *self.target.lock().unwrap_or_else(|e| e.into_inner()) = target;
    }
    pub fn target(&self) -> ShareTarget {
        *self.target.lock().unwrap_or_else(|e| e.into_inner())
    }
}
impl Default for SelectableScreenFactory {
    fn default() -> Self {
        #[cfg(all(feature = "call-screen", any(windows, target_os = "macos")))]
        let id = backend::primary_monitor()
            .ok()
            .and_then(|m| m.id().ok())
            .unwrap_or(0);
        #[cfg(not(all(feature = "call-screen", any(windows, target_os = "macos"))))]
        let id = 0;
        Self::new(ShareTarget::Display(id))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn candidate(target: ShareTarget, app: &str, title: &str) -> Candidate {
        Candidate {
            info: ShareTargetInfo {
                target,
                kind: target.kind(),
                title: title.into(),
                app: app.into(),
                width: 100,
                height: 100,
                primary: false,
            },
            minimized: false,
            own_app: false,
        }
    }
    #[test]
    fn filters_and_orders_candidates() {
        let mut minimized = candidate(ShareTarget::Window(4), "a", "min");
        minimized.minimized = true;
        let mut own = candidate(ShareTarget::Window(5), "a", "own");
        own.own_app = true;
        let mut zero = candidate(ShareTarget::Window(6), "a", "zero");
        zero.info.width = 0;
        let input = vec![
            candidate(ShareTarget::Window(2), "z", "b"),
            minimized,
            own,
            zero,
            candidate(ShareTarget::Window(7), "a", " "),
            candidate(ShareTarget::Window(3), "a", "a"),
            candidate(ShareTarget::Display(1), "", "display"),
        ];
        let ids: Vec<_> = filter_and_sort(input).iter().map(|i| i.target).collect();
        assert_eq!(
            ids,
            vec![
                ShareTarget::Display(1),
                ShareTarget::Window(3),
                ShareTarget::Window(2)
            ]
        );
    }
    #[test]
    fn target_round_trip_and_setter() {
        let factory = SelectableScreenFactory::new(ShareTarget::Display(42));
        let target = ShareTarget::Window(7);
        factory.set_target(target);
        assert_eq!(factory.target(), target);
        for t in [ShareTarget::Display(42), target] {
            assert_eq!(ShareTarget::from_parts(t.kind(), t.id()), t);
        }
    }
}
