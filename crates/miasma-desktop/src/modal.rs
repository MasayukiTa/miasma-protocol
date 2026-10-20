//! One dialog at a time.
//!
//! Several dialogs belong to the same screen (new conversation, new group, add members, the
//! confirmations). Nothing else stops a second one from opening on top of the first, so the
//! screen asks [`Order`] every frame which of the open ones is the newest, keeps that one and
//! closes the rest. Together with a page that is switched off while any dialog is open (the
//! app does that), a dialog can only be reached through the topmost one: Esc closes it, and the
//! controls behind it do not react.

/// Remembers in which order the open dialogs appeared.
#[derive(Debug, Default, Clone)]
pub struct Order {
    seen: Vec<&'static str>,
}

impl Order {
    /// `open` lists the keys of the dialogs that are open now (any order). Returns the key of
    /// the newest one: the one that appeared last. The caller closes every other open dialog.
    pub fn top(&mut self, open: &[&'static str]) -> Option<&'static str> {
        self.seen.retain(|k| open.contains(k));
        for k in open {
            if !self.seen.contains(k) {
                self.seen.push(k);
            }
        }
        self.seen.last().copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_newest_dialog_stays_and_the_rest_are_for_the_caller_to_close() {
        let mut order = Order::default();
        assert_eq!(order.top(&[]), None);
        assert_eq!(order.top(&["picker"]), Some("picker"));
        assert_eq!(order.top(&["picker"]), Some("picker"));
        // A second one opens while the first is still open: the second is on top.
        assert_eq!(order.top(&["picker", "group_form"]), Some("group_form"));
        // The caller closed the picker; the form stays.
        assert_eq!(order.top(&["group_form"]), Some("group_form"));
        assert_eq!(order.top(&[]), None);
    }

    #[test]
    fn a_dialog_that_closed_and_opens_again_is_new_again() {
        let mut order = Order::default();
        order.top(&["a"]);
        order.top(&[]);
        order.top(&["b"]);
        assert_eq!(order.top(&["a", "b"]), Some("a"));
    }
}
