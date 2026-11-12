//! Cancelling long operations (issue #76).
//!
//! A long operation (an export to a file, moving the archive's data folder)
//! runs on a blocking thread, and dropping the async caller doesn't stop it.
//! It checks a [`Cancel`] flag between items instead, and undoes what it had
//! started when the flag is set. The flag is only a request: nothing may
//! assume the work has ended until the operation itself returns.

use crate::error::{Error, Result};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// A shared "stop" request. Clones share the flag. The default is a flag
/// nobody sets, for callers that never cancel.
#[derive(Debug, Clone, Default)]
pub struct Cancel(Arc<AtomicBool>);

impl Cancel {
    pub fn new() -> Self {
        Self::default()
    }

    /// Asks the operation to stop at its next check.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Relaxed);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }

    /// `Err(Error::Cancelled)` once the flag is set; called between items.
    pub fn check(&self) -> Result<()> {
        if self.is_cancelled() { Err(Error::Cancelled) } else { Ok(()) }
    }

    /// A guard that sets the flag when it is dropped: held by an async
    /// caller, it turns the caller being dropped (its client went away) into
    /// a cancellation request.
    pub fn on_drop(&self) -> CancelOnDrop {
        CancelOnDrop(Some(self.clone()))
    }
}

/// See [`Cancel::on_drop`]. [`CancelOnDrop::disarm`] keeps it from setting
/// the flag, once the caller has its answer.
#[derive(Debug)]
pub struct CancelOnDrop(Option<Cancel>);

impl CancelOnDrop {
    pub fn disarm(mut self) {
        self.0 = None;
    }
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        if let Some(cancel) = self.0.take() {
            cancel.cancel();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_dropped_guard_cancels_and_a_disarmed_one_does_not() {
        let cancel = Cancel::new();
        assert!(cancel.check().is_ok());
        cancel.on_drop().disarm();
        assert!(!cancel.is_cancelled(), "disarmed");
        drop(cancel.on_drop());
        assert!(matches!(cancel.clone().check(), Err(Error::Cancelled)));
    }
}
