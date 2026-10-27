//! Opt-in append cuts, dispatched after releasing the log's writer lock.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use super::LogHandle;

/// A host hook for cutting the file thread after a durable append.
///
/// Pass the thread to `Kernel::cut`. The hook should only enqueue that cut;
/// readers run on their own stacks. It runs outside the log's locks. A panic
/// is contained so an entry already on disk never appears to have failed.
pub type AppendCut = dyn Fn(&str) + Send + Sync;

pub(super) struct AppendState {
    cut: Arc<AppendCut>,
    lengths: BTreeMap<PathBuf, u64>,
}

impl LogHandle {
    /// Enable a live raw tail by connecting append notifications to a kernel.
    ///
    /// The callback receives `urn:file:{absolute segment path}` after this
    /// handle appends, opens, closes or rotates a file. A host usually captures
    /// a `Weak<Kernel>` and calls `kernel.cut(thread)` when it upgrades. Reads
    /// with `as=text/x-ikigai-log tail=true` may then cache a live snapshot under
    /// that thread. Listen for its cuts, re-read, and call the new replay's
    /// `open_at(last_offset)` to consume only the appended bytes. An old replay
    /// refuses a changed file; always obtain a fresh one after a cut.
    ///
    /// Only files written through this handle are covered. Other processes
    /// still need a host file watcher. Removing/replacing a hook cuts its old
    /// threads, so a former tail cannot stay cached without a notifier.
    pub fn set_append_cutter(&self, cut: Option<Arc<AppendCut>>) {
        let path = self.open_path();
        let mut lengths = BTreeMap::new();
        if let Some(path) = path {
            if let Ok(metadata) = path.metadata() {
                lengths.insert(path, metadata.len());
            }
        }
        let old = {
            let mut observer = self.append_cutter.lock().expect("log append cutter");
            let old =
                std::mem::replace(&mut *observer, cut.map(|cut| AppendState { cut, lengths }));
            self.append_cuts_enabled
                .store(observer.is_some(), std::sync::atomic::Ordering::Release);
            old
        };
        if let Some(old) = old {
            for path in old.lengths.keys() {
                notify(&old.cut, path);
            }
        }
    }

    pub(crate) fn has_append_cutter(&self) -> bool {
        self.append_cuts_enabled
            .load(std::sync::atomic::Ordering::Acquire)
    }

    fn open_path(&self) -> Option<PathBuf> {
        self.state
            .lock()
            .expect("log state")
            .writer
            .as_ref()
            .and_then(|writer| writer.path().map(PathBuf::from))
    }

    pub(super) fn append_guard(&self) -> AppendGuard<'_> {
        let old = self.has_append_cutter().then(|| self.open_path()).flatten();
        AppendGuard { handle: self, old }
    }
}

fn notify(cut: &Arc<AppendCut>, path: &std::path::Path) {
    let thread = format!("urn:file:{}", path.display());
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| cut(&thread)));
}

pub(super) struct AppendGuard<'a> {
    handle: &'a LogHandle,
    old: Option<PathBuf>,
}

impl Drop for AppendGuard<'_> {
    fn drop(&mut self) {
        if !self.handle.has_append_cutter() {
            return;
        }
        let mut paths = Vec::new();
        if let Some(old) = self.old.take() {
            paths.push(old);
        }
        if let Some(current) = self.handle.open_path() {
            if !paths.contains(&current) {
                paths.push(current);
            }
        }
        // Nested write/rotation guards and concurrent writers coalesce by the
        // committed length. Do not cut on filtered entries or unchanged reads.
        let notifications = {
            let mut observer = self.handle.append_cutter.lock().expect("log append cutter");
            let Some(observer) = observer.as_mut() else {
                return;
            };
            // Completed segments need no future append cuts. Keep only the
            // paths this operation could have changed, not an entire history.
            observer.lengths.retain(|path, _| paths.contains(path));
            paths
                .into_iter()
                .filter_map(|path| {
                    let len = path.metadata().ok()?.len();
                    if observer.lengths.insert(path.clone(), len) == Some(len) {
                        return None;
                    }
                    Some((observer.cut.clone(), path))
                })
                .collect::<Vec<_>>()
        };
        for (cut, path) in notifications {
            notify(&cut, &path);
        }
    }
}

pub(super) fn empty() -> Mutex<Option<AppendState>> {
    Mutex::new(None)
}
