//! The native loading seam: config-home paths in, effective config out — and
//! back out again when `urn:log:config` writes.
//!
//! This is the only module that reads or writes the config files, and it is
//! `cfg`-gated off wasm; everything else stays pure so a browser host can hold
//! a [`LogConfig`] it obtained by any means.
//!
//! `std::fs` here rather than a kernel `urn:file:` sub-request, for the reason
//! `ikigai-a11y` gives: the config home is an absolute path outside any host's
//! fs jail, so reading it through `ikigai-fs` would mean either widening what
//! every `urn:file:` in the host can reach or the crate silently not working on
//! hosts that had not. What the kernel actually needs from the read — the
//! golden threads — is declared explicitly instead, by [`threads`].
//!
//! ## Every function takes its config home
//!
//! There is an ambient pair ([`complete`], [`paths`]) for a host that wants the
//! machine's own, and a rooted twin for everything else. The rooted forms are
//! not only for tests: `$HOME` is process-global, so a test that redirected it
//! would race the harness's own threads, and an endpoint that reads it
//! ambiently cannot be exercised hermetically at all. The endpoints therefore
//! take the home at construction — see [`crate::endpoints::LogHandle`].

use std::path::{Path, PathBuf};

use ikigai_core::config::{config_home, layered_paths_in};

use crate::config::{ConfigError, LogConfig, Patch, STEM};

/// The candidate config files for `app`, lowest precedence first.
///
/// Both entries are returned whether or not they exist — an absent file is a
/// layer that states nothing, not an error.
pub fn paths(app: Option<&str>) -> Result<Vec<PathBuf>, ConfigError> {
    let home = config_home().ok_or(ConfigError::NoConfigHome)?;
    Ok(layered_paths_in(&home, STEM, app))
}

/// The golden threads the effective config depends on: one per **candidate**
/// path, existing or not.
///
/// Including the paths that do not exist yet is the whole point. A cached
/// config that declared only the files it actually read would not notice an
/// operator CREATING `serve.log.toml` — the new override would stay invisible
/// until the process restarted, which is the failure the golden thread exists
/// to prevent.
pub fn threads_in(home: &Path, app: Option<&str>) -> Vec<String> {
    layered_paths_in(home, STEM, app)
        .iter()
        .map(|path| format!("urn:file:{}", path.display()))
        .collect()
}

/// [`threads_in`] against the machine's own config home.
pub fn threads(app: Option<&str>) -> Result<Vec<String>, ConfigError> {
    let home = config_home().ok_or(ConfigError::NoConfigHome)?;
    Ok(threads_in(&home, app))
}

/// The effective config for `app`: `base` with each existing layer folded in,
/// key-wise, lowest precedence first.
///
/// `base` is the **host's** defaults, and it is a parameter rather than a
/// constant because the module cannot make that call: a server and a browser
/// default to the console, and a CLI REPL does not log at all. The crate's own
/// [`LogConfig::default`] is the quiet one, so a host that forgets to state a
/// posture gets silence rather than a journal full of one-shot processes.
pub fn complete_in(
    home: &Path,
    app: Option<&str>,
    base: LogConfig,
) -> Result<LogConfig, ConfigError> {
    let mut effective = base;
    effective.layers.clear();
    for path in layered_paths_in(home, STEM, app) {
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            // Absent is the normal case and means "this layer states nothing".
            // Anything else — a permissions problem, a directory where a file
            // should be — is a real failure and must not read as "no config".
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                return Err(ConfigError::Unreadable {
                    path,
                    message: e.to_string(),
                })
            }
        };
        let patch = Patch::parse(&text, Some(path.clone()))?;
        effective.apply(&patch);
        effective.layers.push(path);
    }
    Ok(effective)
}

/// [`complete_in`] against the machine's own config home.
pub fn complete(app: Option<&str>, base: LogConfig) -> Result<LogConfig, ConfigError> {
    let home = config_home().ok_or(ConfigError::NoConfigHome)?;
    complete_in(&home, app, base)
}

/// The layer a `urn:log:config` write lands in: the app file when the host
/// named itself, else the shared one.
///
/// The **highest-precedence** layer, so the write actually takes effect. Any
/// other choice would let a change be silently overridden by a file the writer
/// never mentioned, which is the config equivalent of a dropped entry.
pub fn target_layer(home: &Path, app: Option<&str>) -> Option<PathBuf> {
    layered_paths_in(home, STEM, app).pop()
}

/// Read one layer file as the patch it is. An absent file is an empty patch.
pub fn read_layer(path: &Path) -> Result<Patch, ConfigError> {
    match std::fs::read_to_string(path) {
        Ok(text) => Patch::parse(&text, Some(path.to_path_buf())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Patch::default()),
        Err(e) => Err(ConfigError::Unreadable {
            path: path.to_path_buf(),
            message: e.to_string(),
        }),
    }
}

/// Merge `change` into the layer at `path` and write it back, key-wise.
///
/// Read-modify-write of the **values**, so keys the change does not mention
/// survive — but **comments in that file do not**. That is the honest cost of a
/// config that is also a resource, and it is why the write's response names the
/// file it touched: an operator who keeps prose in `log.toml` should know which
/// file a `urn:log:config` write will rewrite.
pub fn write_layer(path: &Path, change: &Patch) -> Result<Patch, ConfigError> {
    let mut merged = read_layer(path)?;
    if let Some(level) = &change.level {
        merged.level = Some(level.clone());
    }
    if let Some(destination) = change.destination {
        merged.destination = Some(destination);
    }
    if let Some(directory) = &change.directory {
        merged.directory = Some(directory.clone());
    }
    if let Some(instance) = &change.instance {
        merged.instance = Some(instance.clone());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| ConfigError::Unwritable {
            path: path.to_path_buf(),
            message: e.to_string(),
        })?;
    }
    std::fs::write(path, merged.to_toml()).map_err(|e| ConfigError::Unwritable {
        path: path.to_path_buf(),
        message: e.to_string(),
    })?;
    Ok(merged)
}
