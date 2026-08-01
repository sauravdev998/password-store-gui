//! The `#[tauri::command]` surface — the only door between the webview and the
//! core. Nothing here may return plaintext except the explicit reveal path
//! (PLAN.md §4, invariant 2).

/// Liveness/version probe for the Rust core. Carries no store data.
#[tauri::command]
pub fn core_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
