mod commands;
pub mod crypto;
pub mod error;
pub mod secret;
pub mod store;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
// The only sanctioned panic in the crate: the webview failed to start, before
// any store has been opened, so the message cannot carry secret material.
#[allow(clippy::expect_used)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            if cfg!(debug_assertions) {
                // Logging is debug-only on purpose: no release build should have a
                // sink that a future careless `log::info!` could leak a secret into.
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![commands::core_version])
        .run(tauri::generate_context!())
        // Startup failure only; the message carries no store data.
        .expect("error while running tauri application");
}
