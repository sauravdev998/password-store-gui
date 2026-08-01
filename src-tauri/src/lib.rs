pub mod commands;
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
        // The store and the crypto backend are opened per command rather than
        // here, so a missing store directory or a missing `gpg` is an error the
        // window can show and the user can fix without relaunching.
        .manage(commands::Core::new())
        .invoke_handler(tauri::generate_handler![
            commands::core_version,
            commands::list_tree,
            commands::show_entry,
            commands::reveal_password,
            commands::reveal_field,
            commands::reveal_notes,
        ])
        .run(tauri::generate_context!())
        // Startup failure only; the message carries no store data.
        .expect("error while running tauri application");
}
