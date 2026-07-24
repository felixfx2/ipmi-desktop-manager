pub mod ipmi;
pub mod redfish;
mod keychain;
mod commands;

use commands::AppState;
use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    env_logger::init();

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(AppState::new())
        .setup(|app| {
            let _window = app.get_webview_window("main").unwrap();
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::connect,
            commands::disconnect,
            commands::get_connection_status,
            commands::save_credentials,
            commands::load_credentials,
            commands::delete_saved_credentials,
            commands::get_dashboard,
            commands::power_on,
            commands::power_off,
            commands::power_cycle,
            commands::graceful_shutdown,
            commands::force_off,
            commands::hard_reset,
            commands::get_sensors,
            commands::get_sel_entries,
            commands::clear_sel,
            commands::get_fru_info,
            commands::sol_activate,
            commands::sol_deactivate,
            commands::sol_send_input,
            commands::mount_virtual_media,
            commands::unmount_virtual_media,
            commands::get_virtual_media_status,
            commands::set_boot_device,
            commands::start_sol_output_stream,
            commands::stop_sol_output_stream,
            commands::test_redfish,
            commands::get_protocol_mode,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
