#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    ipmi_desktop_manager_lib::run()
}
