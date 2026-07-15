use crate::ipmi::IpmiClient;
use crate::keychain::{self, StoredCredentials};
use crate::redfish::{RedfishSession, SystemInfo, ThermalInfo, PowerInfo, SelEntry, FruInfo, FirmwareInfo, VirtualMediaStatus};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tauri::{AppHandle, Emitter};

pub struct AppState {
    pub ipmi_client: Mutex<IpmiClient>,
    pub redfish_session: Mutex<Option<RedfishSession>>,
    pub connected: Mutex<bool>,
    pub protocol_mode: Mutex<String>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            ipmi_client: Mutex::new(IpmiClient::new()),
            redfish_session: Mutex::new(None),
            connected: Mutex::new(false),
            protocol_mode: Mutex::new("Auto".to_string()),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConnectionParams {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub protocol_mode: String,
    pub skip_tls_verify: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DashboardData {
    pub system: Option<SystemInfo>,
    pub thermal: Option<ThermalInfo>,
    pub power: Option<PowerInfo>,
    pub firmware: Option<FirmwareInfo>,
    pub power_state: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SensorReading {
    pub name: String,
    pub value: Option<f64>,
    pub unit: String,
    pub status: String,
    pub upper_critical: Option<f64>,
    pub lower_critical: Option<f64>,
}

#[tauri::command]
pub async fn connect(state: tauri::State<'_, AppState>, params: ConnectionParams) -> Result<String, String> {
    *state.protocol_mode.lock().await = params.protocol_mode.clone();

    let mut use_redfish = params.protocol_mode != "IPMI Only";
    let use_ipmi = params.protocol_mode != "Redfish Only";
    let mut any_connected = false;

    if use_redfish {
        let base_url = if params.port == 443 {
            format!("https://{}", params.host)
        } else {
            format!("https://{}:{}", params.host, params.port)
        };
        let mut rf = RedfishSession::new(
            base_url,
            params.username.clone(),
            params.password.clone(),
            params.skip_tls_verify,
        );

        match rf.login().await {
            Ok(()) => {
                *state.redfish_session.lock().await = Some(rf);
                any_connected = true;
                log::info!("Redfish connection established");
            }
            Err(e) => {
                log::warn!("Redfish connection failed: {}, falling back to IPMI", e);
                use_redfish = false;
                if params.protocol_mode == "Redfish Only" {
                    return Err(format!("Redfish connection failed: {}", e));
                }
            }
        }
    }

    if use_ipmi {
        let mut client = state.ipmi_client.lock().await;
        let ipmi_port = 623u16;
        match client.connect(&params.host, ipmi_port, &params.username, &params.password).await {
            Ok(()) => {
                any_connected = true;
                log::info!("IPMI connection established");
            }
            Err(e) => {
                log::warn!("IPMI connection failed: {}", e);
                if !use_redfish {
                    return Err(format!("IPMI connection failed: {}", e));
                }
            }
        }
    }

    if !any_connected {
        return Err("All connection attempts failed".to_string());
    }

    *state.connected.lock().await = true;

    let stored = StoredCredentials {
        host: params.host,
        port: params.port,
        username: params.username,
        protocol_mode: params.protocol_mode,
        skip_tls_verify: params.skip_tls_verify,
    };

    if let Err(e) = keychain::save_credentials(&stored, &params.password) {
        log::warn!("Failed to save credentials to keychain: {}", e);
    }

    Ok("Connected successfully".to_string())
}

#[tauri::command]
pub async fn disconnect(state: tauri::State<'_, AppState>) -> Result<String, String> {
    {
        let mut rf = state.redfish_session.lock().await;
        if let Some(ref session) = *rf {
            let _ = session.logout().await;
        }
        *rf = None;
    }

    state.ipmi_client.lock().await.disconnect().await.map_err(|e| e.to_string())?;
    *state.connected.lock().await = false;

    Ok("Disconnected".to_string())
}

#[tauri::command]
pub async fn get_connection_status(state: tauri::State<'_, AppState>) -> Result<bool, String> {
    Ok(*state.connected.lock().await)
}

#[tauri::command]
pub async fn save_credentials(
    host: String, port: u16, username: String, password: String,
    protocol_mode: String, skip_tls_verify: bool,
) -> Result<(), String> {
    let stored = StoredCredentials {
        host, port, username, protocol_mode, skip_tls_verify,
    };
    keychain::save_credentials(&stored, &password).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn load_credentials() -> Result<Option<StoredCredentials>, String> {
    keychain::load_credentials()
        .map(|opt| opt.map(|(creds, _)| creds))
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_dashboard(state: tauri::State<'_, AppState>) -> Result<DashboardData, String> {
    let mut dashboard = DashboardData {
        system: None,
        thermal: None,
        power: None,
        firmware: None,
        power_state: None,
    };

    let session_clone = {
        let rf = state.redfish_session.lock().await;
        rf.clone()
    };

    if let Some(ref session) = session_clone {
        if let Ok(sys) = session.get_system_info().await {
            dashboard.power_state = Some(sys.power_state.clone());
            dashboard.system = Some(sys);
        }
        if let Ok(thermal) = session.get_thermal().await {
            dashboard.thermal = Some(thermal);
        }
        if let Ok(power) = session.get_power().await {
            dashboard.power = Some(power);
        }
        if let Ok(fw) = session.get_firmware_info().await {
            dashboard.firmware = Some(fw);
        }
    }

    Ok(dashboard)
}

#[tauri::command]
pub async fn power_on(state: tauri::State<'_, AppState>) -> Result<String, String> {
    {
        let rf = state.redfish_session.lock().await;
        if let Some(ref session) = *rf {
            session.set_power_state("On").await.map_err(|e| e.to_string())?;
            return Ok("Power on sent".to_string());
        }
    }

    let mut client = state.ipmi_client.lock().await;
    client.send_ipmi_command(0x00, 0x30, &[0x01]).await.map_err(|e| e.to_string())?;
    Ok("Power on sent via IPMI".to_string())
}

#[tauri::command]
pub async fn power_off(state: tauri::State<'_, AppState>) -> Result<String, String> {
    {
        let rf = state.redfish_session.lock().await;
        if let Some(ref session) = *rf {
            session.set_power_state("ForceOff").await.map_err(|e| e.to_string())?;
            return Ok("Power off sent".to_string());
        }
    }

    let mut client = state.ipmi_client.lock().await;
    client.send_ipmi_command(0x00, 0x30, &[0x00]).await.map_err(|e| e.to_string())?;
    Ok("Power off sent via IPMI".to_string())
}

#[tauri::command]
pub async fn power_cycle(state: tauri::State<'_, AppState>) -> Result<String, String> {
    {
        let rf = state.redfish_session.lock().await;
        if let Some(ref session) = *rf {
            session.set_power_state("PowerCycle").await.map_err(|e| e.to_string())?;
            return Ok("Power cycle sent".to_string());
        }
    }

    let mut client = state.ipmi_client.lock().await;
    client.send_ipmi_command(0x00, 0x30, &[0x03]).await.map_err(|e| e.to_string())?;
    Ok("Power cycle sent via IPMI".to_string())
}

#[tauri::command]
pub async fn graceful_shutdown(state: tauri::State<'_, AppState>) -> Result<String, String> {
    {
        let rf = state.redfish_session.lock().await;
        if let Some(ref session) = *rf {
            session.set_power_state("GracefulShutdown").await.map_err(|e| e.to_string())?;
            return Ok("Graceful shutdown sent".to_string());
        }
    }

    let mut client = state.ipmi_client.lock().await;
    client.send_ipmi_command(0x00, 0x30, &[0x05]).await.map_err(|e| e.to_string())?;
    Ok("Graceful shutdown sent via IPMI".to_string())
}

#[tauri::command]
pub async fn force_off(state: tauri::State<'_, AppState>) -> Result<String, String> {
    {
        let rf = state.redfish_session.lock().await;
        if let Some(ref session) = *rf {
            session.set_power_state("ForceOff").await.map_err(|e| e.to_string())?;
            return Ok("Force off sent".to_string());
        }
    }

    let mut client = state.ipmi_client.lock().await;
    client.send_ipmi_command(0x00, 0x30, &[0x00]).await.map_err(|e| e.to_string())?;
    Ok("Force off sent via IPMI".to_string())
}

#[tauri::command]
pub async fn hard_reset(state: tauri::State<'_, AppState>) -> Result<String, String> {
    {
        let rf = state.redfish_session.lock().await;
        if let Some(ref session) = *rf {
            session.set_power_state("ForceRestart").await.map_err(|e| e.to_string())?;
            return Ok("Hard reset sent".to_string());
        }
    }

    let mut client = state.ipmi_client.lock().await;
    client.send_ipmi_command(0x00, 0x30, &[0x02]).await.map_err(|e| e.to_string())?;
    Ok("Hard reset sent via IPMI".to_string())
}

#[tauri::command]
pub async fn get_sensors(state: tauri::State<'_, AppState>) -> Result<Vec<SensorReading>, String> {
    let mut sensors = Vec::new();

    let rf = state.redfish_session.lock().await;
    if let Some(ref session) = *rf {
        if let Ok(thermal) = session.get_thermal().await {
            for t in &thermal.temperatures {
                sensors.push(SensorReading {
                    name: t.name.clone(),
                    value: t.reading_celsius,
                    unit: "\u{00b0}C".to_string(),
                    status: t.status.health.clone().unwrap_or_else(|| "OK".to_string()),
                    upper_critical: t.upper_critical,
                    lower_critical: t.lower_critical,
                });
            }
            for f in &thermal.fans {
                sensors.push(SensorReading {
                    name: f.name.clone(),
                    value: f.reading,
                    unit: f.reading_units.clone().unwrap_or_else(|| "RPM".to_string()),
                    status: f.status.health.clone().unwrap_or_else(|| "OK".to_string()),
                    upper_critical: None,
                    lower_critical: None,
                });
            }
        }
    }

    Ok(sensors)
}

#[tauri::command]
pub async fn get_sel_entries(state: tauri::State<'_, AppState>) -> Result<Vec<SelEntry>, String> {
    let rf = state.redfish_session.lock().await;
    if let Some(ref session) = *rf {
        session.get_sel().await.map_err(|e| e.to_string())
    } else {
        Ok(Vec::new())
    }
}

#[tauri::command]
pub async fn clear_sel(state: tauri::State<'_, AppState>) -> Result<String, String> {
    let rf = state.redfish_session.lock().await;
    if let Some(ref session) = *rf {
        session.clear_sel().await.map_err(|e| e.to_string())?;
        Ok("SEL cleared".to_string())
    } else {
        Err("Not connected via Redfish".to_string())
    }
}

#[tauri::command]
pub async fn get_fru_info(state: tauri::State<'_, AppState>) -> Result<FruInfo, String> {
    let rf = state.redfish_session.lock().await;
    if let Some(ref session) = *rf {
        session.get_fru().await.map_err(|e| e.to_string())
    } else {
        Ok(FruInfo { board: None, product: None, chassis: None })
    }
}

#[tauri::command]
pub async fn sol_activate(state: tauri::State<'_, AppState>) -> Result<String, String> {
    let mut client = state.ipmi_client.lock().await;
    crate::ipmi::sol::activate_sol(&mut client).await.map_err(|e| e.to_string())?;
    Ok("SOL activated".to_string())
}

#[tauri::command]
pub async fn sol_deactivate(state: tauri::State<'_, AppState>) -> Result<String, String> {
    let mut client = state.ipmi_client.lock().await;
    crate::ipmi::sol::deactivate_sol(&mut client).await.map_err(|e| e.to_string())?;
    Ok("SOL deactivated".to_string())
}

#[tauri::command]
pub async fn sol_send_input(state: tauri::State<'_, AppState>, input: String) -> Result<(), String> {
    let mut client = state.ipmi_client.lock().await;
    crate::ipmi::sol::send_sol_input(&mut client, input.as_bytes()).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn mount_virtual_media(state: tauri::State<'_, AppState>, slot: String, image_url: String, inserted: bool) -> Result<String, String> {
    let rf = state.redfish_session.lock().await;
    if let Some(ref session) = *rf {
        session.mount_virtual_media(&slot, &image_url, inserted).await.map_err(|e| e.to_string())?;
        Ok("Virtual media mounted".to_string())
    } else {
        Err("Not connected via Redfish".to_string())
    }
}

#[tauri::command]
pub async fn unmount_virtual_media(state: tauri::State<'_, AppState>, slot: String) -> Result<String, String> {
    let rf = state.redfish_session.lock().await;
    if let Some(ref session) = *rf {
        session.unmount_virtual_media(&slot).await.map_err(|e| e.to_string())?;
        Ok("Virtual media unmounted".to_string())
    } else {
        Err("Not connected via Redfish".to_string())
    }
}

#[tauri::command]
pub async fn get_virtual_media_status(state: tauri::State<'_, AppState>) -> Result<Vec<VirtualMediaStatus>, String> {
    let rf = state.redfish_session.lock().await;
    if let Some(ref session) = *rf {
        session.get_virtual_media().await.map_err(|e| e.to_string())
    } else {
        Ok(Vec::new())
    }
}

#[tauri::command]
pub async fn set_boot_device(state: tauri::State<'_, AppState>, target: String, persistent: bool) -> Result<String, String> {
    let rf = state.redfish_session.lock().await;
    if let Some(ref session) = *rf {
        let enabled = if persistent { "Continuous" } else { "Once" };
        let body = serde_json::json!({
            "Boot": {
                "BootSourceOverrideTarget": target,
                "BootSourceOverrideEnabled": enabled
            }
        });
        let client = session.client();
        let url = format!("{}/rest/v1/Systems/system", session.base_url);
        let mut req = client.patch(&url).json(&body);
        if let Some(ref token) = session.token {
            req = req.header("X-Auth-Token", token);
        }
        req.send().await.map_err(|e| e.to_string())?
            .error_for_status().map_err(|e| e.to_string())?;
        Ok("Boot device set".to_string())
    } else {
        Err("Not connected via Redfish".to_string())
    }
}

#[tauri::command]
pub async fn start_sol_output_stream(
    app: AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    let socket = {
        let client = state.ipmi_client.lock().await;
        client.get_socket().ok_or("No IPMI socket".to_string())?
    };

    let app_handle = app.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        loop {
            match tokio::time::timeout(
                std::time::Duration::from_millis(100),
                socket.recv(&mut buf),
            ).await {
                Ok(Ok(n)) if n > 0 => {
                    match crate::ipmi::sol::decode_sol_payload(&buf[..n]) {
                        Ok(data) if !data.is_empty() => {
                            let text = String::from_utf8_lossy(&data).to_string();
                            let _ = app_handle.emit("sol-output", text);
                        }
                        _ => {}
                    }
                }
                Ok(Err(_)) => break,
                Err(_) => continue,
                _ => {}
            }
        }
    });

    Ok("SOL output stream started".to_string())
}

#[tauri::command]
pub async fn stop_sol_output_stream() -> Result<String, String> {
    Ok("SOL output stream stopped".to_string())
}
