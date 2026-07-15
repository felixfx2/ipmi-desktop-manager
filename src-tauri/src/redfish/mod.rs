use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum RedfishError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Connection failed: {0}")]
    Connection(String),
    #[error("Not found: {0}")]
    NotFound(String),
}

pub type RedfishResult<T> = Result<T, RedfishError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedfishSession {
    pub base_url: String,
    pub username: String,
    pub password: String,
    pub token: Option<String>,
    pub session_id: Option<String>,
    pub skip_tls_verify: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PowerState {
    pub power_state: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SystemInfo {
    pub name: String,
    pub model: String,
    pub manufacturer: String,
    pub serial_number: String,
    pub bios_version: String,
    pub power_state: String,
    pub uptime: Option<u64>,
    pub total_memory: Option<u64>,
    pub processor_count: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ThermalInfo {
    pub temperatures: Vec<Temperature>,
    pub fans: Vec<Fan>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Temperature {
    pub name: String,
    pub reading_celsius: Option<f64>,
    pub status: SensorStatus,
    pub upper_critical: Option<f64>,
    pub upper_fatal: Option<f64>,
    pub lower_critical: Option<f64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Fan {
    pub name: String,
    pub reading: Option<f64>,
    pub reading_units: Option<String>,
    pub status: SensorStatus,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SensorStatus {
    pub state: Option<String>,
    pub health: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PowerInfo {
    pub power_consumed_watts: Option<f64>,
    pub power_capacity_watts: Option<f64>,
    pub power_metrics: Option<PowerMetrics>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PowerMetrics {
    pub average_consumed_watts: Option<f64>,
    pub max_consumed_watts: Option<f64>,
    pub min_consumed_watts: Option<f64>,
    pub interval_in_min: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SelEntry {
    pub id: String,
    pub severity: String,
    pub created: String,
    pub message: String,
    pub entry_type: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FruInfo {
    pub board: Option<FruBoard>,
    pub product: Option<FruProduct>,
    pub chassis: Option<FruChassis>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FruBoard {
    pub name: String,
    pub manufacturer: Option<String>,
    pub serial_number: Option<String>,
    pub part_number: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FruProduct {
    pub name: String,
    pub manufacturer: Option<String>,
    pub serial_number: Option<String>,
    pub version: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FruChassis {
    pub name: String,
    pub serial_number: Option<String>,
    pub part_number: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VirtualMediaStatus {
    pub image: Option<String>,
    pub inserted: bool,
    pub write_protected: bool,
    pub media_type: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FirmwareInfo {
    pub bmc_version: Option<String>,
    pub bios_version: Option<String>,
}

impl RedfishSession {
    pub fn new(base_url: String, username: String, password: String, skip_tls_verify: bool) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            username,
            password,
            token: None,
            session_id: None,
            skip_tls_verify,
        }
    }

    pub fn client(&self) -> Client {
        let mut builder = Client::builder()
            .timeout(Duration::from_secs(10));

        if self.skip_tls_verify {
            builder = builder.danger_accept_invalid_certs(true);
        }

        builder.build().unwrap_or_else(|_| Client::builder().timeout(Duration::from_secs(10)).build().expect("HTTP client"))
    }

    pub async fn login(&mut self) -> RedfishResult<()> {
        let client = self.client();
        let url = format!("{}/rest/v1/SessionService/Sessions", self.base_url);

        let body = serde_json::json!({
            "UserName": self.username,
            "Password": self.password
        });

        let resp = client.post(&url)
            .json(&body)
            .send()
            .await?
            .error_for_status()
            .map_err(|e| RedfishError::Connection(e.to_string()))?;

        let headers = resp.headers().clone();
        let session: serde_json::Value = resp.json().await?;

        if let Some(token) = headers.get("x-auth-token") {
            self.token = Some(token.to_str().unwrap_or("").to_string());
        } else if let Some(token) = session.get("Token").and_then(|v| v.as_str()) {
            self.token = Some(token.to_string());
        }

        if let Some(id) = session.get("Id").and_then(|v| v.as_str()) {
            self.session_id = Some(id.to_string());
        } else if let Some(id) = session.get("SessionId").and_then(|v| v.as_str()) {
            self.session_id = Some(id.to_string());
        }

        if self.token.is_none() {
            return Err(RedfishError::Connection("No auth token received from BMC".to_string()));
        }

        Ok(())
    }

    pub fn auth_headers(&self) -> Vec<(String, String)> {
        let mut headers = vec![
            ("Content-Type".to_string(), "application/json".to_string()),
        ];
        if let Some(ref token) = self.token {
            headers.push(("X-Auth-Token".to_string(), token.clone()));
        }
        headers
    }

    pub async fn get_json(&self, path: &str) -> RedfishResult<serde_json::Value> {
        let client = self.client();
        let url = format!("{}/rest/v1/{}", self.base_url, path.trim_start_matches('/'));

        let mut req = client.get(&url);
        if let Some(ref token) = self.token {
            req = req.header("X-Auth-Token", token);
        }

        let resp = req.send().await?
            .error_for_status()
            .map_err(|e| {
                if e.status().map_or(false, |s| s.as_u16() == 404) {
                    RedfishError::NotFound(path.to_string())
                } else {
                    RedfishError::Connection(e.to_string())
                }
            })?;

        Ok(resp.json().await?)
    }

    pub async fn post_action(&self, path: &str, action: &str, body: Option<serde_json::Value>) -> RedfishResult<()> {
        let client = self.client();
        let url = format!("{}/rest/v1/{}/Actions/{}", self.base_url, path.trim_start_matches('/'), action);

        let mut req = client.post(&url);
        if let Some(ref token) = self.token {
            req = req.header("X-Auth-Token", token);
        }
        if let Some(body) = body {
            req = req.json(&body);
        }

        req.send().await?
            .error_for_status()
            .map_err(|e| RedfishError::Connection(e.to_string()))?;

        Ok(())
    }

    pub async fn get_system_info(&self) -> RedfishResult<SystemInfo> {
        let val = self.get_json("Systems/system").await?;

        Ok(SystemInfo {
            name: val.get("Name").and_then(|v| v.as_str()).unwrap_or("Unknown").to_string(),
            model: val.get("Model").and_then(|v| v.as_str()).unwrap_or("Unknown").to_string(),
            manufacturer: val.get("Manufacturer").and_then(|v| v.as_str()).unwrap_or("Unknown").to_string(),
            serial_number: val.get("SerialNumber").and_then(|v| v.as_str()).unwrap_or("Unknown").to_string(),
            bios_version: val.get("BiosVersion").and_then(|v| v.as_str()).unwrap_or("Unknown").to_string(),
            power_state: val.get("PowerState").and_then(|v| v.as_str()).unwrap_or("Unknown").to_string(),
            uptime: val.get("BootTime").and_then(|v| v.as_u64()),
            total_memory: val.get("MemorySummary").and_then(|v| v.get("TotalSystemMemoryGiB")).and_then(|v| v.as_f64()).map(|v| v as u64),
            processor_count: val.get("ProcessorSummary").and_then(|v| v.get("Count")).and_then(|v| v.as_u64()),
        })
    }

    pub async fn get_thermal(&self) -> RedfishResult<ThermalInfo> {
        let val = self.get_json("Chassis/1/Thermal").await?;

        let temperatures = val.get("Temperatures")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter().map(|t| Temperature {
                    name: t.get("Name").and_then(|v| v.as_str()).unwrap_or("Unknown").to_string(),
                    reading_celsius: t.get("ReadingCelsius").and_then(|v| v.as_f64()),
                    status: parse_status(t.get("Status")),
                    upper_critical: t.get("UpperThresholdCritical").and_then(|v| v.as_f64()),
                    upper_fatal: t.get("UpperThresholdFatal").and_then(|v| v.as_f64()),
                    lower_critical: t.get("LowerThresholdCritical").and_then(|v| v.as_f64()),
                }).collect()
            })
            .unwrap_or_default();

        let fans = val.get("Fans")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter().map(|f| Fan {
                    name: f.get("Name").and_then(|v| v.as_str()).unwrap_or("Unknown").to_string(),
                    reading: f.get("Reading").and_then(|v| v.as_f64()),
                    reading_units: f.get("ReadingUnits").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    status: parse_status(f.get("Status")),
                }).collect()
            })
            .unwrap_or_default();

        Ok(ThermalInfo { temperatures, fans })
    }

    pub async fn get_power(&self) -> RedfishResult<PowerInfo> {
        let val = self.get_json("Chassis/1/Power").await?;

        let power_control = val.get("PowerControl")
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.first());

        Ok(PowerInfo {
            power_consumed_watts: power_control.and_then(|v| v.get("PowerConsumedWatts")).and_then(|v| v.as_f64()),
            power_capacity_watts: power_control.and_then(|v| v.get("PowerCapacityWatts")).and_then(|v| v.as_f64()),
            power_metrics: power_control.and_then(|v| v.get("PowerMetrics")).map(|m| PowerMetrics {
                average_consumed_watts: m.get("AverageConsumedWatts").and_then(|v| v.as_f64()),
                max_consumed_watts: m.get("MaxConsumedWatts").and_then(|v| v.as_f64()),
                min_consumed_watts: m.get("MinConsumedWatts").and_then(|v| v.as_f64()),
                interval_in_min: m.get("IntervalInMin").and_then(|v| v.as_u64()),
            }),
        })
    }

    pub async fn get_power_state(&self) -> RedfishResult<String> {
        let val = self.get_json("Systems/system").await?;
        Ok(val.get("PowerState").and_then(|v| v.as_str()).unwrap_or("Unknown").to_string())
    }

    pub async fn set_power_state(&self, state: &str) -> RedfishResult<()> {
        let body = serde_json::json!({
            "ResetType": state
        });
        self.post_action("Systems/system", "ComputerSystem.Reset", Some(body)).await
    }

    pub async fn get_sel(&self) -> RedfishResult<Vec<SelEntry>> {
        let val = self.get_json("Managers/1/LogServices/Sel/Entries").await?;

        let entries = val.get("Members")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter().map(|e| SelEntry {
                    id: e.get("Id").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    severity: e.get("Severity").and_then(|v| v.as_str()).unwrap_or("Info").to_string(),
                    created: e.get("Created").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    message: e.get("Message").and_then(|v| v.as_str())
                        .or_else(|| e.get("Message").and_then(|v| v.get("@odata.id")).and_then(|v| v.as_str()))
                        .unwrap_or("").to_string(),
                    entry_type: e.get("EntryType").and_then(|v| v.as_str()).map(|s| s.to_string()),
                }).collect()
            })
            .unwrap_or_default();

        Ok(entries)
    }

    pub async fn clear_sel(&self) -> RedfishResult<()> {
        let body = serde_json::json!({});
        self.post_action("Managers/1/LogServices/Sel", "LogService.ClearLog", Some(body)).await
    }

    pub async fn get_fru(&self) -> RedfishResult<FruInfo> {
        let chassis_val = self.get_json("Chassis/1").await;
        let system_val = self.get_json("Systems/system").await;

        Ok(FruInfo {
            board: Some(FruBoard {
                name: system_val.as_ref().ok()
                    .and_then(|v| v.get("Model"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown Board")
                    .to_string(),
                manufacturer: system_val.as_ref().ok()
                    .and_then(|v| v.get("Manufacturer"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                serial_number: chassis_val.as_ref().ok()
                    .and_then(|v| v.get("SerialNumber"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                part_number: chassis_val.as_ref().ok()
                    .and_then(|v| v.get("PartNumber"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
            }),
            product: Some(FruProduct {
                name: system_val.as_ref().ok()
                    .and_then(|v| v.get("Name"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown System")
                    .to_string(),
                manufacturer: system_val.as_ref().ok()
                    .and_then(|v| v.get("Manufacturer"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                serial_number: system_val.as_ref().ok()
                    .and_then(|v| v.get("SerialNumber"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                version: None,
            }),
            chassis: Some(FruChassis {
                name: chassis_val.as_ref().ok()
                    .and_then(|v| v.get("Name"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown Chassis")
                    .to_string(),
                serial_number: chassis_val.as_ref().ok()
                    .and_then(|v| v.get("SerialNumber"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                part_number: chassis_val.as_ref().ok()
                    .and_then(|v| v.get("PartNumber"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
            }),
        })
    }

    pub async fn get_firmware_info(&self) -> RedfishResult<FirmwareInfo> {
        let manager_val = self.get_json("Managers/1").await;

        let bios_val = self.get_json("Systems/system").await;

        Ok(FirmwareInfo {
            bmc_version: manager_val.ok()
                .and_then(|v| v.get("FirmwareVersion").cloned())
                .and_then(|v| v.as_str().map(|s| s.to_string())),
            bios_version: bios_val.ok()
                .and_then(|v| v.get("BiosVersion").cloned())
                .and_then(|v| v.as_str().map(|s| s.to_string())),
        })
    }

    pub async fn get_virtual_media(&self) -> RedfishResult<Vec<VirtualMediaStatus>> {
        let val = self.get_json("Managers/1/VirtualMedia").await?;

        let members = val.get("Members")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter().map(|vm| VirtualMediaStatus {
                    image: vm.get("Image").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    inserted: vm.get("Inserted").and_then(|v| v.as_bool()).unwrap_or(false),
                    write_protected: vm.get("WriteProtected").and_then(|v| v.as_bool()).unwrap_or(true),
                    media_type: vm.get("MediaTypes").and_then(|v| v.as_array())
                        .and_then(|arr| arr.first())
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                }).collect()
            })
            .unwrap_or_default();

        Ok(members)
    }

    pub async fn mount_virtual_media(&self, slot: &str, image_url: &str, inserted: bool) -> RedfishResult<()> {
        let body = serde_json::json!({
            "Image": image_url,
            "Inserted": inserted,
            "WriteProtected": true
        });
        let client = self.client();
        let url = format!("{}/rest/v1/Managers/1/VirtualMedia/{}", self.base_url, slot);

        let mut req = client.patch(&url).json(&body);
        if let Some(ref token) = self.token {
            req = req.header("X-Auth-Token", token);
        }

        req.send().await?.error_for_status()
            .map_err(|e| RedfishError::Connection(e.to_string()))?;
        Ok(())
    }

    pub async fn unmount_virtual_media(&self, slot: &str) -> RedfishResult<()> {
        self.mount_virtual_media(slot, "", false).await
    }

    pub async fn set_boot_to_virtual_media(&self) -> RedfishResult<()> {
        let body = serde_json::json!({
            "Boot": {
                "BootSourceOverrideTarget": "Cd",
                "BootSourceOverrideEnabled": "Once"
            }
        });
        let client = self.client();
        let url = format!("{}/rest/v1/Systems/system", self.base_url);

        let mut req = client.patch(&url).json(&body);
        if let Some(ref token) = self.token {
            req = req.header("X-Auth-Token", token);
        }

        req.send().await?.error_for_status()
            .map_err(|e| RedfishError::Connection(e.to_string()))?;
        Ok(())
    }

    pub async fn logout(&self) -> RedfishResult<()> {
        if let Some(ref session_id) = self.session_id {
            let client = self.client();
            let url = format!("{}/rest/v1/SessionService/Sessions/{}", self.base_url, session_id);
            let _ = client.delete(&url).send().await;
        }
        Ok(())
    }
}

fn parse_status(val: Option<&serde_json::Value>) -> SensorStatus {
    val.map(|s| SensorStatus {
        state: s.get("State").and_then(|v| v.as_str()).map(|x| x.to_string()),
        health: s.get("Health").and_then(|v| v.as_str()).map(|x| x.to_string()),
    })
    .unwrap_or(SensorStatus { state: None, health: None })
}
