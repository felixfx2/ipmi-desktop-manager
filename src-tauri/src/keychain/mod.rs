use keyring::Entry;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum KeychainError {
    #[error("Keyring error: {0}")]
    Keyring(#[from] keyring::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("UTF-8 error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
}

pub type KeychainResult<T> = Result<T, KeychainError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCredentials {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub protocol_mode: String,
    pub skip_tls_verify: bool,
}

const SERVICE_NAME: &str = "com.ipmi.desktop-manager";
const CREDENTIALS_KEY: &str = "bmc_credentials";
const PASSWORD_KEY: &str = "bmc_password";

pub fn save_credentials(creds: &StoredCredentials, password: &str) -> KeychainResult<()> {
    log::info!("Saving credentials for {}@{}:{}", creds.username, creds.host, creds.port);
    let cred_entry = Entry::new(SERVICE_NAME, CREDENTIALS_KEY)
        .map_err(|e| { log::error!("Failed to create credential entry: {}", e); e })?;
    let pwd_entry = Entry::new(SERVICE_NAME, PASSWORD_KEY)
        .map_err(|e| { log::error!("Failed to create password entry: {}", e); e })?;

    let creds_json = serde_json::to_string(creds)?;
    cred_entry.set_secret(creds_json.as_bytes())
        .map_err(|e| { log::error!("Failed to set credential secret: {}", e); e })?;
    pwd_entry.set_secret(password.as_bytes())
        .map_err(|e| { log::error!("Failed to set password secret: {}", e); e })?;

    log::info!("Credentials saved successfully");
    Ok(())
}

pub fn load_credentials() -> KeychainResult<Option<(StoredCredentials, String)>> {
    let cred_entry = Entry::new(SERVICE_NAME, CREDENTIALS_KEY)?;
    let pwd_entry = Entry::new(SERVICE_NAME, PASSWORD_KEY)?;

    let creds_result = cred_entry.get_secret();
    let pwd_result = pwd_entry.get_secret();

    match (creds_result, pwd_result) {
        (Ok(creds_bytes), Ok(pwd_bytes)) => {
            let creds_str = String::from_utf8(creds_bytes)?;
            let creds: StoredCredentials = serde_json::from_str(&creds_str)?;
            let password = String::from_utf8(pwd_bytes)?;
            log::info!("Loaded saved credentials for {}@{}", creds.username, creds.host);
            Ok(Some((creds, password)))
        }
        (e1, e2) => {
            log::debug!("No saved credentials found (cred={:?}, pwd={:?})", e1.is_err(), e2.is_err());
            Ok(None)
        }
    }
}

pub fn delete_credentials() -> KeychainResult<()> {
    let cred_entry = Entry::new(SERVICE_NAME, CREDENTIALS_KEY)?;
    let pwd_entry = Entry::new(SERVICE_NAME, PASSWORD_KEY)?;

    let _ = cred_entry.delete_credential();
    let _ = pwd_entry.delete_credential();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_serialization() {
        let creds = StoredCredentials {
            host: "192.168.1.100".into(),
            port: 443,
            username: "ADMIN".into(),
            protocol_mode: "Auto".into(),
            skip_tls_verify: false,
        };
        let json = serde_json::to_string(&creds).unwrap();
        let parsed: StoredCredentials = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.host, "192.168.1.100");
        assert_eq!(parsed.port, 443);
    }
}
