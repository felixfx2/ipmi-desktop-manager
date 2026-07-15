use hmac::{Hmac, Mac};
use rand::Rng;
use sha2::Sha256;
use std::net::SocketAddr;
use std::sync::Arc;
use thiserror::Error;
use tokio::net::UdpSocket;

pub mod sol;

type HmacSha256 = Hmac<Sha256>;

#[derive(Error, Debug)]
pub enum IpmiError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Authentication failed: {0}")]
    AuthFailed(String),
    #[error("Session error: {0}")]
    Session(String),
    #[error("Protocol error: {0}")]
    Protocol(String),
    #[error("Timeout")]
    Timeout,
    #[error("Invalid response")]
    InvalidResponse,
}

pub type IpmiResult<T> = Result<T, IpmiError>;

pub const IPMI_PORT: u16 = 623;

#[derive(Debug, Clone)]
pub struct IpmiSession {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: Vec<u8>,
    pub session_id: u32,
    pub auth_type: u8,
    pub seq_number: u32,
    pub managed_system_session_id: u32,
    pub sik: Vec<u8>,
    pub k1: Vec<u8>,
    pub k2: Vec<u8>,
    pub rmcp_header: [u8; 4],
    pub source_addr: u8,
}

impl IpmiSession {
    pub fn new(host: String, port: u16, username: String, password: String) -> Self {
        Self {
            host,
            port,
            username,
            password: password.into_bytes(),
            session_id: 0,
            auth_type: 0x14,
            seq_number: 0,
            managed_system_session_id: 0,
            sik: Vec::new(),
            k1: Vec::new(),
            k2: Vec::new(),
            rmcp_header: [0x06, 0xff, 0x07, 0xca],
            source_addr: 0x20,
        }
    }

    pub fn is_active(&self) -> bool {
        self.managed_system_session_id != 0
    }
}

pub struct IpmiClient {
    socket: Option<Arc<UdpSocket>>,
    session: Option<IpmiSession>,
}

impl IpmiClient {
    pub fn new() -> Self {
        Self {
            socket: None,
            session: None,
        }
    }

    pub fn is_connected(&self) -> bool {
        self.session.as_ref().is_some_and(|s| s.is_active())
    }

    pub fn get_socket(&self) -> Option<Arc<UdpSocket>> {
        self.socket.clone()
    }

    pub async fn connect(
        &mut self,
        host: &str,
        port: u16,
        username: &str,
        password: &str,
    ) -> IpmiResult<()> {
        let addr: SocketAddr = format!("{}:{}", host, port).parse().map_err(
            |e: std::net::AddrParseError| IpmiError::Protocol(format!("Invalid address: {}", e)),
        )?;

        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(addr).await?;

        let mut session = IpmiSession::new(
            host.to_string(),
            port,
            username.to_string(),
            password.to_string(),
        );

        self.rakp_exchange(&socket, &mut session).await?;

        self.socket = Some(Arc::new(socket));
        self.session = Some(session);
        Ok(())
    }

    pub async fn disconnect(&mut self) -> IpmiResult<()> {
        if self.session.as_ref().is_some_and(|s| s.is_active()) {
            let _ = self.close_session().await;
        }
        self.socket = None;
        self.session = None;
        Ok(())
    }

    async fn rakp_exchange(
        &self,
        socket: &UdpSocket,
        session: &mut IpmiSession,
    ) -> IpmiResult<()> {
        use std::time::Duration;

        let rand_a = {
            let mut rng = rand::thread_rng();
            let mut buf = vec![0u8; 16];
            rng.fill(&mut buf[..]);
            buf
        };

        let m1 = build_rakp_m1(&rand_a, session);
        socket.send(&m1).await?;

        let mut buf = vec![0u8; 1024];
        let n = tokio::time::timeout(Duration::from_secs(5), socket.recv(&mut buf))
            .await
            .map_err(|_| IpmiError::Timeout)?
            .map_err(IpmiError::Io)?;
        if n < 48 {
            return Err(IpmiError::Protocol("RAKP-M2 too short".into()));
        }

        let m2 = &buf[0..n];
        parse_rakp_m2(m2, session)?;

        let m3 = build_rakp_m3(session, &rand_a)?;
        socket.send(&m3).await?;

        let n = tokio::time::timeout(Duration::from_secs(5), socket.recv(&mut buf))
            .await
            .map_err(|_| IpmiError::Timeout)?
            .map_err(IpmiError::Io)?;
        if n < 28 {
            return Err(IpmiError::Protocol("RAKP-M4 too short".into()));
        }

        let m4 = &buf[0..n];
        parse_rakp_m4(m4, session)?;

        Ok(())
    }

    pub async fn send_ipmi_command(
        &mut self,
        netfn: u8,
        cmd: u8,
        data: &[u8],
    ) -> IpmiResult<Vec<u8>> {
        let socket = self
            .socket
            .as_ref()
            .ok_or_else(|| IpmiError::Session("Not connected".into()))?;
        let session = self
            .session
            .as_mut()
            .ok_or_else(|| IpmiError::Session("No session".into()))?;

        session.seq_number = session.seq_number.wrapping_add(1);

        let mut packet = Vec::new();
        packet.extend_from_slice(&session.rmcp_header);

        let seq = session.seq_number.to_le_bytes();
        let sid = session.managed_system_session_id.to_le_bytes();

        packet.extend_from_slice(&[0x06, session.auth_type, sid[0], sid[1], sid[2], sid[3]]);

        let mut msg = Vec::new();
        msg.push(session.source_addr);
        msg.push(0x00);
        msg.push(netfn);
        let checksum: u8 = !(msg[0].wrapping_add(msg[1]).wrapping_add(msg[2]));
        msg.push(checksum);
        msg.extend_from_slice(&sid);
        msg.push(0x00);
        msg.push(cmd);
        msg.extend_from_slice(data);
        let mut msg_checksum: u8 = 0;
        for b in msg.iter().skip(4) {
            msg_checksum = msg_checksum.wrapping_add(*b);
        }
        msg_checksum = !msg_checksum;
        msg.push(msg_checksum);

        if session.auth_type == 0x14 {
            let iv: Vec<u8> = {
                let mut rng = rand::thread_rng();
                (0..16).map(|_| rng.gen()).collect()
            };
            let padded_msg = pkcs7_pad(&msg, 16);
            let encrypted = cbc_encrypt(&session.k2, &iv, &padded_msg)?;
            let mut auth_data = Vec::new();
            auth_data.extend_from_slice(&iv);
            auth_data.extend_from_slice(&encrypted);

            let seq_bytes = session.seq_number.to_le_bytes();
            let mut auth_input = Vec::new();
            auth_input.push(0x06);
            auth_input.push(session.auth_type);
            auth_input.extend_from_slice(&sid);
            auth_input.extend_from_slice(&seq_bytes);
            auth_input.extend_from_slice(&auth_data);

            let mut mac = HmacSha256::new_from_slice(&session.k1)
                .map_err(|e| IpmiError::Protocol(format!("HMAC error: {}", e)))?;
            mac.update(&auth_input);
            let result = mac.finalize();
            let auth_code = result.into_bytes();

            packet.extend_from_slice(&auth_code[..16]);
            packet.extend_from_slice(&seq_bytes);
            packet.extend_from_slice(&auth_data);
        } else {
            packet.extend_from_slice(&seq);
            packet.extend_from_slice(&msg);
        }

        let total_len = packet.len();
        packet[5] = (total_len - 6) as u8;

        socket.send(&packet).await?;

        let mut buf = vec![0u8; 1024];
        let n = match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            socket.recv(&mut buf),
        )
        .await
        {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut
                {
                    return Err(IpmiError::Timeout);
                }
                return Err(IpmiError::Io(e));
            }
            Err(_) => return Err(IpmiError::Timeout),
        };

        if n < 10 {
            return Err(IpmiError::InvalidResponse);
        }

        let response_data = if session.auth_type == 0x14 && n > 22 {
            &buf[22..n - 1]
        } else if n > 10 {
            &buf[10..n - 1]
        } else {
            &[]
        };

        if response_data.len() >= 2 {
            let completion = response_data[response_data.len() - 2];
            if completion != 0 {
                return Err(IpmiError::Protocol(format!(
                    "IPMI command returned completion code: 0x{:02x}",
                    completion
                )));
            }
            Ok(response_data[..response_data.len() - 1].to_vec())
        } else {
            Ok(response_data.to_vec())
        }
    }

    async fn close_session(&mut self) -> IpmiResult<()> {
        self.send_ipmi_command(0x06, 0x3c, &[]).await?;
        Ok(())
    }

    pub fn get_session_mut(&mut self) -> Option<&mut IpmiSession> {
        self.session.as_mut()
    }
}

fn build_rakp_m1(rand_a: &[u8], session: &IpmiSession) -> Vec<u8> {
    let mut m1 = Vec::new();
    m1.extend_from_slice(&[0x06, 0xff, 0x07, 0xca, 0x00, 0x00, 0x00, 0x00]);
    m1.extend_from_slice(&[0x11, 0xbe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    m1.extend_from_slice(rand_a);
    m1.push(session.username.len() as u8);
    m1.extend_from_slice(session.username.as_bytes());

    let mut checksum: u8 = 0;
    for b in &m1[4..] {
        checksum = checksum.wrapping_add(*b);
    }
    checksum = !checksum;
    m1.push(checksum);
    m1
}

fn parse_rakp_m2(m2: &[u8], session: &mut IpmiSession) -> IpmiResult<()> {
    if m2.len() < 48 {
        return Err(IpmiError::Protocol("RAKP-M2 too short".into()));
    }

    let status = m2[20];
    if status != 0x00 {
        return Err(IpmiError::AuthFailed(format!(
            "RAKP-M2 status: 0x{:02x}",
            status
        )));
    }

    session.managed_system_session_id = u32::from_le_bytes([m2[16], m2[17], m2[18], m2[19]]);

    Ok(())
}

fn build_rakp_m3(session: &IpmiSession, rand_a: &[u8]) -> IpmiResult<Vec<u8>> {
    use sha2::Digest;

    let mut m3 = Vec::new();
    m3.extend_from_slice(&[0x06, 0xff, 0x07, 0xca, 0x00, 0x00, 0x00, 0x00]);
    m3.extend_from_slice(&[0x13, 0xbe, 0x00, 0x00]);

    let sid = session.managed_system_session_id.to_le_bytes();
    m3.extend_from_slice(&sid);
    m3.extend_from_slice(rand_a);

    let mut data_to_hash = Vec::new();
    data_to_hash.extend_from_slice(rand_a);
    data_to_hash.extend_from_slice(&session.managed_system_session_id.to_le_bytes());
    data_to_hash.push(0x14);
    data_to_hash.push(session.username.len() as u8);
    data_to_hash.extend_from_slice(session.username.as_bytes());
    data_to_hash.extend_from_slice(&session.password);

    let mut hasher = Sha256::new();
    hasher.update(&data_to_hash);
    let hash = hasher.finalize();
    m3.extend_from_slice(&hash);

    let mut checksum: u8 = 0;
    for b in &m3[4..] {
        checksum = checksum.wrapping_add(*b);
    }
    checksum = !checksum;
    m3.push(checksum);

    Ok(m3)
}

fn parse_rakp_m4(m4: &[u8], session: &mut IpmiSession) -> IpmiResult<()> {
    use sha2::Digest;

    if m4.len() < 28 {
        return Err(IpmiError::Protocol("RAKP-M4 too short".into()));
    }

    let status = m4[16];
    if status != 0x00 {
        return Err(IpmiError::AuthFailed(format!(
            "RAKP-M4 status: 0x{:02x}",
            status
        )));
    }

    let sid = session.managed_system_session_id.to_le_bytes();
    let mut salt_data = Vec::new();
    salt_data.extend_from_slice(&session.password);
    salt_data.extend_from_slice(&sid);

    let mut hasher = Sha256::new();
    hasher.update(&salt_data);
    let salt = hasher.finalize();

    let mut key_data = Vec::new();
    key_data.extend_from_slice(&salt);
    key_data.extend_from_slice(&session.password);
    key_data.extend_from_slice(&sid);

    let mut hasher2 = Sha256::new();
    hasher2.update(&key_data);
    let kg = hasher2.finalize();

    session.sik = kg.to_vec();

    let mut k1_data = Vec::new();
    k1_data.extend_from_slice(&session.sik);
    k1_data.push(0x01);
    k1_data.extend_from_slice(&[0x00; 20]);
    let mut hmac =
        HmacSha256::new_from_slice(&session.sik).map_err(|e| IpmiError::Protocol(format!("HMAC error: {}", e)))?;
    hmac.update(&k1_data);
    session.k1 = hmac.finalize().into_bytes().to_vec();

    let mut k2_data = Vec::new();
    k2_data.extend_from_slice(&session.sik);
    k2_data.push(0x02);
    k2_data.extend_from_slice(&[0x00; 20]);
    let mut hmac2 =
        HmacSha256::new_from_slice(&session.sik).map_err(|e| IpmiError::Protocol(format!("HMAC error: {}", e)))?;
    hmac2.update(&k2_data);
    session.k2 = hmac2.finalize().into_bytes().to_vec();

    Ok(())
}

fn pkcs7_pad(data: &[u8], block_size: usize) -> Vec<u8> {
    let pad_len = block_size - (data.len() % block_size);
    let mut padded = data.to_vec();
    padded.extend(std::iter::repeat(pad_len as u8).take(pad_len));
    padded
}

fn cbc_encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> IpmiResult<Vec<u8>> {
    use cipher::{BlockEncryptMut, KeyIvInit};
    use cipher::block_padding::NoPadding;
    type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

    let encryptor = Aes128CbcEnc::new_from_slices(key, iv)
        .map_err(|e| IpmiError::Protocol(format!("Invalid key/IV: {}", e)))?;
    let mut buf = data.to_vec();
    encryptor.encrypt_padded_mut::<NoPadding>(&mut buf, data.len());
    Ok(buf)
}

pub fn cbc_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> IpmiResult<Vec<u8>> {
    use cipher::{BlockDecryptMut, KeyIvInit};
    use cipher::block_padding::NoPadding;
    type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

    let decryptor = Aes128CbcDec::new_from_slices(key, iv)
        .map_err(|e| IpmiError::Protocol(format!("Invalid key/IV: {}", e)))?;
    let mut buf = data.to_vec();
    decryptor
        .decrypt_padded_mut::<NoPadding>(&mut buf)
        .map_err(|e| IpmiError::Protocol(format!("Decryption failed: {}", e)))?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pkcs7_pad() {
        let data = vec![0x01, 0x02, 0x03];
        let padded = pkcs7_pad(&data, 16);
        assert_eq!(padded.len(), 16);
        assert_eq!(padded[3], 13);
    }

    #[test]
    fn test_session_new() {
        let session = IpmiSession::new(
            "192.168.1.100".into(),
            623,
            "ADMIN".into(),
            "password".into(),
        );
        assert!(!session.is_active());
        assert_eq!(session.port, 623);
    }

    #[test]
    fn test_cbc_roundtrip() {
        let key = [0x42u8; 16];
        let iv = [0x24u8; 16];
        let data = b"Hello IPMI!";
        let padded = pkcs7_pad(data, 16);
        let encrypted = cbc_encrypt(&key, &iv, &padded).unwrap();
        let decrypted = cbc_decrypt(&key, &iv, &encrypted).unwrap();
        assert_eq!(decrypted, padded);
    }
}
