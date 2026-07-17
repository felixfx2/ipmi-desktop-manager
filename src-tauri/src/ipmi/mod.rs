use hmac::{Hmac, Mac};
use rand::Rng;
use sha1::Sha1;
use sha2::Sha256;
use std::net::SocketAddr;
use std::sync::Arc;
use thiserror::Error;
use tokio::net::UdpSocket;

pub mod sol;

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

/// RAKP auth algorithm identifiers (IPMI 2.0 spec Table 13-14)
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
enum AuthAlgo {
    HmacMd5_128 = 0x01,
    HmacMd5_256 = 0x02,
    HmacSha1_128 = 0x03,
    HmacSha1_256 = 0x04,
    HmacSha256_128 = 0x05,
    HmacSha256_256 = 0x06,
}

impl AuthAlgo {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::HmacMd5_128),
            0x02 => Some(Self::HmacMd5_256),
            0x03 => Some(Self::HmacSha1_128),
            0x04 => Some(Self::HmacSha1_256),
            0x05 => Some(Self::HmacSha256_128),
            0x06 => Some(Self::HmacSha256_256),
            _ => None,
        }
    }

    fn output_len(&self) -> usize {
        match self {
            Self::HmacMd5_128 | Self::HmacMd5_256 => 16,
            Self::HmacSha1_128 | Self::HmacSha1_256 => 20,
            Self::HmacSha256_128 | Self::HmacSha256_256 => 32,
        }
    }

    fn truncation_len(&self) -> usize {
        match self {
            Self::HmacMd5_128 | Self::HmacSha1_128 | Self::HmacSha256_128 => 16,
            Self::HmacMd5_256 | Self::HmacSha1_256 | Self::HmacSha256_256 => 32,
        }
    }
}

/// Compute HMAC using the negotiated auth algorithm.
/// Returns the full-length HMAC output.
fn compute_hmac(algo: AuthAlgo, key: &[u8], data: &[u8]) -> IpmiResult<Vec<u8>> {
    match algo {
        AuthAlgo::HmacMd5_128 | AuthAlgo::HmacMd5_256 => {
            let mut mac = Hmac::<md5::Md5>::new_from_slice(key)
                .map_err(|e| IpmiError::Protocol(format!("HMAC-MD5 key error: {}", e)))?;
            mac.update(data);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        AuthAlgo::HmacSha1_128 | AuthAlgo::HmacSha1_256 => {
            let mut mac = Hmac::<Sha1>::new_from_slice(key)
                .map_err(|e| IpmiError::Protocol(format!("HMAC-SHA1 key error: {}", e)))?;
            mac.update(data);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        AuthAlgo::HmacSha256_128 | AuthAlgo::HmacSha256_256 => {
            let mut mac = Hmac::<Sha256>::new_from_slice(key)
                .map_err(|e| IpmiError::Protocol(format!("HMAC-SHA256 key error: {}", e)))?;
            mac.update(data);
            Ok(mac.finalize().into_bytes().to_vec())
        }
    }
}

/// Truncate HMAC output to the truncation length for the algorithm
fn trunc_hmac(algo: AuthAlgo, full_hmac: &[u8]) -> Vec<u8> {
    full_hmac[..algo.truncation_len()].to_vec()
}

/// Derive SIK (Session Integrity Key) per IPMI 2.0 spec Section 22.16
fn derive_sik(
    algo: AuthAlgo,
    password: &[u8],
    random_a: &[u8],
    random_b: &[u8],
    managed_sid: u32,
    username: &[u8],
) -> IpmiResult<Vec<u8>> {
    let mut input = Vec::new();
    input.extend_from_slice(random_a);
    input.extend_from_slice(random_b);
    input.extend_from_slice(&managed_sid.to_le_bytes());
    input.push(algo as u8);
    input.push(username.len() as u8);
    input.extend_from_slice(username);

    let full_hmac = compute_hmac(algo, password, &input)?;
    Ok(full_hmac[..algo.truncation_len()].to_vec())
}

/// Derive K1 (integrity key) from SIK per IPMI 2.0 spec
fn derive_k1(algo: AuthAlgo, sik: &[u8]) -> IpmiResult<Vec<u8>> {
    let mut input = Vec::new();
    input.extend_from_slice(sik);
    input.push(0x01);
    input.extend(std::iter::repeat(0x00).take(20));

    let full_hmac = compute_hmac(algo, sik, &input)?;
    Ok(trunc_hmac(algo, &full_hmac))
}

/// Derive K2 (confidentiality key) from SIK per IPMI 2.0 spec
fn derive_k2(algo: AuthAlgo, sik: &[u8]) -> IpmiResult<Vec<u8>> {
    let mut input = Vec::new();
    input.extend_from_slice(sik);
    input.push(0x02);
    input.extend(std::iter::repeat(0x00).take(20));

    let full_hmac = compute_hmac(algo, sik, &input)?;
    Ok(trunc_hmac(algo, &full_hmac))
}

#[derive(Debug, Clone)]
pub struct IpmiSession {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: Vec<u8>,
    pub managed_system_session_id: u32,
    pub initiator_session_id: u32,
    pub auth_algo: AuthAlgo,
    pub seq_number: u32,
    pub sik: Vec<u8>,
    pub k1: Vec<u8>,
    pub k2: Vec<u8>,
    pub random_a: Vec<u8>,
    pub random_b: Vec<u8>,
    pub rmcp_header: [u8; 4],
}

impl IpmiSession {
    pub fn new(host: String, port: u16, username: String, password: String) -> Self {
        let initiator_session_id = rand::thread_rng().gen();
        Self {
            host,
            port,
            username,
            password: password.into_bytes(),
            managed_system_session_id: 0,
            initiator_session_id,
            auth_algo: AuthAlgo::HmacSha1_128,
            seq_number: 0,
            sik: Vec::new(),
            k1: Vec::new(),
            k2: Vec::new(),
            random_a: Vec::new(),
            random_b: Vec::new(),
            rmcp_header: [0x06, 0xff, 0x07, 0xca],
        }
    }

    pub fn is_active(&self) -> bool {
        self.managed_system_session_id != 0 && !self.sik.is_empty()
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

        // Phase 1: Open Session Request/Response
        self.open_session_exchange(&socket, &mut session).await?;

        // Phase 2: RAKP handshake
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

    /// Phase 1: Open Session Request (Message 1) / Response (Message 2)
    async fn open_session_exchange(
        &self,
        socket: &UdpSocket,
        session: &mut IpmiSession,
    ) -> IpmiResult<()> {
        use std::time::Duration;

        let msg = build_open_session_request(session);
        log::debug!("Open Session Request: {} bytes", msg.len());
        socket.send(&msg).await?;

        let mut buf = vec![0u8; 1024];
        let n = tokio::time::timeout(Duration::from_secs(5), socket.recv(&mut buf))
            .await
            .map_err(|_| IpmiError::Timeout)?
            .map_err(IpmiError::Io)?;

        log::debug!("Open Session Response: {} bytes", n);

        if n < 28 {
            return Err(IpmiError::Protocol(format!(
                "Open Session Response too short: {} bytes",
                n
            )));
        }

        parse_open_session_response(&buf[0..n], session)
    }

    /// Phase 2: RAKP-M1/M2/M3/M4 handshake
    async fn rakp_exchange(
        &self,
        socket: &UdpSocket,
        session: &mut IpmiSession,
    ) -> IpmiResult<()> {
        use std::time::Duration;

        // Generate Random_A (16 bytes)
        let rand_a: Vec<u8> = {
            let mut rng = rand::thread_rng();
            (0..16).map(|_| rng.gen()).collect()
        };
        session.random_a = rand_a.clone();

        // Send RAKP-M1 (Message 3)
        let m1 = build_rakp_m1(&rand_a, session);
        log::debug!("RAKP-M1: {} bytes", m1.len());
        socket.send(&m1).await?;

        // Receive RAKP-M2 (Message 4)
        let mut buf = vec![0u8; 1024];
        let n = tokio::time::timeout(Duration::from_secs(5), socket.recv(&mut buf))
            .await
            .map_err(|_| IpmiError::Timeout)?
            .map_err(IpmiError::Io)?;

        log::debug!("RAKP-M2: {} bytes", n);

        if n < 48 {
            return Err(IpmiError::Protocol(format!(
                "RAKP-M2 too short: {} bytes",
                n
            )));
        }

        let m2 = &buf[0..n];
        parse_rakp_m2(m2, session)?;

        // Send RAKP-M3 (Message 5)
        let m3 = build_rakp_m3(session)?;
        log::debug!("RAKP-M3: {} bytes", m3.len());
        socket.send(&m3).await?;

        // Receive RAKP-M4 (Message 6)
        let n = tokio::time::timeout(Duration::from_secs(5), socket.recv(&mut buf))
            .await
            .map_err(|_| IpmiError::Timeout)?
            .map_err(IpmiError::Io)?;

        log::debug!("RAKP-M4: {} bytes", n);

        if n < 28 {
            return Err(IpmiError::Protocol(format!(
                "RAKP-M4 too short: {} bytes",
                n
            )));
        }

        let m4 = &buf[0..n];
        parse_rakp_m4(m4, session)?;

        log::info!(
            "IPMI 2.0 session established: sid=0x{:08x}, algo={:?}",
            session.managed_system_session_id,
            session.auth_algo
        );

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

        // Build the IPMI message (unencrypted part)
        let sid = session.managed_system_session_id.to_le_bytes();

        let mut msg = Vec::new();
        msg.push(0x20); // source addressing (remote console LUN 0)
        msg.push(0x00); // netFn/LUN (App = 0x06 shifted, but here target)
        msg.push(netfn);
        let checksum: u8 = !(msg[0].wrapping_add(msg[1]).wrapping_add(msg[2]));
        msg.push(checksum);
        msg.extend_from_slice(&sid);
        msg.push(0x00); // sequence / LUN
        msg.push(cmd);
        msg.extend_from_slice(data);
        let mut msg_checksum: u8 = 0;
        for b in msg.iter().skip(4) {
            msg_checksum = msg_checksum.wrapping_add(*b);
        }
        msg_checksum = !msg_checksum;
        msg.push(msg_checksum);

        // Build RMCP+ session header
        let session_auth_type = compute_session_auth_type(session);
        let seq_bytes = session.seq_number.to_le_bytes();

        let mut packet = Vec::new();
        packet.extend_from_slice(&session.rmcp_header);
        packet.push(session_auth_type);
        packet.extend_from_slice(&seq_bytes);
        packet.extend_from_slice(&sid);

        // For IPMI 2.0 with AES-CBC-128 confidentiality
        if session_auth_type & 0xC0 == 0x40 {
            // AES-CBC-128 confidentiality
            let iv: Vec<u8> = {
                let mut rng = rand::thread_rng();
                (0..16).map(|_| rng.gen()).collect()
            };
            let padded_msg = pkcs7_pad(&msg, 16);
            let encrypted = cbc_encrypt(&session.k2, &iv, &padded_msg)?;
            let mut auth_data = Vec::new();
            auth_data.extend_from_slice(&iv);
            auth_data.extend_from_slice(&encrypted);

            // Compute integrity HMAC
            let mut auth_input = Vec::new();
            auth_input.extend_from_slice(&packet); // RMCP+ header + session header
            auth_input.extend_from_slice(&seq_bytes);
            auth_input.extend_from_slice(&auth_data);

            let full_hmac = compute_hmac(session.auth_algo, &session.k1, &auth_input)?;
            let auth_code = trunc_hmac(session.auth_algo, &full_hmac);

            packet.extend_from_slice(&auth_code);
            packet.extend_from_slice(&seq_bytes);
            packet.extend_from_slice(&auth_data);
        } else {
            packet.extend_from_slice(&seq_bytes);
            packet.extend_from_slice(&msg);
        }

        let total_len = packet.len();
        packet[5] = (total_len - 6) as u8;

        socket.send(&packet).await?;

        let mut buf = vec![0u8; 4096];
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

        // Parse response - for IPMI 2.0 with encryption, skip auth code + seq + encrypted data header
        let response_data = if session_auth_type & 0xC0 == 0x40 && n > 22 {
            // Skip: auth_code (trunc_len) + seq (4) + IV (16) = find msg data after decryption
            // For now, approximate the response data start
            let skip = session.auth_algo.truncation_len() + 4 + 16;
            if skip < n {
                &buf[skip..n - 1]
            } else {
                &[]
            }
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

/// Compute session auth type byte for IPMI 2.0 session header
/// Bits 7:6 = Confidentiality algo (01 = AES-CBC-128)
/// Bits 2:0 = Integrity algo (matches RAKP auth algo for 128-bit variants)
fn compute_session_auth_type(session: &IpmiSession) -> u8 {
    let confidentiality = 0x01u8; // AES-CBC-128
    let integrity = match session.auth_algo {
        AuthAlgo::HmacMd5_128 | AuthAlgo::HmacMd5_256 => 0x01,
        AuthAlgo::HmacSha1_128 | AuthAlgo::HmacSha1_256 => 0x03,
        AuthAlgo::HmacSha256_128 | AuthAlgo::HmacSha256_256 => 0x05,
    };
    (confidentiality << 6) | (integrity & 0x07)
}

/// Build Open Session Request (IPMI 2.0 Message 1)
fn build_open_session_request(session: &IpmiSession) -> Vec<u8> {
    let mut pkt = Vec::new();

    // RMCP header
    pkt.extend_from_slice(&[0x06, 0xff, 0x07, 0xca]);

    // Session header: auth=0x00, seq=0, sid=0
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    // Message tag
    pkt.push(0x00);

    // Message type: 0x10 = Open Session Request
    pkt.push(0x10);

    // Message length (2 bytes LE) - data after this field
    // Data: max_priv(1) + reserved(1) + init_session_id(4) + auth_algo(1) + integ_algo(1) + confid_algo(1) + reserved(4) = 13
    let msg_len: u16 = 13;
    pkt.extend_from_slice(&msg_len.to_le_bytes());

    // Maximum privilege level: 0x04 = Administrator
    pkt.push(0x04);

    // Reserved
    pkt.push(0x00);

    // Initiator Session ID (4 bytes LE)
    pkt.extend_from_slice(&session.initiator_session_id.to_le_bytes());

    // Authentication algorithm: 0x05 = HMAC-SHA256-128
    pkt.push(AuthAlgo::HmacSha256_128 as u8);

    // Integrity algorithm: 0x05 = HMAC-SHA256-128
    pkt.push(0x05);

    // Confidentiality algorithm: 0x01 = AES-CBC-128
    pkt.push(0x01);

    // Reserved (4 bytes)
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    // Checksum: ~(sum of bytes from byte 4 to last byte before checksum)
    let checksum = compute_checksum(&pkt[4..]);
    pkt.push(checksum);

    pkt
}

/// Parse Open Session Response (IPMI 2.0 Message 2)
fn parse_open_session_response(pkt: &[u8], session: &mut IpmiSession) -> IpmiResult<()> {
    // RMCP header: 4 bytes
    // Session header: 9 bytes (auth=1 + seq=4 + sid=4)
    // Message tag: 1 byte (offset 13)
    // Message type: 1 byte (offset 14) = 0x11
    // Message length: 2 bytes (offset 15-16)
    // Status: 1 byte (offset 17)
    // Max privilege: 1 byte (offset 18)
    // Managed system session ID: 4 bytes (offset 19-22)
    // Initiator session ID: 4 bytes (offset 23-26)
    // Auth algo: 1 byte (offset 27)
    // Integrity algo: 1 byte (offset 28)
    // Confidentiality algo: 1 byte (offset 29)
    // Reserved: 3 bytes (offset 30-32)
    // Checksum: 1 byte (offset 33)

    if pkt.len() < 34 {
        return Err(IpmiError::Protocol("Open Session Response too short".into()));
    }

    // Verify message type = 0x11 (Open Session Response)
    if pkt[14] != 0x11 {
        return Err(IpmiError::Protocol(format!(
            "Unexpected message type in Open Session Response: 0x{:02x}",
            pkt[14]
        )));
    }

    let status = pkt[17];
    if status != 0x00 {
        return Err(IpmiError::AuthFailed(format!(
            "Open Session Response status: 0x{:02x}",
            status
        )));
    }

    // Managed system session ID (from message data, not session header)
    session.managed_system_session_id = u32::from_le_bytes([pkt[19], pkt[20], pkt[21], pkt[22]]);

    // Verify initiator session ID echo
    let echo_init_sid = u32::from_le_bytes([pkt[23], pkt[24], pkt[25], pkt[26]]);
    if echo_init_sid != session.initiator_session_id {
        return Err(IpmiError::Protocol(format!(
            "Initiator session ID mismatch: sent 0x{:08x}, got 0x{:08x}",
            session.initiator_session_id, echo_init_sid
        )));
    }

    // Read negotiated algorithms (from message data)
    let auth_algo_val = pkt[27];
    let _integ_algo_val = pkt[28];
    let _confid_algo_val = pkt[29];

    // Use the auth algorithm if the BMC negotiated a different one
    if let Some(algo) = AuthAlgo::from_u8(auth_algo_val) {
        session.auth_algo = algo;
    } else {
        log::warn!(
            "Unknown auth algorithm 0x{:02x}, falling back to SHA256-128",
            auth_algo_val
        );
        session.auth_algo = AuthAlgo::HmacSha256_128;
    }

    log::debug!(
        "Open Session Response: sid=0x{:08x}, auth=0x{:02x}, integ=0x{:02x}, confid=0x{:02x}",
        session.managed_system_session_id,
        auth_algo_val,
        _integ_algo_val,
        _confid_algo_val
    );

    Ok(())
}

/// Build RAKP-M1 (IPMI 2.0 Message 3)
fn build_rakp_m1(rand_a: &[u8], session: &IpmiSession) -> Vec<u8> {
    let mut pkt = Vec::new();

    // RMCP header
    pkt.extend_from_slice(&[0x06, 0xff, 0x07, 0xca]);

    // Session header: auth=0x00, seq=0, sid=managed_system_session_id
    pkt.push(0x00); // Auth type = None
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Seq = 0
    pkt.extend_from_slice(&session.managed_system_session_id.to_le_bytes());

    // RAKP-M1 header
    pkt.push(0x00); // Message tag
    pkt.push(0x12); // Message type: RAKP-M1

    // Message length (2 bytes LE)
    // Data: auth_algo(1) + reserved(3) + random_a(16) + priv_level(1) + username_len(1) + username(N)
    let msg_len: u16 = (4 + 16 + 1 + 1 + session.username.len()) as u16;
    pkt.extend_from_slice(&msg_len.to_le_bytes());

    // Reserved
    pkt.push(0x00);

    // Authentication algorithm
    pkt.push(session.auth_algo as u8);

    // Reserved (3 bytes)
    pkt.extend_from_slice(&[0x00, 0x00, 0x00]);

    // Random_A (16 bytes)
    pkt.extend_from_slice(rand_a);

    // Managed system privilege level: 0x04 = Administrator
    pkt.push(0x04);

    // Username length
    pkt.push(session.username.len() as u8);

    // Username
    pkt.extend_from_slice(session.username.as_bytes());

    // Checksum: ~(sum of bytes from RMCP header payload onwards)
    let checksum = compute_checksum(&pkt[4..]);
    pkt.push(checksum);

    pkt
}

/// Parse RAKP-M2 (IPMI 2.0 Message 4)
fn parse_rakp_m2(m2: &[u8], session: &mut IpmiSession) -> IpmiResult<()> {
    // RMCP header: 4 bytes (0-3)
    // Session header: 9 bytes (4-12): auth(1) + seq(4) + sid(4)
    // Message tag: 1 byte (13)
    // Message type: 1 byte (14) = 0x13 (RAKP-M2)
    // Message length: 2 bytes (15-16)
    // Status: 1 byte (17)
    // Managed system session ID: 4 bytes (18-21)
    // Random_B: 16 bytes (22-37)
    // GUID: 16 bytes (38-53)
    // Username: variable (54+)
    // Checksum: 1 byte (last)

    if m2.len() < 54 {
        return Err(IpmiError::Protocol(format!(
            "RAKP-M2 too short: {} bytes (need at least 54)",
            m2.len()
        )));
    }

    // Verify message type
    if m2[14] != 0x13 {
        return Err(IpmiError::Protocol(format!(
            "Unexpected message type in RAKP-M2: 0x{:02x} (expected 0x13)",
            m2[14]
        )));
    }

    let status = m2[17];
    if status != 0x00 {
        return Err(IpmiError::AuthFailed(format!(
            "RAKP-M2 status: 0x{:02x}",
            status
        )));
    }

    // Managed system session ID (from message data)
    session.managed_system_session_id = u32::from_le_bytes([m2[18], m2[19], m2[20], m2[21]]);

    // Random_B (16 bytes)
    session.random_b = m2[22..38].to_vec();

    // GUID (16 bytes) - stored but not currently used
    let _guid = &m2[38..54];

    log::debug!(
        "RAKP-M2 parsed: sid=0x{:08x}",
        session.managed_system_session_id
    );

    Ok(())
}

/// Build RAKP-M3 (IPMI 2.0 Message 5)
fn build_rakp_m3(session: &IpmiSession) -> IpmiResult<Vec<u8>> {
    let mut pkt = Vec::new();

    // RMCP header
    pkt.extend_from_slice(&[0x06, 0xff, 0x07, 0xca]);

    // Session header: auth=0x00, seq=0, sid=managed_system_session_id
    pkt.push(0x00); // Auth type = None
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Seq = 0
    pkt.extend_from_slice(&session.managed_system_session_id.to_le_bytes());

    // RAKP-M3 header
    pkt.push(0x00); // Message tag
    pkt.push(0x14); // Message type: RAKP-M3

    // Message length (2 bytes LE)
    // Data: integrity_check_value (truncation_len bytes)
    let icv_len = session.auth_algo.truncation_len() as u16;
    pkt.extend_from_slice(&icv_len.to_le_bytes());

    // Compute RAKP-M3 integrity check value per IPMI 2.0 spec Section 22.16
    // ICV = HMAC(Kg, Random_A || Random_B || ManagedSystemSessionID || AuthAlgorithm || UserNameLen || UserName)
    // Kg = HMAC(Password, Random_B || ManagedSystemSessionID)
    let mut kg_input = session.random_b.clone();
    kg_input.extend_from_slice(&session.managed_system_session_id.to_le_bytes());
    let kg = compute_hmac(session.auth_algo, &session.password, &kg_input)?;

    let mut icv_input = Vec::new();
    icv_input.extend_from_slice(&session.random_a);
    icv_input.extend_from_slice(&session.random_b);
    icv_input.extend_from_slice(&session.managed_system_session_id.to_le_bytes());
    icv_input.push(session.auth_algo as u8);
    icv_input.push(session.username.len() as u8);
    icv_input.extend_from_slice(session.username.as_bytes());

    let full_icv = compute_hmac(session.auth_algo, &kg, &icv_input)?;
    let icv = trunc_hmac(session.auth_algo, &full_icv);

    pkt.extend_from_slice(&icv);

    // Checksum
    let checksum = compute_checksum(&pkt[4..]);
    pkt.push(checksum);

    Ok(pkt)
}

/// Parse RAKP-M4 (IPMI 2.0 Message 6)
fn parse_rakp_m4(m4: &[u8], session: &mut IpmiSession) -> IpmiResult<()> {
    // RMCP header: 4 bytes (0-3)
    // Session header: 9 bytes (4-12)
    // Message tag: 1 byte (13)
    // Message type: 1 byte (14) = 0x15 (RAKP-M4)
    // Message length: 2 bytes (15-16)
    // Status: 1 byte (17)
    // GUID: 16 bytes (18-33)
    // Managed system session ID: 4 bytes (34-37)
    // Integrity check value: variable (38+)
    // Checksum: 1 byte (last)

    let icv_len = session.auth_algo.truncation_len();
    let min_len = 38 + icv_len + 1; // header + icv + checksum

    if m4.len() < min_len {
        return Err(IpmiError::Protocol(format!(
            "RAKP-M4 too short: {} bytes (need at least {})",
            m4.len(),
            min_len
        )));
    }

    // Verify message type
    if m4[14] != 0x15 {
        return Err(IpmiError::Protocol(format!(
            "Unexpected message type in RAKP-M4: 0x{:02x} (expected 0x15)",
            m4[14]
        )));
    }

    let status = m4[17];
    if status != 0x00 {
        return Err(IpmiError::AuthFailed(format!(
            "RAKP-M4 status: 0x{:02x}",
            status
        )));
    }

    // GUID (16 bytes)
    let _guid = &m4[18..34];

    // Managed system session ID (from message data, should match)
    let sid = u32::from_le_bytes([m4[34], m4[35], m4[36], m4[37]]);
    if sid != session.managed_system_session_id {
        log::warn!(
            "RAKP-M4 session ID mismatch: expected 0x{:08x}, got 0x{:08x}",
            session.managed_system_session_id,
            sid
        );
    }

    // Integrity check value
    let received_icv = &m4[38..38 + icv_len];

    // Verify RAKP-M4 ICV per IPMI 2.0 spec
    // ICV = HMAC(Kg, Random_A || Random_B || ManagedSystemSessionID || UserNameLen || UserName)
    let mut kg_input = session.random_b.clone();
    kg_input.extend_from_slice(&session.managed_system_session_id.to_le_bytes());
    let kg = compute_hmac(session.auth_algo, &session.password, &kg_input)?;

    let mut icv_input = Vec::new();
    icv_input.extend_from_slice(&session.random_a);
    icv_input.extend_from_slice(&session.random_b);
    icv_input.extend_from_slice(&session.managed_system_session_id.to_le_bytes());
    icv_input.push(session.username.len() as u8);
    icv_input.extend_from_slice(session.username.as_bytes());

    let full_expected_icv = compute_hmac(session.auth_algo, &kg, &icv_input)?;
    let expected_icv = trunc_hmac(session.auth_algo, &full_expected_icv);

    if received_icv != expected_icv {
        return Err(IpmiError::AuthFailed(
            "RAKP-M4 integrity check failed".into(),
        ));
    }

    // Derive session keys
    session.sik = derive_sik(
        session.auth_algo,
        &session.password,
        &session.random_a,
        &session.random_b,
        session.managed_system_session_id,
        &session.username.as_bytes(),
    )?;

    session.k1 = derive_k1(session.auth_algo, &session.sik)?;
    session.k2 = derive_k2(session.auth_algo, &session.sik)?;

    log::debug!(
        "RAKP-M4 verified: sik={} bytes, k1={} bytes, k2={} bytes",
        session.sik.len(),
        session.k1.len(),
        session.k2.len()
    );

    Ok(())
}

/// Compute IPMI checksum: ~(sum of bytes) & 0xFF
fn compute_checksum(data: &[u8]) -> u8 {
    let sum: u8 = data.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
    !sum
}

fn pkcs7_pad(data: &[u8], block_size: usize) -> Vec<u8> {
    let pad_len = block_size - (data.len() % block_size);
    let mut padded = data.to_vec();
    padded.extend(std::iter::repeat(pad_len as u8).take(pad_len));
    padded
}

fn cbc_encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> IpmiResult<Vec<u8>> {
    use cipher::block_padding::NoPadding;
    use cipher::{BlockEncryptMut, KeyIvInit};
    type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

    let encryptor = Aes128CbcEnc::new_from_slices(key, iv)
        .map_err(|e| IpmiError::Protocol(format!("Invalid key/IV: {}", e)))?;
    let mut buf = data.to_vec();
    let _ = encryptor.encrypt_padded_mut::<NoPadding>(&mut buf, data.len());
    Ok(buf)
}

pub fn cbc_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> IpmiResult<Vec<u8>> {
    use cipher::block_padding::NoPadding;
    use cipher::{BlockDecryptMut, KeyIvInit};
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

    #[test]
    fn test_checksum() {
        // Simple checksum test
        let data = [0x01, 0x02, 0x03];
        let cs = compute_checksum(&data);
        // 0x01 + 0x02 + 0x03 = 0x06, !0x06 = 0xF9
        assert_eq!(cs, 0xF9);
    }
}
