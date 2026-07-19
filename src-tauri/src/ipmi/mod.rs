use hmac::{Hmac, Mac};
use rand::Rng;
use sha1::Sha1;
use sha2::Sha256;
use std::net::SocketAddr;
use std::sync::Arc;
use thiserror::Error;
use tokio::net::UdpSocket;

pub mod sol;

pub const IPMI_PORT: u16 = 623;

const AUTH_NONE: u8 = 0x00;
const AUTH_SHA1: u8 = 0x01;
const AUTH_MD5: u8 = 0x02;
const AUTH_SHA256: u8 = 0x03;

const INTEG_NONE: u8 = 0x00;
const INTEG_SHA1_96: u8 = 0x01;
const INTEG_MD5_128: u8 = 0x02;
const INTEG_MD5_LEGACY: u8 = 0x03;
const INTEG_SHA256_128: u8 = 0x04;

const CRYPT_NONE: u8 = 0x00;
const CRYPT_AES_CBC_128: u8 = 0x01;

const IPMI_AUTHCODE_BUFFER_SIZE: usize = 20;

const RMCP_HEADER: [u8; 4] = [0xFF, 0x00, 0xFF, 0x07];

const PAYLOAD_OPEN_SESSION_REQ: u8 = 0x10;
const PAYLOAD_OPEN_SESSION_RSP: u8 = 0x11;
const PAYLOAD_RAKP_M1: u8 = 0x12;
const PAYLOAD_RAKP_M2: u8 = 0x13;
const PAYLOAD_RAKP_M3: u8 = 0x14;
const PAYLOAD_RAKP_M4: u8 = 0x15;

type HmacMd5Type = Hmac<md5::Md5>;
type HmacSha1Type = Hmac<Sha1>;
type HmacSha256Type = Hmac<Sha256>;

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

fn hmac_fn(auth: u8, key: &[u8], data: &[u8]) -> IpmiResult<Vec<u8>> {
    match auth {
        AUTH_MD5 => {
            let mut m = HmacMd5Type::new_from_slice(key)
                .map_err(|e| IpmiError::Protocol(format!("HMAC-MD5 key error: {}", e)))?;
            m.update(data);
            Ok(m.finalize().into_bytes().to_vec())
        }
        AUTH_SHA1 => {
            let mut m = HmacSha1Type::new_from_slice(key)
                .map_err(|e| IpmiError::Protocol(format!("HMAC-SHA1 key error: {}", e)))?;
            m.update(data);
            Ok(m.finalize().into_bytes().to_vec())
        }
        AUTH_SHA256 => {
            let mut m = HmacSha256Type::new_from_slice(key)
                .map_err(|e| IpmiError::Protocol(format!("HMAC-SHA256 key error: {}", e)))?;
            m.update(data);
            Ok(m.finalize().into_bytes().to_vec())
        }
        _ => Err(IpmiError::Protocol(format!(
            "Unknown auth algo: 0x{:02x}",
            auth
        ))),
    }
}

fn hmac_digest_len(auth: u8) -> usize {
    match auth {
        AUTH_MD5 => 16,
        AUTH_SHA1 => 20,
        AUTH_SHA256 => 32,
        _ => 0,
    }
}

fn rakp_icv_len(auth: u8) -> usize {
    hmac_digest_len(auth)
}

fn integrity_code_len(integ: u8) -> usize {
    match integ {
        INTEG_SHA1_96 => 12,
        INTEG_MD5_128 | INTEG_MD5_LEGACY => 16,
        INTEG_SHA256_128 => 16,
        _ => 0,
    }
}

fn pad_key(password: &[u8]) -> Vec<u8> {
    let mut key = vec![0u8; IPMI_AUTHCODE_BUFFER_SIZE];
    let len = password.len().min(IPMI_AUTHCODE_BUFFER_SIZE);
    key[..len].copy_from_slice(&password[..len]);
    key
}

fn checksum(data: &[u8]) -> u8 {
    data.iter()
        .fold(0u8, |a, &b| a.wrapping_add(b))
        .wrapping_neg()
}

fn ipmi_pad(data: &[u8]) -> Vec<u8> {
    let pad_len = 16 - (data.len() % 16);
    let mut padded = data.to_vec();
    // Pad with incrementing bytes 0x01, 0x02, 0x03, ... (NOT zeros)
    // ipmitool lanplus_encrypt_payload: for (i = 0; i < pad_length; ++i) padded[i] = i + 1;
    for i in 0..pad_len - 1 {
        padded.push((i + 1) as u8);
    }
    padded.push((pad_len - 1) as u8);
    padded
}

fn aes_cbc_encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> IpmiResult<Vec<u8>> {
    use cipher::block_padding::NoPadding;
    use cipher::{BlockEncryptMut, KeyIvInit};
    type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

    let encryptor = Aes128CbcEnc::new_from_slices(key, iv)
        .map_err(|e| IpmiError::Protocol(format!("Invalid key/IV: {}", e)))?;
    let mut buf = data.to_vec();
    let ct = encryptor
        .encrypt_padded_mut::<NoPadding>(&mut buf, data.len())
        .map_err(|e| IpmiError::Protocol(format!("Encryption padding error: {}", e)))?;
    Ok(ct.to_vec())
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

fn derive_sik(
    auth: u8,
    password: &[u8],
    random_a: &[u8],
    random_b: &[u8],
    priv_level: u8,
    username: &str,
) -> IpmiResult<Vec<u8>> {
    let padded_key = pad_key(password);
    let mut input = Vec::new();
    input.extend_from_slice(random_a);
    input.extend_from_slice(random_b);
    input.push(priv_level);
    input.push(username.len() as u8);
    input.extend_from_slice(username.as_bytes());
    hmac_fn(auth, &padded_key, &input)
}

fn derive_k1(auth: u8, sik: &[u8]) -> IpmiResult<Vec<u8>> {
    let const1 = vec![0x01u8; IPMI_AUTHCODE_BUFFER_SIZE];
    hmac_fn(auth, sik, &const1)
}

fn derive_k2(auth: u8, sik: &[u8]) -> IpmiResult<Vec<u8>> {
    let const2 = vec![0x02u8; IPMI_AUTHCODE_BUFFER_SIZE];
    hmac_fn(auth, sik, &const2)
}

#[derive(Debug, Clone)]
pub struct IpmiSession {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: Vec<u8>,
    pub managed_system_session_id: u32,
    pub initiator_session_id: u32,
    pub auth_algo: u8,
    pub integ_algo: u8,
    pub confid_algo: u8,
    pub seq_number: u32,
    pub ipmi_seq: u8,
    pub sik: Vec<u8>,
    pub k1: Vec<u8>,
    pub k2: Vec<u8>,
    pub random_a: Vec<u8>,
    pub random_b: Vec<u8>,
    pub guid: Vec<u8>,
    pub priv_level: u8,
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
            auth_algo: AUTH_SHA1,
            integ_algo: INTEG_SHA1_96,
            confid_algo: CRYPT_AES_CBC_128,
            seq_number: 0,
            ipmi_seq: 0,
            sik: Vec::new(),
            k1: Vec::new(),
            k2: Vec::new(),
            random_a: Vec::new(),
            random_b: Vec::new(),
            guid: Vec::new(),
            priv_level: 0x04,
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

        self.open_session_exchange(&socket, &mut session).await?;
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

    async fn open_session_exchange(
        &self,
        socket: &UdpSocket,
        session: &mut IpmiSession,
    ) -> IpmiResult<()> {
        use std::time::Duration;

        let pkt = build_open_session(
            session.auth_algo,
            session.integ_algo,
            session.confid_algo,
            session.initiator_session_id,
        );
        log::debug!("Open Session Request: {} bytes", pkt.len());
        socket.send(&pkt).await?;

        let mut buf = vec![0u8; 1024];
        let n = tokio::time::timeout(Duration::from_secs(5), socket.recv(&mut buf))
            .await
            .map_err(|_| IpmiError::Timeout)?
            .map_err(IpmiError::Io)?;

        log::debug!("Open Session Response: {} bytes", n);

        let (managed_sid, neg_auth, neg_integ, neg_confid) =
            parse_open_session_response(&buf[..n])
                .map_err(IpmiError::Protocol)?;

        session.managed_system_session_id = managed_sid;
        session.auth_algo = neg_auth;
        session.integ_algo = neg_integ;
        session.confid_algo = neg_confid;

        log::info!(
            "Open Session: sid=0x{:08x} auth=0x{:02x} integ=0x{:02x} confid=0x{:02x}",
            managed_sid,
            neg_auth,
            neg_integ,
            neg_confid
        );

        Ok(())
    }

    async fn rakp_exchange(
        &self,
        socket: &UdpSocket,
        session: &mut IpmiSession,
    ) -> IpmiResult<()> {
        use std::time::Duration;

        let mut random_a = vec![0u8; 16];
        rand::thread_rng().fill(&mut random_a[..]);
        session.random_a = random_a.clone();

        let m1 = build_rakp_m1(
            &random_a,
            session.managed_system_session_id,
            &session.username,
            session.priv_level,
        );
        log::debug!("RAKP-M1: {} bytes", m1.len());
        socket.send(&m1).await?;

        let mut buf = vec![0u8; 1024];
        let n = tokio::time::timeout(Duration::from_secs(5), socket.recv(&mut buf))
            .await
            .map_err(|_| IpmiError::Timeout)?
            .map_err(IpmiError::Io)?;

        log::debug!("RAKP-M2: {} bytes", n);

        let (bmc_sid, random_b, guid) =
            parse_rakp_m2(&buf[..n]).map_err(IpmiError::Protocol)?;

        // NOTE: Do NOT overwrite managed_system_session_id here — it was correctly set
        // by the Open Session Response. The RAKP-M2 echoed "console_id" field (bmc_sid)
        // is the initiator's ID echoed back, NOT the managed system session ID.
        session.random_b = random_b;
        session.guid = guid;

        log::debug!("RAKP-M2: bmc_sid=0x{:08x}", bmc_sid);

        let m3 = build_rakp_m3(
            session.managed_system_session_id,
            session.initiator_session_id,
            &session.random_a,
            &session.random_b,
            &session.username,
            &session.password,
            session.auth_algo,
            session.priv_level & 0x0F, // raw privilege (strip NameOnly bit)
        );
        log::debug!("RAKP-M3: {} bytes", m3.len());
        socket.send(&m3).await?;

        let sik = derive_sik(
            session.auth_algo,
            &session.password,
            &session.random_a,
            &session.random_b,
            session.priv_level & 0x0F, // raw privilege (strip NameOnly bit)
            &session.username,
        )?;
        let k1 = derive_k1(session.auth_algo, &sik)?;
        let k2 = derive_k2(session.auth_algo, &sik)?;

        let n = tokio::time::timeout(Duration::from_secs(5), socket.recv(&mut buf))
            .await
            .map_err(|_| IpmiError::Timeout)?
            .map_err(IpmiError::Io)?;

        log::debug!("RAKP-M4: {} bytes", n);

        parse_rakp_m4(&buf[..n], session.auth_algo, session.integ_algo, &sik, &session.random_a, session.managed_system_session_id, &session.guid)
            .map_err(IpmiError::Protocol)?;

        session.sik = sik;
        session.k1 = k1;
        session.k2 = k2;

        log::info!(
            "RAKP complete: sik={} bytes, k1={} bytes, k2={} bytes",
            session.sik.len(),
            session.k1.len(),
            session.k2.len()
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

        let seq = session.seq_number;
        let rqseq_lun: u8 = ((session.ipmi_seq & 0x3F) << 2) as u8;
        session.seq_number = session.seq_number.wrapping_add(1);
        session.ipmi_seq = session.ipmi_seq.wrapping_add(1);

        let mut msg = Vec::new();
        msg.push(0x20);                         // rs_addr (BMC = responder/target)
        msg.push((netfn << 2) | 0x00);          // netfn | rs_lun
        msg.push(checksum(&msg[0..2]));
        msg.push(0x81);                         // rq_addr = IPMI_REMOTE_SWID (system software address, per ipmitool)
        msg.push(rqseq_lun);                    // rq_seq | rq_lun
        msg.push(cmd);
        msg.extend_from_slice(data);
        msg.push(checksum(&msg[3..]));

        let auth_type: u8 = 0x06; // ipmitool: "ipmi session Auth Type / Format is always 0x06 for IPMI v2"
        // IPMI_MESSAGE (0x00) with auth/encryption flags per IPMI v2.0 spec:
        // bit 7 = encrypted, bit 6 = authenticated
        let mut payload_type: u8 = 0x00; // IPMI_MESSAGE base
        if session.integ_algo != INTEG_NONE {
            payload_type |= 0x40; // authenticated
        }
        if session.confid_algo != CRYPT_NONE {
            payload_type |= 0x80; // encrypted
        }
        let session_id = session.managed_system_session_id;

        let mut packet = Vec::new();
        packet.extend_from_slice(&RMCP_HEADER);
        packet.push(auth_type);
        packet.push(payload_type);
        packet.extend_from_slice(&session_id.to_le_bytes());
        packet.extend_from_slice(&seq.to_le_bytes());

        if session.confid_algo == CRYPT_AES_CBC_128 {
            // ipmitool lanplus_encrypt_payload: encrypts RAW IPMI message directly
            // NO inner integrity — just pad the raw message and encrypt with K2
            let padded = ipmi_pad(&msg);

            let iv: Vec<u8> = {
                let mut rng = rand::thread_rng();
                (0..16).map(|_| rng.gen()).collect()
            };

            let aes_key = &session.k2[..16]; // truncate to 16 bytes for AES-128
            let encrypted = aes_cbc_encrypt(aes_key, &iv, &padded)?;

            let msg_length: u16 = (16 + encrypted.len()) as u16;

            // Outer integrity pad
            let enc_total = 16 + encrypted.len();
            let outer_pad_count = (4 - ((16 + enc_total + 2) % 4)) % 4;
            let outer_pad_bytes = vec![0xFFu8; outer_pad_count];

            let mut outer_input = Vec::new();
            outer_input.push(auth_type);
            outer_input.push(payload_type);
            outer_input.extend_from_slice(&session_id.to_le_bytes());
            outer_input.extend_from_slice(&seq.to_le_bytes());
            outer_input.extend_from_slice(&msg_length.to_le_bytes());
            outer_input.extend_from_slice(&iv);
            outer_input.extend_from_slice(&encrypted);
            outer_input.extend_from_slice(&outer_pad_bytes);
            outer_input.push(outer_pad_count as u8); // pad_length
            outer_input.push(0x07);                    // next_header = IPMI
            let outer_integrity = hmac_fn(session.auth_algo, &session.k1, &outer_input)?;
            let outer_trunc =
                &outer_integrity[..integrity_code_len(session.integ_algo)];

            packet.extend_from_slice(&msg_length.to_le_bytes());
            packet.extend_from_slice(&iv);
            packet.extend_from_slice(&encrypted);
            packet.extend_from_slice(&outer_pad_bytes);
            packet.push(outer_pad_count as u8);        // pad_length
            packet.push(0x07);                          // next_header
            packet.extend_from_slice(outer_trunc);
        } else {
            let msg_length: u16 = msg.len() as u16;

            // Integrity pad: align (header[14] + payload + pad + pad_length[1] + next_header[1]) to 4 bytes
            let pad_count = (4 - ((14 + msg.len() + 2) % 4)) % 4;
            let pad_bytes = vec![0xFFu8; pad_count];

            let mut integrity_input = Vec::new();
            integrity_input.push(auth_type);
            integrity_input.push(payload_type);
            integrity_input.extend_from_slice(&session_id.to_le_bytes());
            integrity_input.extend_from_slice(&seq.to_le_bytes());
            integrity_input.extend_from_slice(&msg_length.to_le_bytes());
            integrity_input.extend_from_slice(&msg);
            integrity_input.extend_from_slice(&pad_bytes);
            integrity_input.push(pad_count as u8);   // pad_length
            integrity_input.push(0x07);                // next_header = IPMI
            let integrity = hmac_fn(session.auth_algo, &session.k1, &integrity_input)?;
            let integrity_trunc = &integrity[..integrity_code_len(session.integ_algo)];

            packet.extend_from_slice(&msg_length.to_le_bytes());
            packet.extend_from_slice(&msg);
            packet.extend_from_slice(&pad_bytes);
            packet.push(pad_count as u8);              // pad_length
            packet.push(0x07);                          // next_header
            packet.extend_from_slice(integrity_trunc);
        }

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

        if n < 16 {
            return Err(IpmiError::InvalidResponse);
        }

        // payload_type (byte 5) carries encryption flags, NOT auth_type (byte 4)
        let resp_payload_type = buf[5];
        let resp_encrypted = (resp_payload_type & 0x80) != 0;
        // Use negotiated integ_algo for auth code length (BMC should match our negotiation)
        let auth_code_len = integrity_code_len(session.integ_algo);

        let _resp_session_id = u32::from_le_bytes([buf[6], buf[7], buf[8], buf[9]]);

        if resp_encrypted {
            if n < 28 {
                return Err(IpmiError::Protocol("Encrypted response too short".into()));
            }

            let resp_msg_len =
                u16::from_le_bytes([buf[14], buf[15]]) as usize;
            let iv_start = 16;
            let iv_end = iv_start + 16;
            let enc_end = iv_end + resp_msg_len - 16;

            if enc_end > n || iv_end > n {
                return Err(IpmiError::Protocol("Encrypted response truncated".into()));
            }

            let iv = &buf[iv_start..iv_end];
            let encrypted = &buf[iv_end..enc_end];
            // Auth code is at end of packet (after pad+pad_length+next_header)
            let outer_integrity = &buf[n - auth_code_len..n];

            // HMAC covers everything before the auth code
            let mut outer_input = Vec::new();
            outer_input.extend_from_slice(&buf[4..n - auth_code_len]);
            let expected_outer = hmac_fn(session.auth_algo, &session.k1, &outer_input)?;
            let expected_outer_trunc = &expected_outer[..auth_code_len];

            if outer_integrity != expected_outer_trunc {
                return Err(IpmiError::AuthFailed(
                    "Response outer integrity check failed".into(),
                ));
            }

            let aes_key = &session.k2[..16]; // truncate to 16 bytes for AES-128
            let decrypted = cbc_decrypt(aes_key, iv, encrypted)?;

            // Remove padding: last byte = pad_length, preceding pad_length bytes are pad (0x01, 0x02...)
            // ipmitool lanplus_decrypt_payload: conf_pad_length = decrypted[bytes_decrypted - 1]
            // payload_size = bytes_decrypted - conf_pad_length - 1
            let pad_len = *decrypted.last().unwrap_or(&0) as usize;
            if pad_len == 0 || pad_len > decrypted.len() || pad_len > 16 {
                return Err(IpmiError::Protocol("Invalid padding in response".into()));
            }

            // ipmitool: payload_size = bytes_decrypted - conf_pad_length - 1
            let ipmi_response = &decrypted[..decrypted.len() - pad_len - 1];

            if ipmi_response.len() >= 3 {
                let completion = ipmi_response[ipmi_response.len() - 1];
                if completion != 0 {
                    return Err(IpmiError::Protocol(format!(
                        "IPMI command returned completion code: 0x{:02x}",
                        completion
                    )));
                }
                Ok(ipmi_response[..ipmi_response.len() - 1].to_vec())
            } else {
                Ok(ipmi_response.to_vec())
            }
        } else {
            let resp_msg_len =
                u16::from_le_bytes([buf[14], buf[15]]) as usize;
            let data_start = 16;
            let data_end = data_start + resp_msg_len;

            if data_end > n || data_start > n {
                return Err(IpmiError::Protocol("Response too short".into()));
            }

            let ipmi_response = &buf[data_start..data_end];
            // Auth code is at end of packet (after pad+pad_length+next_header)
            let resp_ic = &buf[n - auth_code_len..n];

            // HMAC covers everything from byte 4 to auth code start
            let mut verify_input = Vec::new();
            verify_input.extend_from_slice(&buf[4..n - auth_code_len]);
            let expected_ic = hmac_fn(session.auth_algo, &session.k1, &verify_input)?;
            let expected_ic_trunc = &expected_ic[..auth_code_len];

            if resp_ic != expected_ic_trunc {
                return Err(IpmiError::AuthFailed(
                    "Response integrity check failed".into(),
                ));
            }

            if ipmi_response.len() >= 3 {
                let completion = ipmi_response[ipmi_response.len() - 1];
                if completion != 0 {
                    return Err(IpmiError::Protocol(format!(
                        "IPMI command returned completion code: 0x{:02x}",
                        completion
                    )));
                }
                Ok(ipmi_response[..ipmi_response.len() - 1].to_vec())
            } else {
                Ok(ipmi_response.to_vec())
            }
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

fn build_open_session(auth: u8, integ: u8, confid: u8, init_sid: u32) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(48);

    pkt.extend_from_slice(&RMCP_HEADER);

    pkt.push(0x06);
    pkt.push(PAYLOAD_OPEN_SESSION_REQ);
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    let payload_len: u16 = 32;
    pkt.extend_from_slice(&payload_len.to_le_bytes());

    pkt.push(0x00);
    pkt.push(0x04);
    pkt.push(0x00);
    pkt.push(0x00);

    pkt.extend_from_slice(&init_sid.to_le_bytes());

    pkt.push(0x00);
    pkt.push(0x00);
    pkt.push(0x00);
    pkt.push(0x08);
    pkt.push(auth);
    pkt.push(0x00);
    pkt.push(0x00);
    pkt.push(0x00);

    pkt.push(0x01);
    pkt.push(0x00);
    pkt.push(0x00);
    pkt.push(0x08);
    pkt.push(integ);
    pkt.push(0x00);
    pkt.push(0x00);
    pkt.push(0x00);

    pkt.push(0x02);
    pkt.push(0x00);
    pkt.push(0x00);
    pkt.push(0x08);
    pkt.push(confid);
    pkt.push(0x00);
    pkt.push(0x00);
    pkt.push(0x00);

    pkt
}

fn parse_open_session_response(pkt: &[u8]) -> Result<(u32, u8, u8, u8), String> {
    if pkt.len() < 17 {
        return Err(format!("Response too short: {} bytes", pkt.len()));
    }

    let payload_type = pkt[5] & 0x3F;
    if payload_type != PAYLOAD_OPEN_SESSION_RSP {
        return Err(format!(
            "Not Open Session Response: payload_type=0x{:02x}",
            payload_type
        ));
    }

    let msglen = u16::from_le_bytes([pkt[14], pkt[15]]) as usize;
    if msglen < 1 {
        return Err(format!("msglen={} is too small", msglen));
    }

    let p = 16;

    let (_tag, actual_status) = if msglen == 1 {
        (0u8, pkt[p])
    } else {
        (pkt[p], pkt[p + 1])
    };

    if actual_status != 0x00 {
        return Err(format!(
            "Open Session failed: status=0x{:02x} msglen={}",
            actual_status, msglen
        ));
    }

    if msglen < 36 {
        return Err(format!(
            "Success response msglen={} too small (need 36)",
            msglen
        ));
    }

    let managed_sid = u32::from_le_bytes([pkt[p + 8], pkt[p + 9], pkt[p + 10], pkt[p + 11]]);
    let auth_algo = pkt[p + 16];
    let integ_algo = pkt[p + 24];
    let confid_algo = pkt[p + 32];

    Ok((managed_sid, auth_algo, integ_algo, confid_algo))
}

fn build_rakp_m1(random_a: &[u8], managed_sid: u32, username: &str, priv_level: u8) -> Vec<u8> {
    let username_len = username.len().min(16);
    let payload_len = 44 - (16 - username_len);

    let mut pkt = Vec::with_capacity(4 + 10 + 2 + payload_len);

    pkt.extend_from_slice(&RMCP_HEADER);

    pkt.push(0x06);
    pkt.push(PAYLOAD_RAKP_M1);
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    pkt.extend_from_slice(&(payload_len as u16).to_le_bytes());

    pkt.push(0x00);
    pkt.push(0x00);
    pkt.push(0x00);
    pkt.push(0x00);

    pkt.extend_from_slice(&managed_sid.to_le_bytes());
    pkt.extend_from_slice(random_a);

    pkt.push(priv_level);
    pkt.push(0x00);
    pkt.push(0x00);

    pkt.push(username_len as u8);
    pkt.extend_from_slice(username.as_bytes());

    pkt
}

fn parse_rakp_m2(pkt: &[u8]) -> Result<(u32, Vec<u8>, Vec<u8>), String> {
    if pkt.len() < 56 {
        return Err(format!("RAKP-M2 too short: {} bytes", pkt.len()));
    }

    let payload_type = pkt[5] & 0x3F;
    if payload_type != PAYLOAD_RAKP_M2 {
        return Err(format!(
            "Not RAKP-M2: payload_type=0x{:02x}",
            payload_type
        ));
    }

    let msglen = u16::from_le_bytes([pkt[14], pkt[15]]) as usize;
    if msglen < 1 {
        return Err("RAKP-M2 msglen=0".into());
    }

    let p = 16;
    let status = if msglen >= 2 { pkt[p + 1] } else { pkt[p] };
    if status != 0x00 {
        return Err(format!("RAKP-M2 failed: status=0x{:02x}", status));
    }

    let managed_sid = u32::from_le_bytes([pkt[p + 4], pkt[p + 5], pkt[p + 6], pkt[p + 7]]);
    let random_b = pkt[p + 8..p + 24].to_vec();
    let guid = pkt[p + 24..p + 40].to_vec();

    Ok((managed_sid, random_b, guid))
}

fn build_rakp_m3(
    managed_sid: u32,
    console_id: u32,
    _random_a: &[u8],
    random_b: &[u8],
    username: &str,
    password: &[u8],
    auth: u8,
    priv_level: u8,
) -> Vec<u8> {
    let icv_len = rakp_icv_len(auth);
    let padded_key = pad_key(password);

    let mut icv_input = Vec::new();
    icv_input.extend_from_slice(random_b);
    icv_input.extend_from_slice(&console_id.to_le_bytes());
    icv_input.push(priv_level);
    icv_input.push(username.len() as u8);
    icv_input.extend_from_slice(username.as_bytes());

    let full_icv = hmac_fn(auth, &padded_key, &icv_input).unwrap();
    let icv = full_icv[..icv_len].to_vec();

    let mut pkt = Vec::with_capacity(16 + 8 + icv_len);

    pkt.extend_from_slice(&RMCP_HEADER);

    pkt.push(0x06);
    pkt.push(PAYLOAD_RAKP_M3);
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    pkt.extend_from_slice(&[0x00, 0x00]);

    let sess_len_offset = pkt.len();

    pkt.push(0x00);
    pkt.push(0x00);
    pkt.push(0x00);
    pkt.push(0x00);

    pkt.extend_from_slice(&managed_sid.to_le_bytes());

    pkt.extend_from_slice(&icv);

    let sess_len_val = (pkt.len() - sess_len_offset - 2) as u16;
    pkt[sess_len_offset..sess_len_offset + 2]
        .copy_from_slice(&sess_len_val.to_le_bytes());

    pkt
}

/// Parse RAKP Message 4 (ipmitool read_rakp4_message).
/// Payload starts at byte 16:
///   payload[0]     = Message tag
///   payload[1]     = RMCP+ status code
///   payload[2..3]  = Reserved
///   payload[4..7]  = Console Session ID (4 bytes LE, echoed back)
///   payload[8..]   = Integrity Check Value (ICV, truncated HMAC)
///
/// RAKP-M4 ICV = HMAC(auth, SIK, Random_A || SIDc || GUIDc)
/// where SIDc = BMC session ID (from Open Session Response), GUIDc = BMC GUID (from RAKP-M2).
fn parse_rakp_m4(pkt: &[u8], auth: u8, integ: u8, sik: &[u8], random_a: &[u8], bmc_id: u32, bmc_guid: &[u8]) -> Result<Vec<u8>, String> {
    // RAKP-M4 ICV is TRUNCATED (12 bytes for SHA1_96, 16 for MD5_128/SHA256_128)
    let icv_len = integrity_code_len(integ);

    let payload_type = pkt[5] & 0x3F;
    if payload_type != PAYLOAD_RAKP_M4 {
        return Err(format!(
            "Not RAKP-M4: payload_type=0x{:02x}",
            payload_type
        ));
    }

    let msglen = u16::from_le_bytes([pkt[14], pkt[15]]) as usize;
    if msglen < 8 {
        return Err(format!("RAKP-M4 msglen={} too small (need >= 8)", msglen));
    }

    let p = 16;
    let status = pkt[p + 1];
    if status != 0x00 {
        return Err(format!("RAKP-M4 failed: status=0x{:02x}", status));
    }

    // AST2600 (Supermicro) quirk: GUID field is ABSENT from RAKP-M4 response.
    // With GUID:   payload = 8 + 16 + icv_len; ICV at p+24
    // Without GUID: payload = 8 + icv_len;     ICV at p+8
    let has_guid = (msglen - 8) != icv_len;
    let icv_start = if has_guid { p + 8 + 16 } else { p + 8 };
    if icv_start + icv_len > pkt.len() {
        return Err(format!(
            "RAKP-M4 too short for ICV: need {} bytes at offset {}, got {}",
            icv_len,
            icv_start,
            pkt.len()
        ));
    }
    let received_icv = pkt[icv_start..icv_start + icv_len].to_vec();

    // Verify: ICV = HMAC(auth, SIK, Random_A || SIDc || GUIDc)
    // SIDc = BMC session ID from Open Session Response, GUIDc = BMC GUID from RAKP-M2
    let mut verify_input = Vec::new();
    verify_input.extend_from_slice(random_a);
    verify_input.extend_from_slice(&bmc_id.to_le_bytes());
    verify_input.extend_from_slice(bmc_guid);

    let full_expected_icv = hmac_fn(auth, sik, &verify_input)
        .map_err(|e| format!("HMAC error: {}", e))?;
    let expected_icv = full_expected_icv[..icv_len].to_vec();

    if received_icv != expected_icv {
        return Err("RAKP-M4 ICV mismatch".into());
    }

    Ok(received_icv)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipmi_pad() {
        let data = vec![0x01, 0x02, 0x03];
        let padded = ipmi_pad(&data);
        assert_eq!(padded.len(), 16);
        // Pad with incrementing bytes 0x01, 0x02, ... (NOT zeros)
        assert_eq!(padded[3], 0x01);
        assert_eq!(padded[4], 0x02);
        assert_eq!(padded[14], 0x0C);
        assert_eq!(padded[15], 12); // pad_length = pad_len - 1
    }

    #[test]
    fn test_ipmi_pad_aligned() {
        let data = vec![0x01; 16];
        let padded = ipmi_pad(&data);
        assert_eq!(padded.len(), 32);
        assert_eq!(padded[31], 15);
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
    fn test_checksum() {
        let data = [0x01, 0x02, 0x03];
        let cs = checksum(&data);
        assert_eq!(cs, 0xFA);
    }

    #[test]
    fn test_pad_key() {
        let short = pad_key(b"ADMIN");
        assert_eq!(short.len(), 20);
        assert_eq!(&short[..5], b"ADMIN");
        assert_eq!(&short[5..], &[0u8; 15]);

        let exact = pad_key(&[0x42u8; 20]);
        assert_eq!(exact.len(), 20);
        assert_eq!(exact, [0x42u8; 20]);

        let long = pad_key(&[0x42u8; 25]);
        assert_eq!(long.len(), 20);
        assert_eq!(long, [0x42u8; 20]);
    }

    #[test]
    fn test_cbc_roundtrip() {
        let key = [0x42u8; 16];
        let iv = [0x24u8; 16];
        let data = b"Hello IPMI!";
        let padded = ipmi_pad(data);
        let encrypted = aes_cbc_encrypt(&key, &iv, &padded).unwrap();
        let decrypted = cbc_decrypt(&key, &iv, &encrypted).unwrap();
        assert_eq!(decrypted, padded);
    }
}
