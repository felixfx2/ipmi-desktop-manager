use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::Sha256;
use rand::Rng;

// IPMI 2.0 spec algorithm IDs (from ipmi_constants.h / Table 13-17..19)
const AUTH_NONE:     u8 = 0x00;
const AUTH_SHA1:     u8 = 0x01;
const AUTH_MD5:      u8 = 0x02;
const AUTH_SHA256:   u8 = 0x03;

const INTEG_NONE:        u8 = 0x00;
const INTEG_SHA1_96:     u8 = 0x01;
const INTEG_MD5_128:     u8 = 0x02;
const INTEG_MD5_LEGACY:  u8 = 0x03;
const INTEG_SHA256_128:  u8 = 0x04;

const CRYPT_NONE:        u8 = 0x00;
const CRYPT_AES_CBC_128: u8 = 0x01;

type HmacMd5 = Hmac<md5::Md5>;
type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;

fn hmac_md5(key: &[u8], data: &[u8]) -> Vec<u8> { let mut m = HmacMd5::new_from_slice(key).unwrap(); m.update(data); m.finalize().into_bytes().to_vec() }
fn hmac_sha1(key: &[u8], data: &[u8]) -> Vec<u8> { let mut m = HmacSha1::new_from_slice(key).unwrap(); m.update(data); m.finalize().into_bytes().to_vec() }
fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> { let mut m = HmacSha256::new_from_slice(key).unwrap(); m.update(data); m.finalize().into_bytes().to_vec() }

fn hmac_fn(auth: u8, key: &[u8], data: &[u8]) -> Vec<u8> {
    match auth {
        AUTH_MD5 => hmac_md5(key, data),
        AUTH_SHA1 => hmac_sha1(key, data),
        AUTH_SHA256 => hmac_sha256(key, data),
        _ => panic!("unknown auth algo 0x{:02x}", auth),
    }
}

fn hmac_digest_len(auth: u8) -> usize {
    match auth {
        AUTH_MD5 => 16,
        AUTH_SHA1 => 20,
        AUTH_SHA256 => 32,
        _ => panic!("unknown auth algo 0x{:02x}", auth),
    }
}

fn hmac_block_size(auth: u8) -> usize {
    match auth {
        AUTH_MD5 => 64,
        AUTH_SHA1 => 64,
        AUTH_SHA256 => 128,
        _ => panic!("unknown auth algo 0x{:02x}", auth),
    }
}

/// RAKP-M3 ICV truncation per IPMI spec:
/// SHA1: 12 bytes, MD5: 16 bytes (full), SHA256: 16 bytes
fn rakp_icv_len(auth: u8) -> usize {
    match auth {
        AUTH_MD5 => 16,
        AUTH_SHA1 => 12,
        AUTH_SHA256 => 16,
        _ => panic!("unknown auth algo 0x{:02x}", auth),
    }
}

/// Session integrity code (auth tag) size per integrity algorithm
fn integrity_code_len(integ: u8) -> usize {
    match integ {
        INTEG_SHA1_96 => 12,
        INTEG_MD5_128 | INTEG_MD5_LEGACY => 16,
        INTEG_SHA256_128 => 16,
        _ => panic!("unknown integrity algo 0x{:02x}", integ),
    }
}

// Two's complement checksum (ipmitool uses this)
fn checksum(data: &[u8]) -> u8 {
    data.iter().fold(0u8, |a, &b| a.wrapping_add(b)).wrapping_neg()
}

fn hex(label: &str, data: &[u8]) {
    print!("{}: [{}b] ", label, data.len());
    for (i, b) in data.iter().enumerate() {
        print!("{:02x} ", b);
        if (i + 1) % 32 == 0 && i + 1 < data.len() { print!("\n      "); }
    }
    println!();
}

/// Build an Open Session Request following ipmitool's lanplus.c format exactly.
///
/// RMCP header (4 bytes): [0x06, 0x00, 0xFF, 0x07]
/// Session header (10 bytes): [auth_type=0x06, payload_type=0x10, session_id(4 LE)=0, sequence(4 LE)=0]
/// Session-level msg_length (2 bytes LE) = payload_length (32)
///
/// Payload (32 bytes, IPMI_OPEN_SESSION_REQUEST_SIZE):
///   msg[0] = 0x00              Message tag
///   msg[1] = 0x04              Max privilege (Administrator)
///   msg[2..3] = 0x00           Reserved
///   msg[4..7] = init_sid       Console session ID (4 bytes LE)
///   msg[8..15]  Auth payload:  [0x00, 0x00, 0x00, 0x08, auth_alg, 0, 0, 0]
///   msg[16..23] Integ payload: [0x01, 0x00, 0x00, 0x08, integ_alg, 0, 0, 0]
///   msg[24..31] Crypt payload: [0x02, 0x00, 0x00, 0x08, crypt_alg, 0, 0, 0]
fn build_open_session(auth: u8, integ: u8, confid: u8, init_sid: u32) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(48);

    // RMCP header
    pkt.extend_from_slice(&[0x06, 0x00, 0xFF, 0x07]);

    // Session header (10 bytes)
    pkt.push(0x06); // auth type = IPMI v2.0
    pkt.push(0x10); // payload type = Open Session Request
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // session ID = 0
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // sequence = 0

    // Session-level message length (2 bytes LE) = size of payload that follows
    let payload_len: u16 = 32; // IPMI_OPEN_SESSION_REQUEST_SIZE
    pkt.extend_from_slice(&payload_len.to_le_bytes());

    // --- Payload (32 bytes) ---
    pkt.push(0x00); // Message tag
    pkt.push(0x04); // Max privilege = Administrator
    pkt.push(0x00); // Reserved
    pkt.push(0x00); // Reserved

    // Console session ID (4 bytes LE)
    pkt.extend_from_slice(&init_sid.to_le_bytes());

    // Authentication algorithm payload (8 bytes)
    pkt.push(0x00); // Payload type = 0 (authentication)
    pkt.push(0x00); // Reserved
    pkt.push(0x00); // Reserved
    pkt.push(0x08); // Payload length = 8
    pkt.push(auth); // Algorithm value
    pkt.push(0x00); // Reserved
    pkt.push(0x00); // Reserved
    pkt.push(0x00); // Reserved

    // Integrity algorithm payload (8 bytes)
    pkt.push(0x01); // Payload type = 1 (integrity)
    pkt.push(0x00); // Reserved
    pkt.push(0x00); // Reserved
    pkt.push(0x08); // Payload length = 8
    pkt.push(integ); // Algorithm value
    pkt.push(0x00); // Reserved
    pkt.push(0x00); // Reserved
    pkt.push(0x00); // Reserved

    // Confidentiality algorithm payload (8 bytes)
    pkt.push(0x02); // Payload type = 2 (confidentiality)
    pkt.push(0x00); // Reserved
    pkt.push(0x00); // Reserved
    pkt.push(0x08); // Payload length = 8
    pkt.push(confid); // Algorithm value
    pkt.push(0x00); // Reserved
    pkt.push(0x00); // Reserved
    pkt.push(0x00); // Reserved

    assert_eq!(pkt.len(), 48, "Open Session Request must be 48 bytes");
    pkt
}

/// Parse Open Session Response.
/// Packet layout (bytes from start of UDP packet):
///   0-3:   RMCP header
///   4-13:  Session header [auth(1), payload_type(1), session_id(4 LE), sequence(4 LE)]
///   14-15: Session-level message length (2 bytes LE)
///   16+:   Payload
///
/// Payload format (IPMI spec Table 13-11):
///   msg[0]     = Message tag
///   msg[1]     = RMCP+ status code (0xC0=success)
///   msg[2..3]  = Reserved
///   msg[4]     = Maximum Privilege Level
///   msg[5..7]  = Reserved
///   msg[8..11] = Managed System Session ID (4 bytes LE)
///   msg[12..15]= Console Session ID Echo (4 bytes LE)
///   msg[16]    = Authentication Algorithm Type
///   msg[17..19]= Reserved
///   msg[20]    = Integrity Algorithm Type
///   msg[21..23]= Reserved
///   msg[24]    = Confidentiality Algorithm Type
///   msg[25..27]= Reserved
/// Total payload = 28 bytes on success.
fn parse_open_session_response(pkt: &[u8]) -> Result<(u32, u8, u8, u8), String> {
    if pkt.len() < 17 {
        return Err(format!("Response too short: {} bytes", pkt.len()));
    }

    let payload_type = pkt[5] & 0x3F;
    if payload_type != 0x11 {
        return Err(format!("Not Open Session Response: payload_type=0x{:02x}", payload_type));
    }

    let msglen = u16::from_le_bytes([pkt[14], pkt[15]]) as usize;
    if msglen < 1 {
        return Err(format!("msglen={} is too small", msglen));
    }

    // Payload starts at byte 16
    let p = 16;
    let _status = pkt[p + 0]; // msg[0] = tag, msg[1] = status -- but for 1-byte error, only status

    // If msglen==1, BMC sent just the status code (error shorthand)
    // If msglen>=2, msg[0]=tag, msg[1]=status
    let (tag, actual_status) = if msglen == 1 {
        (0u8, pkt[p])
    } else {
        (pkt[p], pkt[p + 1])
    };

    if actual_status != 0x00 {
        return Err(format!("Open Session failed: tag=0x{:02x} status=0x{:02x} msglen={}", tag, actual_status, msglen));
    }

    if msglen < 28 {
        return Err(format!("Success response msglen={} too small (need 28)", msglen));
    }

    let managed_sid = u32::from_le_bytes([pkt[p + 8], pkt[p + 9], pkt[p + 10], pkt[p + 11]]);
    let auth_algo = pkt[p + 16];
    let integ_algo = pkt[p + 20];
    let confid_algo = pkt[p + 24];

    Ok((managed_sid, auth_algo, integ_algo, confid_algo))
}

/// Build RAKP Message 1 (IPMI spec Table 13-14 / ipmitool ipmi_lanplus_rakp1).
/// Payload only (no checksum, no internal msglen):
///   msg[0]       = Message tag (0x00)
///   msg[1..3]    = Reserved (0x00)
///   msg[4..7]    = Managed System Session ID (4 bytes LE)
///   msg[8..23]   = Random Number A (16 bytes)
///   msg[24]      = Requested Maximum Privilege Level
///   msg[25..26]  = Reserved (0x00)
///   msg[27]      = User Name Length
///   msg[28..]    = User Name (variable, up to 16 bytes)
fn build_rakp_m1(random_a: &[u8], managed_sid: u32, username: &str, priv_level: u8) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(48);

    // RMCP header
    pkt.extend_from_slice(&[0x06, 0x00, 0xFF, 0x07]);

    // Session header (10 bytes): auth=0x06, payload_type=0x12 (RAKP-M1), sid=managed_sid, seq=0
    pkt.push(0x06);
    pkt.push(0x12); // IPMI_PAYLOAD_TYPE_RAKP_1
    pkt.extend_from_slice(&managed_sid.to_le_bytes());
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // seq = 0

    // Session-level message length
    let sess_len_offset = pkt.len();
    pkt.extend_from_slice(&[0x00, 0x00]);

    // --- Payload (IPMI spec Table 13-14 / ipmitool ipmi_lanplus_send_rakp_1) ---
    // payload[0]:      Message tag
    // payload[1..3]:   Reserved
    // payload[4..7]:   Managed System Session ID
    // payload[8..23]:  Random Number A (16 bytes)
    // payload[24]:     Requested Maximum Privilege Level
    // payload[25]:     Name Only Lookup (0x00 = name-only, 0xFF = use GUID too)
    // payload[26]:     User Name Length
    // payload[27..]:   User Name
    pkt.push(0x00); // Message tag
    pkt.push(0x00); // Reserved
    pkt.push(0x00); // Reserved
    pkt.push(0x00); // Reserved

    pkt.extend_from_slice(&managed_sid.to_le_bytes()); // Managed System Session ID
    pkt.extend_from_slice(random_a);                    // Random A (16 bytes)
    pkt.push(priv_level);                               // Requested Max Privilege
    pkt.push(0x00);                                     // Name Only Lookup (0x00 = name-only)
    pkt.push(username.len() as u8);                     // User Name Length
    pkt.extend_from_slice(username.as_bytes());         // User Name

    // Pad username field to 16 bytes (ipmitool pads username to IPMI_MAX_USERNAME_LENGTH)
    let username_padded_len = username.len().min(16);
    let current_after_username = 27 + username_padded_len; // payload bytes up to end of username
    while pkt.len() < 16 + current_after_username {
        pkt.push(0x00);
    }

    // Set session-level msg_length = payload size
    let sess_len_val = (pkt.len() - sess_len_offset - 2) as u16;
    pkt[sess_len_offset..sess_len_offset + 2].copy_from_slice(&sess_len_val.to_le_bytes());

    pkt
}

/// Parse RAKP Message 2 (IPMI spec Table 13-15 / ipmitool read_rakp2_message).
/// Payload starts at byte 16:
///   payload[0]       = Message tag
///   payload[1]       = RMCP+ status code
///   payload[2..3]    = Reserved
///   payload[4..7]    = Managed System Session ID (4 bytes LE)
///   payload[8..23]   = Random Number B (16 bytes)
///   payload[24..39]  = GUID (16 bytes)
///   payload[40]      = User Name Length
///   payload[41..]    = User Name
fn parse_rakp_m2(pkt: &[u8]) -> Result<(u32, Vec<u8>, Vec<u8>), String> {
    if pkt.len() < 56 {
        return Err(format!("RAKP-M2 too short: {} bytes", pkt.len()));
    }

    let payload_type = pkt[5] & 0x3F;
    if payload_type != 0x13 {
        return Err(format!("Not RAKP-M2: payload_type=0x{:02x}", payload_type));
    }

    let msglen = u16::from_le_bytes([pkt[14], pkt[15]]) as usize;
    if msglen < 1 {
        return Err("RAKP-M2 msglen=0".into());
    }

    let p = 16; // payload start
    let status = if msglen >= 2 { pkt[p + 1] } else { pkt[p] };
    if status != 0x00 {
        return Err(format!("RAKP-M2 failed: status=0x{:02x}", status));
    }

    let managed_sid = u32::from_le_bytes([pkt[p + 4], pkt[p + 5], pkt[p + 6], pkt[p + 7]]);
    let random_b = pkt[p + 8..p + 24].to_vec();
    let guid = pkt[p + 24..p + 40].to_vec();

    Ok((managed_sid, random_b, guid))
}

/// Build RAKP Message 3 (IPMI spec Table 13-16 / ipmitool ipmi_lanplus_send_rakp_3).
/// Payload only:
///   msg[0]       = Message tag (0x00)
///   msg[1..3]    = Reserved (0x00)
///   msg[4..]     = Integrity Check Value (ICV, truncated HMAC output)
///       MD5: 16 bytes, SHA1: 12 bytes, SHA256: 16 bytes
///
/// ICV = HMAC(auth_alg, Kg, Random_A || Random_B || ManagedSystemSessionID || AuthAlgorithm || UserNameLen || UserName)
/// Kg  = HMAC(auth_alg, password, Random_B || ManagedSystemSessionID)
fn build_rakp_m3(
    managed_sid: u32,
    random_a: &[u8],
    random_b: &[u8],
    username: &str,
    password: &[u8],
    auth: u8,
) -> Vec<u8> {
    let icv_len = rakp_icv_len(auth);

    // Compute Kg
    let mut kg_input = random_b.to_vec();
    kg_input.extend_from_slice(&managed_sid.to_le_bytes());
    let kg = hmac_fn(auth, password, &kg_input);

    // Compute ICV
    let mut icv_input = Vec::new();
    icv_input.extend_from_slice(random_a);
    icv_input.extend_from_slice(random_b);
    icv_input.extend_from_slice(&managed_sid.to_le_bytes());
    icv_input.push(auth);
    icv_input.push(username.len() as u8);
    icv_input.extend_from_slice(username.as_bytes());

    let full_icv = hmac_fn(auth, &kg, &icv_input);
    let icv = full_icv[..icv_len].to_vec();

    let mut pkt = Vec::with_capacity(16 + 4 + icv_len);

    // RMCP header
    pkt.extend_from_slice(&[0x06, 0x00, 0xFF, 0x07]);

    // Session header: auth=0x06, payload_type=0x14 (RAKP-M3), sid=managed_sid, seq=0
    pkt.push(0x06);
    pkt.push(0x14); // IPMI_PAYLOAD_TYPE_RAKP_3
    pkt.extend_from_slice(&managed_sid.to_le_bytes());
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // seq = 0

    // Session-level message length
    let sess_len_offset = pkt.len();
    pkt.extend_from_slice(&[0x00, 0x00]);

    // --- Payload (4 + icv_len bytes) ---
    pkt.push(0x00); // Message tag
    pkt.push(0x00); // Reserved
    pkt.push(0x00); // Reserved
    pkt.push(0x00); // Reserved
    pkt.extend_from_slice(&icv); // Integrity Check Value

    // Set session-level msg_length
    let sess_len_val = (pkt.len() - sess_len_offset - 2) as u16;
    pkt[sess_len_offset..sess_len_offset + 2].copy_from_slice(&sess_len_val.to_le_bytes());

    pkt
}

/// Parse RAKP Message 4 (IPMI spec Table 13-17 / ipmitool read_rakp4_message).
/// Payload starts at byte 16:
///   payload[0]       = Message tag
///   payload[1]       = RMCP+ status code
///   payload[2..3]    = Reserved
///   payload[4..19]   = GUID (16 bytes)
///   payload[20..23]  = Managed System Session ID (4 bytes LE)
///   payload[24..]    = Integrity Check Value (ICV)
fn parse_rakp_m4(pkt: &[u8]) -> Result<(u32, Vec<u8>), String> {
    let payload_type = pkt[5] & 0x3F;
    if payload_type != 0x15 {
        return Err(format!("Not RAKP-M4: payload_type=0x{:02x}", payload_type));
    }

    let msglen = u16::from_le_bytes([pkt[14], pkt[15]]) as usize;
    if msglen < 1 {
        return Err("RAKP-M4 msglen=0".into());
    }

    let p = 16;
    let status = if msglen >= 2 { pkt[p + 1] } else { pkt[p] };
    if status != 0x00 {
        return Err(format!("RAKP-M4 failed: status=0x{:02x}", status));
    }

    let _guid = pkt[p + 4..p + 20].to_vec();
    let managed_sid = u32::from_le_bytes([pkt[p + 20], pkt[p + 21], pkt[p + 22], pkt[p + 23]]);

    // ICV starts at p+24, length depends on auth algo
    let icv_start = p + 24;
    let icv = if icv_start + rakp_icv_len(0x02) <= pkt.len() {
        pkt[icv_start..icv_start + rakp_icv_len(0x02)].to_vec()
    } else {
        Vec::new()
    };

    Ok((managed_sid, icv))
}

/// Derive session keys per IPMI spec §22.16 / ipmitool lanplus session key derivation.
///
/// Kg  = HMAC(auth, password, Random_B || ManagedSystemSessionID)
/// SIK = HMAC(auth, Kg, Random_A || Random_B || ManagedSystemSessionID || AuthAlgorithm || UserNameLen || UserName)
///       (NOT truncated — full digest output: 20 bytes for SHA1, 16 for MD5, 32 for SHA256)
///
/// K1 = HMAC(auth, SIK, SIK || 0x01 || zeros)  — padded to HMAC block size
/// K2 = HMAC(auth, SIK, SIK || 0x02 || zeros)  — padded to HMAC block size
/// K1 and K2 are truncated for integrity code:
///       SHA1-96: 12 bytes, MD5-128: 16 bytes, SHA256-128: 16 bytes
fn derive_session_keys(
    auth: u8,
    integ: u8,
    password: &[u8],
    random_a: &[u8],
    random_b: &[u8],
    managed_sid: u32,
    username: &str,
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    // Kg
    let mut kg_input = random_b.to_vec();
    kg_input.extend_from_slice(&managed_sid.to_le_bytes());
    let kg = hmac_fn(auth, password, &kg_input);

    // SIK (full output, NOT truncated)
    let mut sik_input = Vec::new();
    sik_input.extend_from_slice(random_a);
    sik_input.extend_from_slice(random_b);
    sik_input.extend_from_slice(&managed_sid.to_le_bytes());
    sik_input.push(auth);
    sik_input.push(username.len() as u8);
    sik_input.extend_from_slice(username.as_bytes());
    let sik = hmac_fn(auth, &kg, &sik_input);

    // K1 and K2: input = SIK || counter(1) || zeros(padding to block size)
    let bs = hmac_block_size(auth);

    let mut k1_input = Vec::with_capacity(bs);
    k1_input.extend_from_slice(&sik);
    k1_input.push(0x01);
    k1_input.resize(bs, 0x00);
    let k1_full = hmac_fn(auth, &sik, &k1_input);

    let mut k2_input = Vec::with_capacity(bs);
    k2_input.extend_from_slice(&sik);
    k2_input.push(0x02);
    k2_input.resize(bs, 0x00);
    let k2_full = hmac_fn(auth, &sik, &k2_input);

    // Truncate K1/K2 to integrity code length
    let k1 = k1_full[..integrity_code_len(integ)].to_vec();
    let k2 = k2_full[..integrity_code_len(integ)].to_vec();

    (sik, k1, k2)
}

#[tokio::main]
async fn main() {
    let host = std::env::var("IPMI_HOST").unwrap_or("10.2.1.10".into());
    let username = std::env::var("IPMI_USER").unwrap_or("ADMIN".into());
    let password = std::env::var("IPMI_PASS").unwrap_or("ADMIN".into());

    println!("=== IPMI 2.0 Protocol Test ===");
    println!("Target: {}:623", host);
    println!("User: '{}' Pass: '{}'", username, password);
    println!();

    let addr: SocketAddr = format!("{}:623", host).parse().unwrap();
    let init_sid: u32 = rand::thread_rng().gen();
    println!("Initiator SID: 0x{:08x}", init_sid);

    // Algorithm combos to try: (auth, integ, confid)
    // Standard IPMI cipher suites:
    //   Suite 0: None+None+None (0x00,0x00,0x00)
    //   Suite 1: SHA1+None+None (0x01,0x00,0x00)
    //   Suite 2: SHA1+SHA1_96+None (0x01,0x01,0x00)
    //   Suite 3: SHA1+SHA1_96+AES_128 (0x01,0x01,0x01) — preferred
    //   Suite 6: MD5+None+None (0x02,0x00,0x00)
    //   Suite 7: MD5+MD5_128+None (0x02,0x02,0x00)
    //   Suite 8: MD5+MD5_128+AES_128 (0x02,0x02,0x01)
    //   Suite 11: SHA256+SHA256_128+AES_128 (0x03,0x04,0x01)
    let combos: Vec<(u8, u8, u8, &str)> = vec![
        (0x00, 0x00, 0x00, "None+None+None"),       // Suite 0 — simplest
        (0x01, 0x00, 0x00, "SHA1+None+None"),        // Suite 1
        (0x01, 0x01, 0x00, "SHA1+SHA1_96+None"),     // Suite 2
        (0x01, 0x01, 0x01, "SHA1+SHA1_96+AES"),      // Suite 3 — preferred
        (0x02, 0x00, 0x00, "MD5+None+None"),         // Suite 6
        (0x02, 0x02, 0x00, "MD5+MD5_128+None"),      // Suite 7
        (0x02, 0x02, 0x01, "MD5+MD5_128+AES"),       // Suite 8
        (0x03, 0x04, 0x01, "SHA256+SHA256_128+AES"), // Suite 11
    ];

    for &(auth, integ, confid, name) in &combos {
        println!("--- Trying: {} (auth={:02x} integ={:02x} conf={:02x}) ---", name, auth, integ, confid);

        let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        socket.connect(addr).await.unwrap();

        // Step 1: Open Session Request
        let req = build_open_session(auth, integ, confid, init_sid);
        hex("  REQ OpenSession", &req);

        socket.send(&req).await.unwrap();

        let mut buf = vec![0u8; 1024];
        match tokio::time::timeout(Duration::from_secs(3), socket.recv(&mut buf)).await {
            Ok(Ok(n)) => {
                hex("  RSP OpenSession", &buf[..n]);

                match parse_open_session_response(&buf[..n]) {
                    Ok((managed_sid, neg_auth, neg_integ, neg_confid)) => {
                        println!("  SUCCESS: managed_sid=0x{:08x} auth=0x{:02x} integ=0x{:02x} confid=0x{:02x}",
                            managed_sid, neg_auth, neg_integ, neg_confid);

                        // Step 2: RAKP-M1
                        let mut random_a = vec![0u8; 16];
                        rand::thread_rng().fill(&mut random_a[..]);

                        let m1 = build_rakp_m1(&random_a, managed_sid, &username, 0x04);
                        hex("  REQ RAKP-M1", &m1);

                        socket.send(&m1).await.unwrap();

                        match tokio::time::timeout(Duration::from_secs(3), socket.recv(&mut buf)).await {
                            Ok(Ok(n)) => {
                                hex("  RSP RAKP-M2", &buf[..n]);

                                match parse_rakp_m2(&buf[..n]) {
                                    Ok((bmc_sid, random_b, guid)) => {
                                        println!("  RAKP-M2: bmc_sid=0x{:08x}", bmc_sid);

                                        // Step 3: RAKP-M3
                                        let m3 = build_rakp_m3(
                                            managed_sid, &random_a, &random_b,
                                            &username, password.as_bytes(), neg_auth,
                                        );
                                        hex("  REQ RAKP-M3", &m3);

                                        socket.send(&m3).await.unwrap();

                                        match tokio::time::timeout(Duration::from_secs(3), socket.recv(&mut buf)).await {
                                            Ok(Ok(n)) => {
                                                hex("  RSP RAKP-M4", &buf[..n]);

                                match parse_rakp_m4(&buf[..n]) {
                                    Ok((managed_sid_m4, _icv)) => {
                                        println!("\n  *** FULL RAKP HANDSHAKE SUCCEEDED! ***");
                                        println!("  Algorithm combo {} works!", name);

                                        // Derive keys
                                        let (sik, k1, k2) = derive_session_keys(
                                            neg_auth, neg_integ, password.as_bytes(),
                                            &random_a, &random_b,
                                            managed_sid, &username,
                                        );
                                        hex("  SIK", &sik);
                                        hex("  K1", &k1);
                                        hex("  K2", &k2);
                                        return;
                                    }
                                    Err(e) => println!("  RAKP-M4: {}", e),
                                }
                                            }
                                            Ok(Err(e)) => println!("  RAKP-M4 recv err: {}", e),
                                            Err(_) => println!("  RAKP-M4 TIMEOUT"),
                                        }
                                    }
                                    Err(e) => println!("  RAKP-M2 parse error: {}", e),
                                }
                            }
                            Ok(Err(e)) => println!("  RAKP-M2 recv err: {}", e),
                            Err(_) => println!("  RAKP-M2 TIMEOUT"),
                        }
                    }
                    Err(e) => println!("  Open Session parse error: {}", e),
                }
            }
            Ok(Err(e)) => println!("  Open Session recv err: {}", e),
            Err(_) => println!("  Open Session TIMEOUT"),
        }

        println!();
    }

    println!("No algorithm combination succeeded.");
}
