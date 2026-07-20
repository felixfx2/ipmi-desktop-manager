#![allow(dead_code, unused_variables)]

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

const RMCP_HEADER: [u8; 4] = [0x06, 0x00, 0xFF, 0x07];

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

/// Pad password to 20 bytes (IPMI_AUTHCODE_BUFFER_SIZE) for use as HMAC key.
/// ipmitool uses session->authcode which is padded to 20 bytes.
fn pad_key(password: &[u8]) -> Vec<u8> {
    let mut key = vec![0u8; 20];
    let len = password.len().min(20);
    key[..len].copy_from_slice(&password[..len]);
    key
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

/// RAKP ICV length = full HMAC output (NOT truncated).
/// ipmitool rakp_icv_len() returns HMAC_MD5_LENGTH=16, HMAC_SHA1_LENGTH=20, HMAC_SHA256_LENGTH=32.
/// Session integrity codes are truncated (SHA1_96=12), but RAKP ICVs use the full digest.
fn rakp_icv_len(auth: u8) -> usize {
    match auth {
        AUTH_MD5 => 16,
        AUTH_SHA1 => 20,
        AUTH_SHA256 => 32,
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
/// Payload format (per ipmitool lanplus.c read_open_session_response):
///   msg[0]     = Message tag
///   msg[1]     = RMCP+ status code (0x00=success)
///   msg[2]     = Maximum Privilege Level
///   msg[3]     = Reserved
///   msg[4..7]  = Console Session ID Echo (4 bytes LE, our ID echoed back)
///   msg[8..11] = BMC Session ID / Managed System Session ID (4 bytes LE)
///   msg[12..15]= Reserved
///   msg[16]    = Authentication Algorithm Type
///   msg[17..19]= Reserved
///   msg[20..23]= Reserved (auth algo payload continuation)
///   msg[24]    = Integrity Algorithm Type
///   msg[25..27]= Reserved
///   msg[28..31]= Reserved (integrity algo payload continuation)
///   msg[32]    = Confidentiality Algorithm Type
///   msg[33..35]= Reserved
/// Total payload = 36 bytes on success.
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

    if msglen < 36 {
        return Err(format!("Success response msglen={} too small (need 36)", msglen));
    }

    let managed_sid = u32::from_le_bytes([pkt[p + 8], pkt[p + 9], pkt[p + 10], pkt[p + 11]]);
    let auth_algo = pkt[p + 16];
    let integ_algo = pkt[p + 24];
    let confid_algo = pkt[p + 32];

    Ok((managed_sid, auth_algo, integ_algo, confid_algo))
}

/// Build RAKP Message 1 (ipmitool ipmi_lanplus_rakp1).
/// Payload (IPMI_RAKP1_MESSAGE_SIZE = 44, but actual length varies with username):
///   msg[0]       = Message tag (0x00)
///   msg[1..3]    = Reserved (0x00)
///   msg[4..7]    = Managed System Session ID (4 bytes LE)
///   msg[8..23]   = Random Number A (16 bytes)
///   msg[24]      = Requested Maximum Privilege Level | Name Only Lookup bit
///   msg[25]      = Reserved (0x00)
///   msg[26]      = Reserved (0x00)
///   msg[27]      = User Name Length
///   msg[28..]    = User Name (variable, padded to 16 bytes)
fn build_rakp_m1(random_a: &[u8], managed_sid: u32, username: &str, priv_level: u8) -> Vec<u8> {
    // Total RAKP-M1 payload = 44 - (16 - username.len())
    let username_len = username.len().min(16);
    let payload_len = 44 - (16 - username_len);
    let pkt_len = 4 + 10 + 2 + payload_len; // RMCP(4) + session(10) + msglen(2) + payload
    let mut pkt = Vec::with_capacity(pkt_len);

    // RMCP header
    pkt.extend_from_slice(&[0x06, 0x00, 0xFF, 0x07]);

    // Session header (10 bytes): auth=0x06, payload_type=0x12 (RAKP-M1), sid=0 (pre-session), seq=0
    pkt.push(0x06);
    pkt.push(0x12); // IPMI_PAYLOAD_TYPE_RAKP_1
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // session ID = 0 (pre-session)
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // seq = 0

    // Session-level message length (2 bytes LE)
    let sess_len_offset = pkt.len();
    pkt.extend_from_slice(&(payload_len as u16).to_le_bytes());

    // --- Payload (ipmitool ipmi_lanplus_send_rakp_1) ---
    pkt.push(0x00); // Message tag
    pkt.push(0x00); // Reserved
    pkt.push(0x00); // Reserved
    pkt.push(0x00); // Reserved

    pkt.extend_from_slice(&managed_sid.to_le_bytes()); // Managed System Session ID
    pkt.extend_from_slice(random_a);                    // Random A (16 bytes)

    // msg[24] = privilege level | name_only_lookup (combined in1 byte per ipmitool)
    pkt.push(priv_level);  // 0x04 = Administrator, name_only_lookup bit is 0

    pkt.push(0x00); // msg[25] = Reserved
    pkt.push(0x00); // msg[26] = Reserved

    // msg[27] = User Name Length
    pkt.push(username_len as u8);

    // msg[28..] = User Name (NOT padded — payload_length accounts for this)
    pkt.extend_from_slice(username.as_bytes());

    pkt
}

/// Parse RAKP Message 2 (IPMI spec Table 13-15 / ipmitool read_rakp2_message).
/// Payload starts at byte 16:
///   payload[0]       = Message tag
///   payload[1]       = RMCP+ status code
///   payload[2..3]    = Reserved
///   payload[4..7]    = Session ID (SIDm per spec — see note below)
///   payload[8..23]   = Random Number B (16 bytes)
///   payload[24..39]  = GUID (16 bytes)
///   payload[40+]     = Key Exchange Authentication Code (HMAC)
///
/// NOTE: ipmitool reads payload[4..7] into rakp2_message.console_id, which is
/// confusing naming. Per the spec, this field is SIDm (Managed System Session ID).
/// However, in practice the BMC echoes the CONSOLE session ID here.
/// ipmitool does NOT overwrite session->v2_data.bmc_id with this value.
fn parse_rakp_m2(pkt: &[u8]) -> Result<(u32, Vec<u8>, Vec<u8>, Vec<u8>), String> {
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

    let sid_m = u32::from_le_bytes([pkt[p + 4], pkt[p + 5], pkt[p + 6], pkt[p + 7]]);
    let random_b = pkt[p + 8..p + 24].to_vec();
    let guid = pkt[p + 24..p + 40].to_vec();

    // Key Exchange Authentication Code (SHA1 = 20 bytes, starting at payload offset 40)
    let hmac_len = match msglen {
        60 => 20,  // SHA1: 40 + 20 = 60
        56 => 16,  // MD5: 40 + 16 = 56
        72 => 32,  // SHA256: 40 + 32 = 72
        _ => if msglen > 40 { msglen - 40 } else { 0 },
    };
    let keac = if hmac_len > 0 && p + 40 + hmac_len <= pkt.len() {
        pkt[p + 40..p + 40 + hmac_len].to_vec()
    } else {
        Vec::new()
    };

    Ok((sid_m, random_b, guid, keac))
}

/// Build RAKP Message 3 (ipmitool ipmi_lanplus_send_rakp_3).
/// Payload only:
///   msg[0]       = Message tag (0x00)
///   msg[1..3]    = Reserved (0x00)
///   msg[4..]     = Integrity Check Value (ICV, truncated HMAC output)
///       MD5: 16 bytes, SHA1: 12 bytes, SHA256: 16 bytes
///
/// Per ipmitool lanplus_generate_rakp3_authcode:
/// ICV = HMAC(auth, Kuid, Random_B || ManagedSystemSessionID || PrivLevel || UsernameLen || UserName)
/// Kuid = password bytes (the authcode)
fn build_rakp_m3(
    managed_sid: u32,
    console_id: u32,
    _random_a: &[u8],
    random_b: &[u8],
    username: &str,
    password: &[u8],
    auth: u8,
    integ: u8,
    priv_level: u8,
) -> Vec<u8> {
    // RAKP-M3 ICV uses the FULL auth algo HMAC output (NOT truncated to integrity code length).
    // ipmitool lanplus_generate_rakp3_authcode sends the full lanplus_HMAC() output.
    // For SHA1: 20 bytes. For MD5: 16 bytes. For SHA256: 32 bytes.
    let icv_len = rakp_icv_len(auth);
    let padded_key = pad_key(password);

    // Compute ICV using Kuid (padded password) as key
    // Per ipmitool lanplus_generate_rakp3_authcode:
    // Input: Random_B || SIDm || PrivLevel || UsernameLen || UserName
    // ipmitool uses session->v2_data.console_id (the CLIENT's session ID) as SIDm.
    // Despite the IPMI spec naming "SIDm" as "Managed System Session ID",
    // ipmitool consistently uses the console (client) session ID here.
    let mut icv_input = Vec::new();
    icv_input.extend_from_slice(random_b);
    icv_input.extend_from_slice(&console_id.to_le_bytes());
    icv_input.push(priv_level);
    icv_input.push(username.len() as u8);
    icv_input.extend_from_slice(username.as_bytes());

    let full_icv = hmac_fn(auth, &padded_key, &icv_input);
    let icv = full_icv[..icv_len].to_vec();

    let mut pkt = Vec::with_capacity(16 + 8 + icv_len);

    // RMCP header
    pkt.extend_from_slice(&[0x06, 0x00, 0xFF, 0x07]);

    // Session header: auth=0x06, payload_type=0x14 (RAKP-M3), sid=0 (pre-session), seq=0
    pkt.push(0x06);
    pkt.push(0x14); // IPMI_PAYLOAD_TYPE_RAKP_3
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // session ID = 0 (pre-session)
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // seq = 0

    // Session-level message length
    let sess_len_offset = pkt.len();
    pkt.extend_from_slice(&[0x00, 0x00]);

    // --- Payload (8 + icv_len bytes per ipmitool) ---
    pkt.push(0x00); // msg[0] = Message tag
    pkt.push(0x00); // msg[1] = RAKP-M2 return code (0 = success)
    pkt.push(0x00); // msg[2] = reserved
    pkt.push(0x00); // msg[3] = reserved

    // msg[4..7] = Managed System Session ID (BMC session ID) — CRITICAL!
    pkt.extend_from_slice(&managed_sid.to_le_bytes());

    pkt.extend_from_slice(&icv); // msg[8..] = Integrity Check Value

    // Set session-level msg_length
    let sess_len_val = (pkt.len() - sess_len_offset - 2) as u16;
    pkt[sess_len_offset..sess_len_offset + 2].copy_from_slice(&sess_len_val.to_le_bytes());

    pkt
}

/// Parse RAKP Message 4 (ipmitool read_rakp4_message).
/// Payload starts at byte 16:
///   payload[0]       = Message tag
///   payload[1]       = RMCP+ status code
///   payload[2..3]    = Reserved
///   payload[4..7]    = Console Session ID (4 bytes LE, echoed back)
///   payload[8..]     = Integrity Check Value (ICV, truncated HMAC)
///
/// RAKP-M4 ICV verification (ipmitool lanplus_rakp4_hmac_matches):
/// ICV = HMAC(auth, SIK, Random_A || SIDc || GUIDc)
/// where SIDc = BMC session ID (from Open Session Response), GUIDc = BMC GUID (from RAKP-M2).
/// Truncated to 12 bytes for SHA1_96.
fn parse_rakp_m4(pkt: &[u8], auth: u8, integ: u8, sik: &[u8], random_a: &[u8], bmc_id: u32, bmc_guid: &[u8]) -> Result<Vec<u8>, String> {
    // RAKP-M4 ICV uses the INTEGRITY algo length (e.g. SHA1_96=12), NOT the auth algo length
    let icv_len = integrity_code_len(integ);

    let payload_type = pkt[5] & 0x3F;
    if payload_type != 0x15 {
        return Err(format!("Not RAKP-M4: payload_type=0x{:02x}", payload_type));
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
    // Detect by checking if payload size minus fixed fields equals icv_len (no GUID)
    // or payload size minus fixed fields equals 16 + icv_len (has GUID).
    let has_guid = (msglen - 8) != icv_len; // if msglen-8 == icv_len, no GUID
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
    // NOTE: ipmitool lanplus_rakp4_hmac_matches uses this order:
    //   Rm(Random_A,16) || SIDc(bmc_id,4) || GUIDc(16)
    let mut verify_input = Vec::new();
    verify_input.extend_from_slice(random_a);
    verify_input.extend_from_slice(&bmc_id.to_le_bytes());
    verify_input.extend_from_slice(bmc_guid);

    let full_expected_icv = hmac_fn(auth, sik, &verify_input);
    let expected_icv = full_expected_icv[..icv_len].to_vec();

    if received_icv != expected_icv {
        return Err(format!(
            "RAKP-M4 ICV mismatch!\n  received:  {}\n  expected:  {}",
            hex_str(&received_icv),
            hex_str(&expected_icv),
        ));
    }

    Ok(received_icv)
}

/// IPMI pad: pad to 16-byte boundary with incrementing bytes (0x01, 0x02, ...),
/// last byte = pad_len.
/// ipmitool lanplus_encrypt_payload: for (i = 0; i < pad_length; ++i) padded[i] = i + 1;
/// padded[input_length + pad_length] = pad_length;
/// Pad len is always 1..=16 (full block of padding added when data is already aligned).
fn ipmi_pad(data: &[u8]) -> Vec<u8> {
    let pad_len = 16 - (data.len() % 16);
    let mut padded = data.to_vec();
    // Pad with incrementing bytes 0x01, 0x02, 0x03, ... (NOT zeros)
    for i in 0..pad_len - 1 {
        padded.push((i + 1) as u8);
    }
    padded.push((pad_len - 1) as u8);
    padded
}

fn aes_cbc_encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
    use cipher::block_padding::NoPadding;
    use cipher::{BlockEncryptMut, KeyIvInit};
    type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

    let encryptor = Aes128CbcEnc::new_from_slices(key, iv)
        .expect("Invalid key/IV for AES-CBC");
    let mut buf = data.to_vec();
    let ct = encryptor
        .encrypt_padded_mut::<NoPadding>(&mut buf, data.len())
        .expect("AES-CBC encryption padding error");
    ct.to_vec()
}

fn cbc_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
    use cipher::block_padding::NoPadding;
    use cipher::{BlockDecryptMut, KeyIvInit};
    type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

    let decryptor = Aes128CbcDec::new_from_slices(key, iv)
        .expect("Invalid key/IV for AES-CBC decrypt");
    let mut buf = data.to_vec();
    decryptor
        .decrypt_padded_mut::<NoPadding>(&mut buf)
        .expect("AES-CBC decryption failed");
    buf
}

fn hex_str(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ")
}

fn hex_inline(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ")
}

/// Derive session keys per ipmitool lanplus session key derivation.
///
/// Kuid = password padded to IPMI_AUTHCODE_BUFFER_SIZE (20 bytes)
/// SIK = HMAC(auth, Kuid, Random_A || Random_B || PrivLevel || UsernameLen || UserName)
///       Full digest output, NOT truncated (20 bytes for SHA1, 16 for MD5, 32 for SHA256)
///
/// K1 = HMAC(auth, SIK, CONST_1)  where CONST_1 = 0x01 repeated 20 times
/// K2 = HMAC(auth, SIK, CONST_2)  where CONST_2 = 0x02 repeated 20 times
/// K1 and K2 are full digest output, NOT truncated (truncation happens when computing auth codes)
fn derive_session_keys(
    auth: u8,
    password: &[u8],
    random_a: &[u8],
    random_b: &[u8],
    username: &str,
    priv_level: u8,
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    // SIK: HMAC(auth, Kuid=padded_password, Random_A || Random_B || PrivLevel || UsernameLen || UserName)
    let padded_key = pad_key(password);
    let mut sik_input = Vec::new();
    sik_input.extend_from_slice(random_a);
    sik_input.extend_from_slice(random_b);
    sik_input.push(priv_level);
    sik_input.push(username.len() as u8);
    sik_input.extend_from_slice(username.as_bytes());
    let sik = hmac_fn(auth, &padded_key, &sik_input);

    // K1 = HMAC(auth, key=SIK, data=CONST_1) where CONST_1 = [0x01; 20]
    let const1 = vec![0x01u8; 20];
    let k1 = hmac_fn(auth, &sik, &const1);

    // K2 = HMAC(auth, key=SIK, data=CONST_2) where CONST_2 = [0x02; 20]
    let const2 = vec![0x02u8; 20];
    let k2 = hmac_fn(auth, &sik, &const2);

    (sik, k1, k2)
}

#[tokio::main]
async fn main() {
    let host = std::env::var("IPMI_HOST").unwrap_or("10.2.1.10".into());
    let username = std::env::var("IPMI_USER").unwrap_or("opencode".into());
    let password = std::env::var("IPMI_PASS").unwrap_or("S8008078f!".into());

    println!("=== IPMI 2.0 Protocol Test ===");
    println!("Target: {}:623", host);
    println!("User: '{}' Pass: '{}'", username, password);
    println!();

    let addr: SocketAddr = format!("{}:623", host).parse().unwrap();

    // ===== RAW v1.5 TEST: Confirm UDP connectivity works =====
    println!("=== v1.5 Raw Test: Get Device ID (no session) ===");
    {
        let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        socket.connect(addr).await.unwrap();

        // Build a raw IPMI v1.5 Get Device ID command (no session, no auth)
        // RMCP header: version=0x06, reserved=0x00, sequence=0xFF (no ACK), class=0x07 (IPMI)
        // Session header: auth_type=0x00 (none), session_seq=0x00000000, session_id=0x00000000
        // Message length: 2 bytes LE
        // IPMI message: rs_addr=0x20, netfn_rslun=0x18 (App NetFn 0x06<<2 | 0x00), checksum, rq_addr=0x81, rq_seq=0x00, cmd=0x01, checksum
        let mut ipmi_msg = Vec::new();
        ipmi_msg.push(0x20); // rs_addr (BMC)
        ipmi_msg.push(0x18); // netfn=0x06 (App), rs_lun=0x00
        ipmi_msg.push(checksum(&ipmi_msg[0..2])); // checksum1
        ipmi_msg.push(0x81); // rq_addr (system software)
        ipmi_msg.push(0x00); // rq_seq=0, rq_lun=0
        ipmi_msg.push(0x01); // cmd = Get Device ID
        ipmi_msg.push(checksum(&ipmi_msg[3..])); // checksum2

        // v1.5 packet: RMCP(4) + session(11) + msglen(2) + ipmi_msg
        let msg_len = ipmi_msg.len() as u16;
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0x06, 0x00, 0xFF, 0x07]); // RMCP header
        pkt.push(0x00); // auth type = none
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // session_seq = 0
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // session_id = 0
        pkt.extend_from_slice(&msg_len.to_le_bytes());     // msg_length = 2 bytes LE
        pkt.extend_from_slice(&ipmi_msg);

        hex("  v1.5 REQ", &pkt);
        socket.send(&pkt).await.ok();

        let mut rbuf = vec![0u8; 1024];
        match tokio::time::timeout(Duration::from_secs(3), socket.recv(&mut rbuf)).await {
            Ok(Ok(n)) => {
                println!("  v1.5 GOT RESPONSE ({} bytes)! UDP works!", n);
                hex("  v1.5 RSP", &rbuf[..n]);
            }
            Ok(Err(e)) => println!("  v1.5 recv error: {}", e),
            Err(_) => println!("  v1.5 TIMEOUT - no response at all"),
        }
    }
    println!();

    // ipmitool HARDCODES console_id = 0xA0A2A3A4 (see lanplus.h)
    // Using a random init_sid causes RAKP-M3 ICV to fail (status=0x08)
    let init_sid: u32 = 0xA0A2A3A4;
    println!("Initiator SID: 0x{:08x} (hardcoded, matching ipmitool)", init_sid);

    // Privilege levels to try (IPMI spec Table 13-17):
    //   0x01 = Callback, 0x02 = User, 0x03 = Operator, 0x04 = Administrator
    // The Name Only lookup bit (0x80) goes in bit 7 of msg[24]
    // per ipmitool: msg[24] = privlvl | lookupbit
    let priv_levels: Vec<(u8, &str)> = vec![
        (0x04 | 0x80, "Admin + NameOnly"),       // Admin with Name Only flag
    ];

    // Try both None and AES-CBM for confidentiality
    let combos: Vec<(u8, u8, u8, &str)> = vec![
        (0x01, 0x01, 0x00, "SHA1+SHA1_96+None"),    // Try None first
        (0x01, 0x01, 0x01, "SHA1+SHA1_96+AES"),     // Then with AES
    ];

    for &(auth, integ, confid, name) in &combos {
    for &(priv_byte, priv_name) in &priv_levels {
        println!("--- Trying: {} auth={:02x} integ={:02x} conf={:02x} priv={} ({:02x}) ---", name, auth, integ, confid, priv_name, priv_byte);

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

                        let m1 = build_rakp_m1(&random_a, managed_sid, &username, priv_byte);
                        hex("  REQ RAKP-M1", &m1);

                        socket.send(&m1).await.unwrap();

                        match tokio::time::timeout(Duration::from_secs(3), socket.recv(&mut buf)).await {
                            Ok(Ok(n)) => {
                                hex("  RSP RAKP-M2", &buf[..n]);

                                match parse_rakp_m2(&buf[..n]) {
                                    Ok((bmc_sid, random_b, guid, keac)) => {
                                        println!("  RAKP-M2: bmc_sid=0x{:08x}", bmc_sid);
                                        hex("  RAKP-M2 KEAC", &keac);

                                        // Verify RAKP-M2 HMAC per ipmitool lanplus_rakp2_hmac_matches
                                        // HMAC(auth, Kuid, SIDm||SIDc||Rm||Rc||GUIDc||ROLEm||ULEN||USERNAME)
                                        // SIDm=console_id(init_sid), SIDc=bmc_id(managed_sid from Open Session Response)
                                        // NOTE: RAKP-M2 payload[4..7] echoes console_id, NOT bmc_id!
                                        {
                                            let padded_key = pad_key(password.as_bytes());
                                            let mut m2_hmac_input = Vec::new();
                                            m2_hmac_input.extend_from_slice(&init_sid.to_le_bytes());     // SIDm = console_id
                                            m2_hmac_input.extend_from_slice(&managed_sid.to_le_bytes()); // SIDc = bmc_id (from Open Session Response)
                                            m2_hmac_input.extend_from_slice(&random_a);                   // Rm = Random A
                                            m2_hmac_input.extend_from_slice(&random_b);                   // Rc = Random B
                                            m2_hmac_input.extend_from_slice(&guid);                       // GUIDc = BMC GUID
                                            m2_hmac_input.push(priv_byte);                                // ROLEm
                                            m2_hmac_input.push(username.len() as u8);                     // ULEN
                                            m2_hmac_input.extend_from_slice(username.as_bytes());         // USERNAME
                                            let expected_m2_hmac = hmac_fn(neg_auth, &padded_key, &m2_hmac_input);
                                            if keac == expected_m2_hmac {
                                                println!("  RAKP-M2 HMAC: VERIFIED ✓ ({} bytes)", keac.len());
                                            } else {
                                                println!("  RAKP-M2 HMAC: MISMATCH!");
                                                hex("  expected", &expected_m2_hmac);
                                            }
                                        }

                                        // Step 3: RAKP-M3
                                        // ICV = HMAC(auth, Kuid, Random_B || SIDm(console_id) || ROLEm || UsernameLen || UserName)
                                        // CRITICAL: RAKP ICV is FULL HMAC output (20 bytes for SHA1), NOT truncated to 12!
                                        {
                                            let padded_key = pad_key(password.as_bytes());
                                            let mut m3_icv_input = Vec::new();
                                            m3_icv_input.extend_from_slice(&random_b);
                                            m3_icv_input.extend_from_slice(&init_sid.to_le_bytes()); // SIDm = console_id
                                            m3_icv_input.push(priv_byte);
                                            m3_icv_input.push(username.len() as u8);
                                            m3_icv_input.extend_from_slice(username.as_bytes());
                                            let m3_full_icv = hmac_fn(neg_auth, &padded_key, &m3_icv_input);
                                            let icv_len = rakp_icv_len(neg_auth);
                                            println!("  M3 ICV length: {} bytes (rakp_icv_len={})", icv_len, icv_len);
                                            hex("  M3 expected ICV (full)", &m3_full_icv);
                                        }

                                        let m3 = build_rakp_m3(
                                            managed_sid, init_sid, &random_a, &random_b,
                                            &username, password.as_bytes(), neg_auth, neg_integ,
                                            priv_byte, // full privilege byte (including NameOnly bit per ipmitool requested_role)
                                        );
                                        hex("  REQ RAKP-M3", &m3);

                                        socket.send(&m3).await.unwrap();

                                        match tokio::time::timeout(Duration::from_secs(3), socket.recv(&mut buf)).await {
                                            Ok(Ok(n)) => {
                                                hex("  RSP RAKP-M4", &buf[..n]);

                                        // Derive SIK first (needed to verify RAKP-M4 ICV)
                                        let (sik, _k1_full, _k2_full) = derive_session_keys(
                                            neg_auth, password.as_bytes(),
                                            &random_a, &random_b,
                                            &username,
                                            priv_byte, // full privilege byte (including NameOnly bit per ipmitool requested_role)
                                        );
                                        hex("  SIK", &sik);

                                        // Debug: show M4 ICV verification inputs
                                        {
                                            let mut m4_verify = Vec::new();
                                            m4_verify.extend_from_slice(&random_a); // Random_A first
                                            m4_verify.extend_from_slice(&managed_sid.to_le_bytes()); // SIDc = BMC session ID from Open Session Response
                                            m4_verify.extend_from_slice(&guid);
                                            hex("  M4 ICV input (RA||SIDc||GUIDc)", &m4_verify);
                                            hex("  M4 ICV key (SIK)", &sik);
                                        }

                                        match parse_rakp_m4(&buf[..n], neg_auth, neg_integ, &sik, &random_a, managed_sid, &guid) {
                                            Ok(_icv) => {
                                                println!("\n  *** FULL RAKP HANDSHAKE SUCCEEDED! ***");
                                                println!("  Algorithm combo {} works!", name);

                                                // Derive session keys for post-session commands
                                                let k1 = {
                                                    let const1 = vec![0x01u8; 20];
                                                    hmac_fn(neg_auth, &sik, &const1)
                                                };
                                                let k2 = {
                                                    let const2 = vec![0x02u8; 20];
                                                    hmac_fn(neg_auth, &sik, &const2)
                                                };
                                                let ic_len = integrity_code_len(neg_integ);
                                                println!("  K1={}", hex_inline(&k1));
                                                println!("  K2={}", hex_inline(&k2));
                                                println!("  integ_code_len={}", ic_len);

                                                // Helper: build and send an IPMI command, return raw payload
                                                async fn send_ipmi_cmd(
                                                    socket: &UdpSocket,
                                                    session_id: u32,
                                                    session_seq: &mut u32,
                                                    ipmi_seq: &mut u8,
                                                    k1: &[u8],
                                                    k2: &[u8],
                                                    neg_auth: u8,
                                                    neg_integ: u8,
                                                    neg_confid: u8,
                                                    netfn: u8,
                                                    cmd: u8,
                                                    data: &[u8],
                                                ) -> Option<Vec<u8>> {
                                                    let seq_val = *session_seq;
                                                    let rqseq_lun: u8 = ((*ipmi_seq & 0x3F) << 2) as u8;
                                                    *session_seq = session_seq.wrapping_add(1);
                                                    *ipmi_seq = ipmi_seq.wrapping_add(1);

                                                    // Build IPMI message
                                                    let mut msg = Vec::new();
                                                    msg.push(0x20);          // rs_addr (BMC = responder/target)
                                                    msg.push((netfn << 2) | 0x00); // netfn | rs_lun
                                                    msg.push(checksum(&msg[0..2]));
                                                    msg.push(0x81);          // rq_addr = IPMI_REMOTE_SWID (system software address, per ipmitool)
                                                    msg.push(rqseq_lun);    // rq_seq | rq_lun
                                                    msg.push(cmd);
                                                    msg.extend_from_slice(data);
                                                    msg.push(checksum(&msg[3..]));

                                                    println!("  IPMI msg ({}b): {}", msg.len(), hex_str(&msg));
                                                    println!("  auth_type=0x{:02x} payload_type=0x{:02x} session_id=0x{:08x} seq={}", 
                                                        0x06u8,
                                                        {
                                                            let mut pt: u8 = 0x00;
                                                            if neg_integ != INTEG_NONE { pt |= 0x40; }
                                                            if neg_confid != CRYPT_NONE { pt |= 0x80; }
                                                            pt
                                                        },
                                                        session_id, seq_val);

                                                    let auth_type: u8 = 0x06; // ipmitool: "ipmi session Auth Type / Format is always 0x06 for IPMI v2"
                                                    // IPMI_MESSAGE (0x00) with auth/encryption flags per IPMI v2.0 spec:
                                                    // bit 7 = encrypted, bit 6 = authenticated
                                                    let mut payload_type: u8 = 0x00; // IPMI_MESSAGE base
                                                    if neg_integ != INTEG_NONE {
                                                        payload_type |= 0x40; // authenticated
                                                    }
                                                    if neg_confid != CRYPT_NONE {
                                                        payload_type |= 0x80; // encrypted
                                                    }
                                                    let ic_len = integrity_code_len(neg_integ);

                                                    let mut packet = Vec::new();
                                                    packet.extend_from_slice(&RMCP_HEADER);
                                                    packet.push(auth_type);
                                                    packet.push(payload_type);
                                                    packet.extend_from_slice(&session_id.to_le_bytes());
                                                    packet.extend_from_slice(&seq_val.to_le_bytes());

                                                    if neg_confid != CRYPT_NONE {
                                                        // AES-CBC-128 encrypted path
                                                        // ipmitool lanplus_encrypt_payload: encrypts RAW IPMI message directly
                                                        // NO inner integrity — just pad the raw message and encrypt with K2

                                                        // 1. IPMI pad (pad to 16-byte boundary with 0x01,0x02... + pad_length)
                                                        let padded = ipmi_pad(&msg);

                                                        // 2. Random 16-byte IV
                                                        let iv: Vec<u8> = {
                                                            let mut rng = rand::thread_rng();
                                                            (0..16).map(|_| rng.gen()).collect()
                                                        };

                                                        // 3. AES-CBC-128 encrypt with K2 (truncated to 16 bytes for AES-128)
                                                        let aes_key = &k2[..16];
                                                        let encrypted = aes_cbc_encrypt(aes_key, &iv, &padded);

                                                        // 4. msg_length = 16(IV) + encrypted.len()
                                                        let msg_length: u16 = (16 + encrypted.len()) as u16;

                                                        // 5. Outer integrity pad (align HMAC input to 4-byte boundary)
                                                        // HMAC input: header[14] + msg_length[2] + IV[16] + encrypted + pad + pad_length[1] + next_header[1]
                                                        // header[14] + msg_length[2] = 16; msg_length includes IV(16) + encrypted
                                                        // So: 16 + msg_length + pad + 2 must be multiple of 4
                                                        let enc_total = 16 + encrypted.len(); // = msg_length as usize
                                                        let outer_pad_count = (4 - ((16 + enc_total + 2) % 4)) % 4;
                                                        let outer_pad_bytes = vec![0xFFu8; outer_pad_count];

                                                        let mut outer_input = Vec::new();
                                                        outer_input.push(auth_type);
                                                        outer_input.push(payload_type);
                                                        outer_input.extend_from_slice(&session_id.to_le_bytes());
                                                        outer_input.extend_from_slice(&seq_val.to_le_bytes());
                                                        outer_input.extend_from_slice(&msg_length.to_le_bytes());
                                                        outer_input.extend_from_slice(&iv);
                                                        outer_input.extend_from_slice(&encrypted);
                                                        outer_input.extend_from_slice(&outer_pad_bytes);
                                                        outer_input.push(outer_pad_count as u8); // pad_length
                                                        outer_input.push(0x07);                     // next_header = IPMI
                                                        let outer_integrity = hmac_fn(neg_auth, k1, &outer_input);
                                                        let outer_trunc = &outer_integrity[..ic_len];

                                                        println!("  [AES ENCRYPTED PATH]");
                                                        println!("  raw IPMI msg ({}b): {}", msg.len(), hex_str(&msg));
                                                        println!("  padded ({}b): {}", padded.len(), hex_str(&padded));
                                                        println!("  IV: {}", hex_str(&iv));
                                                        println!("  encrypted ({}b): {}", encrypted.len(), hex_str(&encrypted));
                                                        println!("  msg_length: {} (IV + encrypted)", msg_length);
                                                        println!("  outer_integrity trunc ({}b): {}", ic_len, hex_str(outer_trunc));
                                                        println!("  outer_integrity pad: {} bytes", outer_pad_count);

                                                        packet.extend_from_slice(&msg_length.to_le_bytes());
                                                        packet.extend_from_slice(&iv);
                                                        packet.extend_from_slice(&encrypted);
                                                        packet.extend_from_slice(&outer_pad_bytes);
                                                        packet.push(outer_pad_count as u8);        // pad_length
                                                        packet.push(0x07);                          // next_header
                                                        packet.extend_from_slice(outer_trunc);
                                                    } else {
                                                        // Integrity-only path (confid=None)
                                                        // ipmitool: integrity pad ensures (header[14] + payload + pad + pad_length[1] + next_header[1]) is multiple of 4
                                                        let msg_length: u16 = msg.len() as u16;
                                                        let pad_count = (4 - ((14 + msg.len() + 2) % 4)) % 4;
                                                        let pad_bytes = vec![0xFFu8; pad_count];

                                                        let mut integrity_input = Vec::new();
                                                        integrity_input.push(auth_type);
                                                        integrity_input.push(payload_type);
                                                        integrity_input.extend_from_slice(&session_id.to_le_bytes());
                                                        integrity_input.extend_from_slice(&seq_val.to_le_bytes());
                                                        integrity_input.extend_from_slice(&msg_length.to_le_bytes());
                                                        integrity_input.extend_from_slice(&msg);
                                                        integrity_input.extend_from_slice(&pad_bytes);
                                                        integrity_input.push(pad_count as u8);   // pad_length
                                                        integrity_input.push(0x07);                // next_header = IPMI
                                                        let integrity = hmac_fn(neg_auth, k1, &integrity_input);
                                                        let integrity_trunc = &integrity[..ic_len];

                                                        println!("  HMAC key (K1): {}", hex_str(k1));
                                                        println!("  HMAC input ({}b): {}", integrity_input.len(), hex_str(&integrity_input));
                                                        println!("  HMAC full ({}b): {}", integrity.len(), hex_str(&integrity));
                                                        println!("  HMAC trunc ({}b): {}", integrity_trunc.len(), hex_str(integrity_trunc));
                                                        println!("  integrity pad: {} bytes (pad_count={})", pad_bytes.len(), pad_count);

                                                        packet.extend_from_slice(&msg_length.to_le_bytes());
                                                        packet.extend_from_slice(&msg);
                                                        packet.extend_from_slice(&pad_bytes);
                                                        packet.push(pad_count as u8);              // pad_length
                                                        packet.push(0x07);                          // next_header
                                                        packet.extend_from_slice(integrity_trunc);
                                                    }

                                                    hex("  REQ IPMI", &packet);
                                                    socket.send(&packet).await.ok()?;

                                                    let mut rbuf = vec![0u8; 4096];
                                                    match tokio::time::timeout(Duration::from_secs(3), socket.recv(&mut rbuf)).await {
                                                        Ok(Ok(n)) => {
                                                            hex("  RSP IPMI", &rbuf[..n]);

                                                            // payload_type (byte 5) carries encryption flags, NOT auth_type (byte 4)
                                                            let resp_payload_type = rbuf[5];
                                                            let resp_encrypted = (resp_payload_type & 0x80) != 0;

                                                            if resp_encrypted {
                                                                // Encrypted response
                                                                let resp_msg_len = u16::from_le_bytes([rbuf[14], rbuf[15]]) as usize;
                                                                if resp_msg_len < 16 || n < 16 + resp_msg_len + 2 + ic_len {
                                                                    println!("  Encrypted response too short: msg_len={} total={}", resp_msg_len, n);
                                                                    return None;
                                                                }
                                                                let iv = &rbuf[16..32];
                                                                let enc_data = &rbuf[32..16 + resp_msg_len];
                                                                // Auth code is at end of packet (after pad+pad_length+next_header)
                                                                let resp_ic = &rbuf[n - ic_len..n];

                                                                // Verify outer integrity: HMAC covers bytes[4..n-ic_len] (everything before auth code)
                                                                let mut verify_input = Vec::new();
                                                                verify_input.extend_from_slice(&rbuf[4..n - ic_len]);
                                                                let expected_ic = hmac_fn(neg_auth, k1, &verify_input);
                                                                let expected_ic_trunc = &expected_ic[..ic_len];

                                                                if resp_ic == expected_ic_trunc {
                                                                    println!("  Outer integrity: VERIFIED ✓");
                                                                } else {
                                                                    println!("  Outer integrity: MISMATCH!");
                                                                    hex("  expected", expected_ic_trunc);
                                                                    hex("  got", resp_ic);
                                                                    return None;
                                                                }

                                                                // Decrypt with K2 (truncated to 16 bytes for AES-128)
                                                                let aes_key = &k2[..16];
                                                                let decrypted = cbc_decrypt(aes_key, iv, enc_data);
                                                                println!("  Decrypted ({}b): {}", decrypted.len(), hex_str(&decrypted));

                                                                // Remove padding: last byte = pad_length, preceding pad_length bytes are pad (0x01, 0x02...)
                                                                // ipmitool lanplus_decrypt_payload: conf_pad_length = decrypted[bytes_decrypted - 1]
                                                                // payload_size = bytes_decrypted - conf_pad_length - 1
                                                                let pad_len = *decrypted.last().unwrap_or(&0) as usize;
                                                                let ipmi_response = &decrypted[..decrypted.len() - pad_len - 1];
                                                                println!("  IPMI response after decrypt ({}b): {}", ipmi_response.len(), hex_str(ipmi_response));
                                                                 if ipmi_response.len() >= 7 {
                                                                     let rs_netfn = ipmi_response[1];
                                                                     let completion = ipmi_response[6];
                                                                     println!("  IPMI rs_netfn=0x{:02x} completion=0x{:02x}", rs_netfn, completion);
                                                                     Some(ipmi_response[6..ipmi_response.len()-1].to_vec())
                                                                } else {
                                                                    println!("  IPMI payload too short: {} bytes", ipmi_response.len());
                                                                    None
                                                                }
                                                            } else {
                                                                // Integrity-only response (no encryption)
                                                                let resp_msg_len = u16::from_le_bytes([rbuf[14], rbuf[15]]) as usize;
                                                                let resp_data_start = 16;
                                                                let resp_data_end = resp_data_start + resp_msg_len;
                                                                let payload = &rbuf[resp_data_start..resp_data_end];
                                                                // Auth code is at end of packet (after pad+pad_length+next_header)
                                                                let resp_ic = &rbuf[n - ic_len..n];

                                                                // Verify: HMAC covers bytes[4..n-ic_len] (everything before auth code)
                                                                let mut verify_input = Vec::new();
                                                                verify_input.extend_from_slice(&rbuf[4..n - ic_len]);
                                                                let expected_ic = hmac_fn(neg_auth, k1, &verify_input);
                                                                let expected_ic_trunc = &expected_ic[..ic_len];

                                                                if resp_ic == expected_ic_trunc {
                                                                    println!("  Outer integrity: VERIFIED ✓");
                                                                } else {
                                                                    println!("  Outer integrity: MISMATCH!");
                                                                    hex("  expected", expected_ic_trunc);
                                                                    hex("  got", resp_ic);
                                                                    return None;
                                                                }

                                                                 if payload.len() >= 7 {
                                                                     let rs_netfn = payload[1];
                                                                     let completion = payload[6];
                                                                     println!("  IPMI rs_netfn=0x{:02x} completion=0x{:02x}", rs_netfn, completion);
                                                                     Some(payload[6..payload.len()-1].to_vec())
                                                                } else {
                                                                    println!("  IPMI payload too short: {} bytes", payload.len());
                                                                    None
                                                                }
                                                            }
                                                        }
                                                        Ok(Err(e)) => { println!("  recv err: {}", e); None }
                                                        Err(_) => { println!("  TIMEOUT"); None }
                                                    }
                                                }

                                                // Wait for BMC to activate session (some BMCs need this)
                                                println!("\n  Waiting 2000ms for session activation...");
                                                tokio::time::sleep(Duration::from_millis(2000)).await;

                                                let mut session_seq: u32 = 0;
                                                let mut ipmi_seq: u8 = 0;

                                                // Try multiple commands and channels
                                                // 1. Get Auth Capabilities on various channels
                                                let channels_to_try = [0x0E, 0x04, 0x00, 0x01, 0x08];
                                                for &ch in &channels_to_try {
                                                    println!("\n--- Get Auth Capabilities ch=0x{:02x} (0x06 0x38) ---", ch);
                                                    if let Some(data) = send_ipmi_cmd(
                                                        &socket, managed_sid, &mut session_seq, &mut ipmi_seq,
                                                        &k1, &k2, neg_auth, neg_integ, neg_confid,
                                                        0x06, 0x38, &[ch, 0x04],
                                                    ).await {
                                                        if data.len() >= 2 {
                                                            println!("  SUCCESS! Auth types: 0x{:02x}  Channel 0x{:02x} works!", data[1], ch);
                                                            break;
                                                        }
                                                    }
                                                }

                                                // 2. Get Device ID (simpler, no channel needed)
                                                println!("\n--- Get Device ID (0x06 0x01) ---");
                                                if let Some(data) = send_ipmi_cmd(
                                                    &socket, managed_sid, &mut session_seq, &mut ipmi_seq,
                                                    &k1, &k2, neg_auth, neg_integ, neg_confid,
                                                    0x06, 0x01, &[],
                                                ).await {
                                                    if data.len() >= 6 {
                                                        println!("  SUCCESS! Device ID: 0x{:02x}", data[0]);
                                                        println!("  Device Rev: 0x{:02x}", data[3]);
                                                        println!("  IPMI v{}.{}", data[4] >> 4, data[4] & 0x0F);
                                                    }
                                                }

                                                // 3. Get Channel Info (NetFn=App 0x06, Cmd=0x52)
                                                println!("\n--- Get Channel Info ch=0x0E (0x06 0x52) ---");
                                                if let Some(data) = send_ipmi_cmd(
                                                    &socket, managed_sid, &mut session_seq, &mut ipmi_seq,
                                                    &k1, &k2, neg_auth, neg_integ, neg_confid,
                                                    0x06, 0x52, &[0x0E],
                                                ).await {
                                                    println!("  Got {} bytes back", data.len());
                                                }

                                                // 4. Get Session Info (NetFn=App 0x06, Cmd 0x3D, data=[0x00])
                                                println!("\n--- Get Session Info (0x06 0x3D) ---");
                                                if let Some(data) = send_ipmi_cmd(
                                                    &socket, managed_sid, &mut session_seq, &mut ipmi_seq,
                                                    &k1, &k2, neg_auth, neg_integ, neg_confid,
                                                    0x06, 0x3D, &[0x00],
                                                ).await {
                                                    println!("  Got {} bytes back", data.len());
                                                }

                                                // 5. Close Session (NetFn=App 0x06, Cmd 0x3C)
                                                println!("\n--- Close Session (0x06 0x3C) ---");
                                                let mut close_data = Vec::new();
                                                close_data.extend_from_slice(&managed_sid.to_le_bytes());
                                                if let Some(data) = send_ipmi_cmd(
                                                    &socket, managed_sid, &mut session_seq, &mut ipmi_seq,
                                                    &k1, &k2, neg_auth, neg_integ, neg_confid,
                                                    0x06, 0x3C, &close_data,
                                                ).await {
                                                    println!("  Got {} bytes back", data.len());
                                                }

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
    } // for priv_level
    } // for combo

    println!("No algorithm combination succeeded.");
}
