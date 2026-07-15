use super::{IpmiClient, IpmiError, IpmiResult};
use std::sync::Arc;
use tokio::net::UdpSocket;

pub struct SolSession {
    pub active: bool,
    pub socket: Arc<UdpSocket>,
    pub session_id: u32,
}

impl SolSession {
    pub fn new(socket: Arc<UdpSocket>, session_id: u32) -> Self {
        Self {
            active: true,
            socket,
            session_id,
        }
    }
}

pub async fn activate_sol(client: &mut IpmiClient) -> IpmiResult<()> {
    let data = vec![
        0x00, // session update
        0x01, // SOL activating
        0x00, 0x00, 0x00, 0x00, // shared aux
    ];

    client.send_ipmi_command(0x0c, 0x20, &data).await?;
    Ok(())
}

pub async fn deactivate_sol(client: &mut IpmiClient) -> IpmiResult<()> {
    let data = vec![
        0x00,
        0x00, // SOL deactivating
        0x00, 0x00, 0x00, 0x00,
    ];

    client.send_ipmi_command(0x0c, 0x21, &data).await?;
    Ok(())
}

pub async fn send_sol_input(client: &mut IpmiClient, input: &[u8]) -> IpmiResult<()> {
    if input.is_empty() {
        return Ok(());
    }

    let mut data = Vec::new();
    data.push(0x00);
    data.push(0x01);

    let seq = client.get_session_mut()
        .ok_or(IpmiError::Session("No session".into()))?
        .seq_number
        .to_le_bytes();
    data.extend_from_slice(&seq);

    data.push(input.len() as u8);
    data.extend_from_slice(input);

    let pad_len = if data.len() % 16 != 0 {
        16 - (data.len() % 16)
    } else {
        0
    };
    data.extend(std::iter::repeat(0xff).take(pad_len));

    client.send_ipmi_command(0x0c, 0x22, &data).await?;
    Ok(())
}

pub fn decode_sol_payload(data: &[u8]) -> IpmiResult<Vec<u8>> {
    if data.len() < 10 {
        return Err(IpmiError::Protocol("SOL payload too short".into()));
    }

    let _sequence = u32::from_le_bytes([data[2], data[3], data[4], data[5]]);
    let _acked_chars = data[6];
    let data_len = data[7] as usize;

    let start = 8;
    let end = std::cmp::min(start + data_len, data.len());
    Ok(data[start..end].to_vec())
}
