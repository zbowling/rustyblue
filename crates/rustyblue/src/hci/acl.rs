//! HCI ACL data packet handling
//!
//! This module defines structures and helpers for working with HCI ACL packets.

use crate::hci::constants::HCI_ACL_PKT;

/// HCI ACL data packet
#[derive(Debug, Clone)]
pub struct HciAcl {
    /// Connection handle and flags
    pub handle: u16,
    /// Packet boundary flag
    pub pb_flag: u8,
    /// Broadcast flag
    pub bc_flag: u8,
    /// Payload
    pub data: Vec<u8>,
}

impl HciAcl {
    /// Create a new ACL packet
    pub fn new(handle: u16, pb_flag: u8, bc_flag: u8, data: Vec<u8>) -> Self {
        Self {
            handle,
            pb_flag,
            bc_flag,
            data,
        }
    }

    /// Convert the ACL packet to raw bytes suitable for transmission
    pub fn to_bytes(&self) -> Vec<u8> {
        let handle_flags = self.handle | ((self.pb_flag as u16) << 12) | ((self.bc_flag as u16) << 14);
        let mut out = Vec::with_capacity(self.data.len() + 5);
        out.push(HCI_ACL_PKT);
        out.extend_from_slice(&handle_flags.to_le_bytes());
        out.extend_from_slice(&(self.data.len() as u16).to_le_bytes());
        out.extend_from_slice(&self.data);
        out
    }

    /// Parse an ACL packet from raw bytes (without packet type)
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }
        let handle_flags = u16::from_le_bytes([data[0], data[1]]);
        let handle = handle_flags & 0x0FFF;
        let pb_flag = ((handle_flags >> 12) & 0x03) as u8;
        let bc_flag = ((handle_flags >> 14) & 0x03) as u8;
        let data_len = u16::from_le_bytes([data[2], data[3]]) as usize;
        if data.len() < 4 + data_len {
            return None;
        }
        let payload = data[4..4 + data_len].to_vec();
        Some(Self {
            handle,
            pb_flag,
            bc_flag,
            data: payload,
        })
    }
}

