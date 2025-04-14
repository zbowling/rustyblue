//! L2CAP Packet handling
//!
//! This module provides structures and functions for handling L2CAP packets.

use super::constants::*;
use super::types::*;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::convert::TryFrom;
use std::io::{Cursor, Read, Write};

/// L2CAP Packet header
#[derive(Debug, Clone, Copy)]
pub struct L2capHeader {
    /// Length of the L2CAP payload in bytes
    pub length: u16,
    /// Channel Identifier
    pub channel_id: u16,
}

impl L2capHeader {
    /// Create a new L2CAP header
    pub fn new(length: u16, channel_id: u16) -> Self {
        Self { length, channel_id }
    }

    /// Parse an L2CAP header from raw bytes
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < L2CAP_BASIC_HEADER_SIZE {
            return None;
        }

        let mut cursor = Cursor::new(data);
        let length = cursor.read_u16::<LittleEndian>().ok()?;
        let channel_id = cursor.read_u16::<LittleEndian>().ok()?;

        Some(Self { length, channel_id })
    }

    /// Serialize the header to bytes
    pub fn to_bytes(&self) -> [u8; L2CAP_BASIC_HEADER_SIZE] {
        let mut result = [0u8; L2CAP_BASIC_HEADER_SIZE];
        let mut cursor = Cursor::new(&mut result[..]);

        cursor.write_u16::<LittleEndian>(self.length).unwrap();
        cursor.write_u16::<LittleEndian>(self.channel_id).unwrap();

        result
    }
}

/// L2CAP Control frame for enhanced retransmission/streaming modes
#[derive(Debug, Clone, Copy)]
pub struct L2capControlField {
    /// Frame type (0 = I-frame, 1 = S-frame)
    pub frame_type: bool,
    /// TxSeq number (I-frames only)
    pub tx_seq: u8,
    /// Segmentation and Reassembly bits
    pub sar: u8,
    /// Supervisory function (S-frames only)
    pub supervisory_function: u8,
    /// Poll bit
    pub poll: bool,
    /// Final bit
    pub final_bit: bool,
    /// ReqSeq number (Acknowledge messages up to this sequence)
    pub req_seq: u8,
}

impl L2capControlField {
    /// Create a new control field for an Information frame (I-frame)
    pub fn new_i_frame(tx_seq: u8, req_seq: u8, poll: bool, sar: u8) -> Self {
        Self {
            frame_type: false, // I-frame
            tx_seq,
            sar,
            supervisory_function: 0, // Not used for I-frames
            poll,
            final_bit: false, // Not used for I-frames
            req_seq,
        }
    }

    /// Create a new control field for a Supervisory frame (S-frame)
    pub fn new_s_frame(supervisory_function: u8, req_seq: u8, final_bit: bool) -> Self {
        Self {
            frame_type: true, // S-frame
            tx_seq: 0,        // Not used for S-frames
            sar: 0,           // Not used for S-frames
            supervisory_function,
            poll: false, // Not used for S-frames
            final_bit,
            req_seq,
        }
    }

    /// Parse the control field from raw bytes
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 2 {
            return None;
        }

        let mut cursor = Cursor::new(data);
        let control = cursor.read_u16::<LittleEndian>().ok()?;

        let frame_type = (control & L2CAP_CTRL_FRAME_TYPE_MASK) != 0;

        let supervisory_function = if frame_type {
            ((control & L2CAP_CTRL_SUPERVISORY_MASK) >> 2) as u8
        } else {
            0
        };

        let tx_seq = if !frame_type {
            ((control & L2CAP_CTRL_TXSEQ_MASK) >> L2CAP_CTRL_TXSEQ_SHIFT) as u8
        } else {
            0
        };

        let req_seq = ((control & L2CAP_CTRL_REQSEQ_MASK) >> L2CAP_CTRL_REQSEQ_SHIFT) as u8;

        let poll_final = (control & L2CAP_CTRL_POLL) != 0;

        let sar = if !frame_type {
            ((control & L2CAP_CTRL_SAR_MASK) >> L2CAP_CTRL_SAR_SHIFT) as u8
        } else {
            0
        };

        Some(Self {
            frame_type,
            tx_seq,
            sar,
            supervisory_function,
            poll: poll_final && !frame_type,
            final_bit: poll_final && frame_type,
            req_seq,
        })
    }

    /// Convert the control field to a u16 value
    pub fn to_u16(&self) -> u16 {
        let mut control: u16 = 0;

        if self.frame_type {
            control |= L2CAP_CTRL_FRAME_TYPE_MASK;
            control |= (self.supervisory_function as u16) << 2;

            if self.final_bit {
                control |= L2CAP_CTRL_FINAL;
            }
        } else {
            control |= (self.tx_seq as u16) << L2CAP_CTRL_TXSEQ_SHIFT;
            control |= (self.sar as u16) << L2CAP_CTRL_SAR_SHIFT;

            if self.poll {
                control |= L2CAP_CTRL_POLL;
            }
        }

        control |= (self.req_seq as u16) << L2CAP_CTRL_REQSEQ_SHIFT;

        control
    }

    /// Serialize the control field to bytes
    pub fn to_bytes(&self) -> [u8; 2] {
        let control = self.to_u16();
        let mut result = [0u8; 2];
        let mut cursor = Cursor::new(&mut result[..]);

        cursor.write_u16::<LittleEndian>(control).unwrap();

        result
    }
}

/// Represents a full L2CAP packet with header and payload
#[derive(Debug, Clone)]
pub struct L2capPacket {
    /// L2CAP header
    pub header: L2capHeader,
    /// Optional control field for retransmission/streaming modes
    pub control: Option<L2capControlField>,
    /// Payload data
    pub payload: Vec<u8>,
}

impl L2capPacket {
    /// Create a new L2CAP packet
    pub fn new(channel_id: u16, payload: Vec<u8>) -> Self {
        let length = payload.len() as u16;

        Self {
            header: L2capHeader::new(length, channel_id),
            control: None,
            payload,
        }
    }

    /// Create a new L2CAP packet with control field
    pub fn new_with_control(channel_id: u16, control: L2capControlField, payload: Vec<u8>) -> Self {
        let length = (payload.len() + 2) as u16; // +2 for control field

        Self {
            header: L2capHeader::new(length, channel_id),
            control: Some(control),
            payload,
        }
    }

    /// Parse an L2CAP packet from raw bytes
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < L2CAP_BASIC_HEADER_SIZE {
            return None;
        }

        let header = L2capHeader::parse(data)?;

        // Make sure we have enough data for the payload
        if data.len() < L2CAP_BASIC_HEADER_SIZE + header.length as usize {
            return None;
        }

        // Check if this might be a packet with control field
        let (control, payload_start) = if header.channel_id > L2CAP_ATTRIBUTE_PROTOCOL_CID {
            // Try to parse control field for dynamic channels
            let control_data = &data[L2CAP_BASIC_HEADER_SIZE..L2CAP_BASIC_HEADER_SIZE + 2];
            if let Some(control) = L2capControlField::parse(control_data) {
                (Some(control), L2CAP_BASIC_HEADER_SIZE + 2)
            } else {
                (None, L2CAP_BASIC_HEADER_SIZE)
            }
        } else {
            // Fixed channels don't use control field
            (None, L2CAP_BASIC_HEADER_SIZE)
        };

        // Extract payload
        let payload_end = L2CAP_BASIC_HEADER_SIZE + header.length as usize;
        let payload = data[payload_start..payload_end].to_vec();

        Some(Self {
            header,
            control,
            payload,
        })
    }

    /// Serialize the L2CAP packet to a byte vector
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(L2CAP_BASIC_HEADER_SIZE + self.header.length as usize);

        // Add header
        result.extend_from_slice(&self.header.to_bytes());

        // Add control field if present
        if let Some(control) = self.control {
            result.extend_from_slice(&control.to_bytes());
        }

        // Add payload
        result.extend_from_slice(&self.payload);

        result
    }

    /// Get the full size of the packet in bytes
    pub fn size(&self) -> usize {
        L2CAP_BASIC_HEADER_SIZE + self.header.length as usize
    }
}

/// L2CAP Command header used in signaling packets
#[derive(Debug, Clone, Copy)]
pub struct L2capCommandHeader {
    /// Command code
    pub code: u8,
    /// Command identifier
    pub identifier: u8,
    /// Length of command parameters
    pub length: u16,
}

impl L2capCommandHeader {
    /// Create a new command header
    pub fn new(code: u8, identifier: u8, length: u16) -> Self {
        Self {
            code,
            identifier,
            length,
        }
    }

    /// Parse a command header from raw bytes
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }

        let code = data[0];
        let identifier = data[1];

        let mut cursor = Cursor::new(&data[2..4]);
        let length = cursor.read_u16::<LittleEndian>().ok()?;

        Some(Self {
            code,
            identifier,
            length,
        })
    }

    /// Serialize the command header to bytes
    pub fn to_bytes(&self) -> [u8; 4] {
        let mut result = [0u8; 4];

        result[0] = self.code;
        result[1] = self.identifier;

        let mut cursor = Cursor::new(&mut result[2..4]);
        cursor.write_u16::<LittleEndian>(self.length).unwrap();

        result
    }
}

/// L2CAP Connection Request parameters
#[derive(Debug, Clone, Copy)]
pub struct ConnectionRequestParams {
    /// Protocol/Service Multiplexer (PSM)
    pub psm: u16,
    /// Source Channel Identifier (SCID)
    pub scid: u16,
}

impl TryFrom<&[u8]> for ConnectionRequestParams {
    type Error = L2capError;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        if data.len() < 4 {
            return Err(L2capError::InvalidParameter(
                "Connection request parameters too short".into(),
            ));
        }

        let mut cursor = Cursor::new(data);
        let psm = cursor
            .read_u16::<LittleEndian>()
            .map_err(|_| L2capError::InvalidParameter("Failed to read PSM".into()))?;

        let scid = cursor
            .read_u16::<LittleEndian>()
            .map_err(|_| L2capError::InvalidParameter("Failed to read SCID".into()))?;

        Ok(Self { psm, scid })
    }
}

impl ConnectionRequestParams {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> [u8; 4] {
        let mut result = [0u8; 4];
        let mut cursor = Cursor::new(&mut result[..]);

        cursor.write_u16::<LittleEndian>(self.psm).unwrap();
        cursor.write_u16::<LittleEndian>(self.scid).unwrap();

        result
    }
}

/// L2CAP Connection Response parameters
#[derive(Debug, Clone, Copy)]
pub struct ConnectionResponseParams {
    /// Destination Channel Identifier (DCID)
    pub dcid: u16,
    /// Source Channel Identifier (SCID)
    pub scid: u16,
    /// Result (0 = success, non-zero = failure)
    pub result: u16,
    /// Status (only meaningful when result = pending)
    pub status: u16,
}

impl TryFrom<&[u8]> for ConnectionResponseParams {
    type Error = L2capError;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        if data.len() < 8 {
            return Err(L2capError::InvalidParameter(
                "Connection response parameters too short".into(),
            ));
        }

        let mut cursor = Cursor::new(data);
        let dcid = cursor
            .read_u16::<LittleEndian>()
            .map_err(|_| L2capError::InvalidParameter("Failed to read DCID".into()))?;

        let scid = cursor
            .read_u16::<LittleEndian>()
            .map_err(|_| L2capError::InvalidParameter("Failed to read SCID".into()))?;

        let result = cursor
            .read_u16::<LittleEndian>()
            .map_err(|_| L2capError::InvalidParameter("Failed to read result".into()))?;

        let status = cursor
            .read_u16::<LittleEndian>()
            .map_err(|_| L2capError::InvalidParameter("Failed to read status".into()))?;

        Ok(Self {
            dcid,
            scid,
            result,
            status,
        })
    }
}

impl ConnectionResponseParams {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> [u8; 8] {
        let mut result = [0u8; 8];
        let mut cursor = Cursor::new(&mut result[..]);

        cursor.write_u16::<LittleEndian>(self.dcid).unwrap();
        cursor.write_u16::<LittleEndian>(self.scid).unwrap();
        cursor.write_u16::<LittleEndian>(self.result).unwrap();
        cursor.write_u16::<LittleEndian>(self.status).unwrap();

        result
    }
}
