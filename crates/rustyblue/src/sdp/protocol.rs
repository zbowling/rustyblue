use crate::error::Error;
use crate::sdp::types::{DataElement, SdpPdu, Uuid};

pub struct SdpPacket {
    pub pdu_id: SdpPdu,
    pub transaction_id: u16,
    pub parameters_length: u16,
    pub parameters: Vec<u8>,
}

impl SdpPacket {
    pub fn new(pdu_id: SdpPdu, transaction_id: u16, parameters: Vec<u8>) -> Self {
        let parameters_length = parameters.len() as u16;
        Self {
            pdu_id,
            transaction_id,
            parameters_length,
            parameters,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(5 + self.parameters.len());
        buffer.push(self.pdu_id as u8);
        buffer.extend_from_slice(&self.transaction_id.to_be_bytes());
        buffer.extend_from_slice(&self.parameters_length.to_be_bytes());
        buffer.extend_from_slice(&self.parameters);
        buffer
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, Error> {
        if data.len() < 5 {
            return Err(Error::InvalidPacket("SDP packet too short".into()));
        }

        let pdu_id = match data[0] {
            0x01 => SdpPdu::ErrorResponse,
            0x02 => SdpPdu::ServiceSearchRequest,
            0x03 => SdpPdu::ServiceSearchResponse,
            0x04 => SdpPdu::ServiceAttributeRequest,
            0x05 => SdpPdu::ServiceAttributeResponse,
            0x06 => SdpPdu::ServiceSearchAttributeRequest,
            0x07 => SdpPdu::ServiceSearchAttributeResponse,
            _ => return Err(Error::InvalidPacket("Unknown SDP PDU ID".into())),
        };

        let transaction_id = u16::from_be_bytes([data[1], data[2]]);
        let parameters_length = u16::from_be_bytes([data[3], data[4]]);

        if data.len() < 5 + parameters_length as usize {
            return Err(Error::InvalidPacket("SDP packet too short for parameter length".into()));
        }

        let parameters = data[5..(5 + parameters_length as usize)].to_vec();

        Ok(Self {
            pdu_id,
            transaction_id,
            parameters_length,
            parameters,
        })
    }
}

pub fn encode_service_search_request(transaction_id: u16, uuids: &[Uuid], max_records: u16) -> Vec<u8> {
    let mut parameters = Vec::new();
    
    // Service UUID list
    let uuid_list_len = uuids.len() as u8;
    parameters.push(uuid_list_len);
    
    for uuid in uuids {
        encode_uuid(uuid, &mut parameters);
    }
    
    // Maximum service record count
    parameters.extend_from_slice(&max_records.to_be_bytes());
    
    // Continuation state (null for initial request)
    parameters.push(0);
    
    let packet = SdpPacket::new(SdpPdu::ServiceSearchRequest, transaction_id, parameters);
    packet.serialize()
}

fn encode_uuid(uuid: &Uuid, buffer: &mut Vec<u8>) {
    match uuid {
        Uuid::Uuid16(value) => {
            buffer.push(0x19); // Data element type 1, size 1 (2 bytes)
            buffer.extend_from_slice(&value.to_be_bytes());
        }
        Uuid::Uuid32(value) => {
            buffer.push(0x1A); // Data element type 1, size 2 (4 bytes)
            buffer.extend_from_slice(&value.to_be_bytes());
        }
        Uuid::Uuid128(value) => {
            buffer.push(0x1C); // Data element type 1, size 4 (16 bytes)
            buffer.extend_from_slice(value);
        }
    }
}

pub fn decode_data_element(data: &[u8], offset: &mut usize) -> Result<DataElement, Error> {
    if *offset >= data.len() {
        return Err(Error::InvalidPacket("Data element offset beyond data length".into()));
    }
    
    let header = data[*offset];
    *offset += 1;
    
    let element_type = (header >> 3) & 0x1F;
    let size_index = header & 0x07;
    
    match element_type {
        0 => Ok(DataElement::Nil), // Nil
        1 => { // Unsigned integer
            match size_index {
                0 => {
                    let value = data[*offset];
                    *offset += 1;
                    Ok(DataElement::Unsigned8(value))
                },
                1 => {
                    let value = u16::from_be_bytes([data[*offset], data[*offset + 1]]);
                    *offset += 2;
                    Ok(DataElement::Unsigned16(value))
                },
                2 => {
                    let value = u32::from_be_bytes([
                        data[*offset], data[*offset + 1], data[*offset + 2], data[*offset + 3]
                    ]);
                    *offset += 4;
                    Ok(DataElement::Unsigned32(value))
                },
                3 => {
                    let value = u64::from_be_bytes([
                        data[*offset], data[*offset + 1], data[*offset + 2], data[*offset + 3],
                        data[*offset + 4], data[*offset + 5], data[*offset + 6], data[*offset + 7]
                    ]);
                    *offset += 8;
                    Ok(DataElement::Unsigned64(value))
                },
                _ => Err(Error::InvalidPacket("Invalid size index for unsigned integer".into())),
            }
        },
        // Add other data element type handlers as needed
        // This is a simplified implementation
        _ => Err(Error::NotImplemented("Data element type not implemented".into())),
    }
}