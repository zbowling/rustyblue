use crate::error::Error;
use crate::sdp::protocol::SdpPacket;
use crate::sdp::types::{ServiceRecord, SdpPdu, Uuid, DataElement};
use std::collections::HashMap;

pub struct SdpServer {
    service_records: HashMap<u32, ServiceRecord>,
    next_handle: u32,
}

impl SdpServer {
    pub fn new() -> Self {
        Self {
            service_records: HashMap::new(),
            next_handle: 0x10000, // Start handles at this value
        }
    }

    pub fn register_service(&mut self, service: ServiceRecord) -> u32 {
        let handle = self.next_handle;
        self.next_handle += 1;
        
        self.service_records.insert(handle, service);
        handle
    }

    pub fn unregister_service(&mut self, handle: u32) -> bool {
        self.service_records.remove(&handle).is_some()
    }

    pub fn handle_request(&self, request: &SdpPacket) -> Result<SdpPacket, Error> {
        match request.pdu_id {
            SdpPdu::ServiceSearchRequest => self.handle_service_search(request),
            SdpPdu::ServiceAttributeRequest => self.handle_service_attribute(request),
            SdpPdu::ServiceSearchAttributeRequest => self.handle_service_search_attribute(request),
            _ => Err(Error::InvalidPacket("Unsupported SDP PDU type".into())),
        }
    }

    fn handle_service_search(&self, request: &SdpPacket) -> Result<SdpPacket, Error> {
        // TODO: Implement service search handler
        // Parse UUIDs from request, look up matching services, send handles back
        
        // Placeholder response
        let parameters = vec![0, 0, 0, 0, 0]; // Empty response with zeros
        Ok(SdpPacket::new(SdpPdu::ServiceSearchResponse, request.transaction_id, parameters))
    }

    fn handle_service_attribute(&self, request: &SdpPacket) -> Result<SdpPacket, Error> {
        // TODO: Implement service attribute handler
        // Parse service handle and attribute IDs, return requested attributes
        
        // Placeholder response
        let parameters = vec![0, 0, 0]; // Empty response with zeros
        Ok(SdpPacket::new(SdpPdu::ServiceAttributeResponse, request.transaction_id, parameters))
    }

    fn handle_service_search_attribute(&self, request: &SdpPacket) -> Result<SdpPacket, Error> {
        // TODO: Implement service search attribute handler
        // Parse UUIDs and attribute IDs, find matching services, return attributes
        
        // Placeholder response
        let parameters = vec![0, 0, 0]; // Empty response with zeros
        Ok(SdpPacket::new(SdpPdu::ServiceSearchAttributeResponse, request.transaction_id, parameters))
    }

    fn find_matching_services(&self, uuids: &[Uuid]) -> Vec<u32> {
        let mut matching_handles = Vec::new();
        
        for (handle, record) in &self.service_records {
            let mut matches = true;
            
            for uuid in uuids {
                if !record.service_class_id_list.contains(uuid) {
                    matches = false;
                    break;
                }
            }
            
            if matches {
                matching_handles.push(*handle);
            }
        }
        
        matching_handles
    }
}