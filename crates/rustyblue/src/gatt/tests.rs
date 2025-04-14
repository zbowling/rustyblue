//! Unit tests for GATT functionality

use crate::gatt::client::{DisconnectionComplete, LeConnectionComplete};
use crate::hci::constants::*;
use crate::hci::{HciEvent, HciSocket};
use std::os::unix::io::RawFd;

/// Mock HCI socket for testing
struct MockHciSocket {
    fd: RawFd,
    queued_events: Vec<HciEvent>,
    next_event_index: usize,
}

impl MockHciSocket {
    fn new() -> Self {
        Self {
            fd: 999, // Dummy fd
            queued_events: Vec::new(),
            next_event_index: 0,
        }
    }

    fn queue_event(&mut self, event: HciEvent) {
        self.queued_events.push(event);
    }

    fn queue_connection_complete(&mut self, status: u8, handle: u16) {
        let mut params = vec![EVT_LE_CONN_COMPLETE, status];
        params.extend_from_slice(&handle.to_le_bytes());
        // Role (central)
        params.push(0x00);
        // Peer address type (public)
        params.push(0x00);
        // Peer address (00:11:22:33:44:55)
        params.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        // Connection interval (10 ms)
        params.extend_from_slice(&0x0008u16.to_le_bytes());
        // Connection latency
        params.extend_from_slice(&0x0000u16.to_le_bytes());
        // Supervision timeout
        params.extend_from_slice(&0x00C8u16.to_le_bytes());
        // Master clock accuracy
        params.push(0x00);

        self.queue_event(HciEvent {
            event_code: EVT_LE_META_EVENT,
            parameter_total_length: params.len() as u8,
            parameters: params,
        });
    }

    fn queue_disconnection_complete(&mut self, status: u8, handle: u16, reason: u8) {
        let mut params = vec![status];
        params.extend_from_slice(&handle.to_le_bytes());
        params.push(reason);

        self.queue_event(HciEvent {
            event_code: EVT_DISCONN_COMPLETE,
            parameter_total_length: params.len() as u8,
            parameters: params,
        });
    }

    fn queue_command_complete(&mut self, ogf: u8, ocf: u16, status: u8) {
        let opcode = ((ogf as u16) << 10) | (ocf & 0x3ff);
        let mut params = vec![1]; // Num_HCI_Command_Packets
        params.extend_from_slice(&opcode.to_le_bytes());
        params.push(status);

        self.queue_event(HciEvent {
            event_code: EVT_CMD_COMPLETE,
            parameter_total_length: params.len() as u8,
            parameters: params,
        });
    }

    fn queue_command_status(&mut self, status: u8, ogf: u8, ocf: u16) {
        let opcode = ((ogf as u16) << 10) | (ocf & 0x3ff);
        let mut params = vec![status, 1]; // Status, Num_HCI_Command_Packets
        params.extend_from_slice(&opcode.to_le_bytes());

        self.queue_event(HciEvent {
            event_code: EVT_CMD_STATUS,
            parameter_total_length: params.len() as u8,
            parameters: params,
        });
    }
}

// Implement necessary traits for the mock socket
impl std::os::unix::io::AsRawFd for MockHciSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

// Fake HciSocket trait to match what's expected by the GattClient
impl MockHciSocket {
    fn send_command(
        &self,
        _command: &crate::hci::HciCommand,
    ) -> Result<(), crate::error::HciError> {
        Ok(())
    }

    fn read_event(&mut self) -> Result<HciEvent, crate::error::HciError> {
        if self.next_event_index < self.queued_events.len() {
            let event = self.queued_events[self.next_event_index].clone();
            self.next_event_index += 1;
            Ok(event)
        } else {
            Err(crate::error::HciError::ReceiveError(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "No more events",
            )))
        }
    }

    fn read_event_timeout(
        &mut self,
        _timeout: Option<std::time::Duration>,
    ) -> Result<HciEvent, crate::error::HciError> {
        self.read_event()
    }
}

impl From<MockHciSocket> for HciSocket {
    fn from(_mock: MockHciSocket) -> Self {
        unreachable!("This is just a trick for the tests - not actually called");
    }
}

#[test]
fn test_le_connection_complete_parsing() {
    // Create a test event
    let mut params = vec![EVT_LE_CONN_COMPLETE, 0x00]; // Subevent code, Status
    params.extend_from_slice(&0x0040u16.to_le_bytes()); // Connection handle
    params.push(0x00); // Role
    params.push(0x00); // Peer address type
    params.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]); // Peer address
    params.extend_from_slice(&0x0010u16.to_le_bytes()); // Connection interval
    params.extend_from_slice(&0x0000u16.to_le_bytes()); // Connection latency
    params.extend_from_slice(&0x00C8u16.to_le_bytes()); // Supervision timeout
    params.push(0x00); // Master clock accuracy

    let event = HciEvent {
        event_code: EVT_LE_META_EVENT,
        parameter_total_length: params.len() as u8,
        parameters: params,
    };

    let conn_complete = LeConnectionComplete::parse(&event).unwrap();

    assert_eq!(conn_complete.status, 0x00);
    assert_eq!(conn_complete.connection_handle, 0x0040);
    assert_eq!(conn_complete.role, 0x00);
    assert_eq!(conn_complete.peer_address_type, 0x00);
    assert_eq!(
        conn_complete.peer_address,
        [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]
    );
    assert_eq!(conn_complete.conn_interval, 0x0010);
    assert_eq!(conn_complete.conn_latency, 0x0000);
    assert_eq!(conn_complete.supervision_timeout, 0x00C8);
    assert_eq!(conn_complete.master_clock_accuracy, 0x00);

    // Test invalid event (not a LE Meta event)
    let invalid_event = HciEvent {
        event_code: EVT_CMD_COMPLETE,
        parameter_total_length: 4,
        parameters: vec![1, 0, 0, 0],
    };

    assert!(LeConnectionComplete::parse(&invalid_event).is_none());

    // Test invalid event (wrong subevent)
    let mut params = vec![EVT_LE_ADVERTISING_REPORT]; // Wrong subevent code
    params.extend_from_slice(&[0; 18]); // Add dummy data to match required length

    let invalid_event = HciEvent {
        event_code: EVT_LE_META_EVENT,
        parameter_total_length: params.len() as u8,
        parameters: params,
    };

    assert!(LeConnectionComplete::parse(&invalid_event).is_none());

    // Test invalid event (too short)
    let params = vec![EVT_LE_CONN_COMPLETE, 0x00]; // Too short

    let invalid_event = HciEvent {
        event_code: EVT_LE_META_EVENT,
        parameter_total_length: params.len() as u8,
        parameters: params,
    };

    assert!(LeConnectionComplete::parse(&invalid_event).is_none());
}

#[test]
fn test_disconnection_complete_parsing() {
    // Create a test event
    let mut params = vec![0x00]; // Status
    params.extend_from_slice(&0x0040u16.to_le_bytes()); // Connection handle
    params.push(0x13); // Reason

    let event = HciEvent {
        event_code: EVT_DISCONN_COMPLETE,
        parameter_total_length: params.len() as u8,
        parameters: params,
    };

    let disc_complete = DisconnectionComplete::parse(&event).unwrap();

    assert_eq!(disc_complete.status, 0x00);
    assert_eq!(disc_complete.connection_handle, 0x0040);
    assert_eq!(disc_complete.reason, 0x13);

    // Test invalid event (not a Disconnection Complete event)
    let invalid_event = HciEvent {
        event_code: EVT_CMD_COMPLETE,
        parameter_total_length: 4,
        parameters: vec![1, 0, 0, 0],
    };

    assert!(DisconnectionComplete::parse(&invalid_event).is_none());

    // Test invalid event (too short)
    let params = vec![0x00]; // Too short

    let invalid_event = HciEvent {
        event_code: EVT_DISCONN_COMPLETE,
        parameter_total_length: params.len() as u8,
        parameters: params,
    };

    assert!(DisconnectionComplete::parse(&invalid_event).is_none());
}

// More tests can be added for GATT client functionality when it's more complete
