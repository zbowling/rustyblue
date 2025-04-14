//! Unit tests for HCI packet parsing and serialization

use super::constants::*;
use super::packet::*;

#[test]
fn test_hci_command_serialization() {
    // Test Reset command
    let command = HciCommand::Reset;
    let packet = command.to_packet();

    assert_eq!(packet[0], HCI_COMMAND_PKT);

    // Opcode: Reset (0x0003)
    let opcode = u16::from_le_bytes([packet[1], packet[2]]);
    assert_eq!(opcode, 0x0C03); // OGF_HOST_CTL << 10 | OCF_RESET

    // Param length: 0
    assert_eq!(packet[3], 0);

    // Test LE Set Scan Parameters command
    let command = HciCommand::LeSetScanParameters {
        scan_type: 0x01,
        scan_interval: 0x0010,
        scan_window: 0x0010,
        own_address_type: 0x00,
        filter_policy: 0x00,
    };

    let packet = command.to_packet();

    assert_eq!(packet[0], HCI_COMMAND_PKT);

    // Opcode: LE Set Scan Parameters (0x000B)
    let opcode = u16::from_le_bytes([packet[1], packet[2]]);
    assert_eq!(opcode, 0x200B); // OGF_LE << 10 | OCF_LE_SET_SCAN_PARAMETERS

    // Param length: 7
    assert_eq!(packet[3], 7);

    // Parameters
    assert_eq!(packet[4], 0x01); // scan_type
    assert_eq!(u16::from_le_bytes([packet[5], packet[6]]), 0x0010); // scan_interval
    assert_eq!(u16::from_le_bytes([packet[7], packet[8]]), 0x0010); // scan_window
    assert_eq!(packet[9], 0x00); // own_address_type
    assert_eq!(packet[10], 0x00); // filter_policy

    // Test Disconnect command
    let command = HciCommand::Disconnect {
        handle: 0x0040,
        reason: 0x13,
    };

    let packet = command.to_packet();

    assert_eq!(packet[0], HCI_COMMAND_PKT);

    // Opcode: Disconnect (0x0006)
    let opcode = u16::from_le_bytes([packet[1], packet[2]]);
    assert_eq!(opcode, 0x0406); // OGF_LINK_CTL << 10 | OCF_DISCONNECT

    // Param length: 3
    assert_eq!(packet[3], 3);

    // Parameters
    assert_eq!(u16::from_le_bytes([packet[4], packet[5]]), 0x0040); // handle
    assert_eq!(packet[6], 0x13); // reason

    // Test Raw command
    let command = HciCommand::new(OGF_LE, OCF_LE_CREATE_CONNECTION, vec![0x01, 0x02, 0x03]);

    let packet = command.to_packet();

    assert_eq!(packet[0], HCI_COMMAND_PKT);

    // Opcode: LE Create Connection (0x000D)
    let opcode = u16::from_le_bytes([packet[1], packet[2]]);
    assert_eq!(opcode, 0x200D); // OGF_LE << 10 | OCF_LE_CREATE_CONNECTION

    // Param length: 3
    assert_eq!(packet[3], 3);

    // Parameters
    assert_eq!(packet[4], 0x01);
    assert_eq!(packet[5], 0x02);
    assert_eq!(packet[6], 0x03);
}

#[test]
fn test_hci_event_parsing() {
    // Create a simple Command Complete event
    let data = [
        EVT_CMD_COMPLETE, // Event code
        4,                // Parameter length
        1,                // Num_HCI_Command_Packets
        0x03,             // Command_Opcode (low byte)
        0x0C,             // Command_Opcode (high byte)
        0x00,             // Status
    ];

    let event = HciEvent::parse(&data).unwrap();

    assert_eq!(event.event_code, EVT_CMD_COMPLETE);
    assert_eq!(event.parameter_total_length, 4);
    assert_eq!(event.parameters, vec![1, 0x03, 0x0C, 0x00]);

    // Test is_command_complete method
    assert!(event.is_command_complete(OGF_HOST_CTL, OCF_RESET));
    assert!(!event.is_command_complete(OGF_LINK_CTL, OCF_DISCONNECT));

    // Test get_status method
    assert_eq!(event.get_status(), 0x00);

    // Create a simple LE Meta Event (Connection Complete)
    let data = [
        EVT_LE_META_EVENT,    // Event code
        19,                   // Parameter length
        EVT_LE_CONN_COMPLETE, // Subevent code
        0x00,                 // Status
        0x40,
        0x00, // Connection_Handle
        0x00, // Role
        0x00, // Peer_Address_Type
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06, // Peer_Address
        0x0A,
        0x00, // Conn_Interval
        0x00,
        0x00, // Conn_Latency
        0x80,
        0x0C, // Supervision_Timeout
        0x00, // Master_Clock_Accuracy
    ];

    let event = HciEvent::parse(&data).unwrap();

    assert_eq!(event.event_code, EVT_LE_META_EVENT);
    assert_eq!(event.parameter_total_length, 19);
    assert_eq!(event.parameters[0], EVT_LE_CONN_COMPLETE);

    // Invalid data tests
    assert!(HciEvent::parse(&[]).is_none()); // Empty data
    assert!(HciEvent::parse(&[EVT_CMD_COMPLETE, 10, 1, 2]).is_none()); // Too short for parameter length
}

#[test]
fn test_le_advertising_report_parsing() {
    // Create an LE Advertising Report event
    let data = [
        EVT_LE_META_EVENT,         // Event code
        16,                        // Parameter length
        EVT_LE_ADVERTISING_REPORT, // Subevent code
        1,                         // Num_Reports
        0,                         // Event_Type
        0,                         // Address_Type
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06, // Address
        3,    // Data_Length
        0x09,
        0x54,
        0x65, // Data (Type: Complete Local Name, Value: "Te")
        0xC3, // RSSI (-61 dBm)
    ];

    let event = HciEvent {
        event_code: EVT_LE_META_EVENT,
        parameter_total_length: 16,
        parameters: vec![
            EVT_LE_ADVERTISING_REPORT, // Subevent code
            1,                         // Num_Reports
            0,                         // Event_Type
            0,                         // Address_Type
            0x01,
            0x02,
            0x03,
            0x04,
            0x05,
            0x06, // Address
            3,    // Data_Length
            0x09,
            0x54,
            0x65, // Data
            0xC3, // RSSI
        ],
    };

    // Parse LE Advertising Report
    let reports = LeAdvertisingReport::parse_from_event(&event).unwrap();

    assert_eq!(reports.len(), 1);

    let report = &reports[0];
    assert_eq!(report.event_type, 0);
    assert_eq!(report.address_type, 0);
    assert_eq!(report.address, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
    assert_eq!(report.data_length, 3);
    assert_eq!(report.data, vec![0x09, 0x54, 0x65]);
    assert_eq!(report.rssi, -61);

    // Test invalid cases

    // Not an LE Meta event
    let invalid_event = HciEvent {
        event_code: EVT_CMD_COMPLETE,
        parameter_total_length: 4,
        parameters: vec![1, 0x03, 0x0C, 0x00],
    };

    let result = LeAdvertisingReport::parse_from_event(&invalid_event);
    assert!(result.is_err());

    // Not an Advertising Report subevent
    let invalid_event = HciEvent {
        event_code: EVT_LE_META_EVENT,
        parameter_total_length: 3,
        parameters: vec![EVT_LE_CONN_COMPLETE, 0x00, 0x00],
    };

    let result = LeAdvertisingReport::parse_from_event(&invalid_event);
    assert!(result.is_err());

    // No reports
    let invalid_event = HciEvent {
        event_code: EVT_LE_META_EVENT,
        parameter_total_length: 2,
        parameters: vec![EVT_LE_ADVERTISING_REPORT, 0],
    };

    let result = LeAdvertisingReport::parse_from_event(&invalid_event);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 0);
}

// Test GATT connection event parsing
#[test]
fn test_gatt_connection_event_parsing() {
    use crate::gatt::client::{DisconnectionComplete, LeConnectionComplete};

    // Create an LE Connection Complete event
    let data = [
        EVT_LE_META_EVENT,    // Event code
        19,                   // Parameter length
        EVT_LE_CONN_COMPLETE, // Subevent code
        0x00,                 // Status
        0x40,
        0x00, // Connection_Handle
        0x00, // Role
        0x00, // Peer_Address_Type
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06, // Peer_Address
        0x0A,
        0x00, // Conn_Interval
        0x00,
        0x00, // Conn_Latency
        0x80,
        0x0C, // Supervision_Timeout
        0x00, // Master_Clock_Accuracy
    ];

    let event = HciEvent::parse(&data).unwrap();

    // Parse LE Connection Complete
    let conn_complete = LeConnectionComplete::parse(&event).unwrap();

    assert_eq!(conn_complete.status, 0x00);
    assert_eq!(conn_complete.connection_handle, 0x0040);
    assert_eq!(conn_complete.role, 0x00);
    assert_eq!(conn_complete.peer_address_type, 0x00);
    assert_eq!(
        conn_complete.peer_address,
        [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]
    );
    assert_eq!(conn_complete.conn_interval, 0x000A);
    assert_eq!(conn_complete.conn_latency, 0x0000);
    assert_eq!(conn_complete.supervision_timeout, 0x0C80);
    assert_eq!(conn_complete.master_clock_accuracy, 0x00);

    // Create a Disconnection Complete event
    let data = [
        EVT_DISCONN_COMPLETE, // Event code
        4,                    // Parameter length
        0x00,                 // Status
        0x40,
        0x00, // Connection_Handle
        0x13, // Reason
    ];

    let event = HciEvent::parse(&data).unwrap();

    // Parse Disconnection Complete
    let disc_complete = DisconnectionComplete::parse(&event).unwrap();

    assert_eq!(disc_complete.status, 0x00);
    assert_eq!(disc_complete.connection_handle, 0x0040);
    assert_eq!(disc_complete.reason, 0x13);

    // Test invalid cases

    // Not an LE Meta event for connection complete
    let invalid_event = HciEvent {
        event_code: EVT_CMD_COMPLETE,
        parameter_total_length: 4,
        parameters: vec![1, 0x03, 0x0C, 0x00],
    };

    let result = LeConnectionComplete::parse(&invalid_event);
    assert!(result.is_none());

    // Not a disconnection complete event
    let invalid_event = HciEvent {
        event_code: EVT_CMD_COMPLETE,
        parameter_total_length: 4,
        parameters: vec![1, 0x03, 0x0C, 0x00],
    };

    let result = DisconnectionComplete::parse(&invalid_event);
    assert!(result.is_none());
}
