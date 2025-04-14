//! Tests for the L2CAP implementation

#[cfg(test)]
mod tests {
    use super::super::channel::*;
    use super::super::constants::*;
    use super::super::core::*;
    use super::super::packet::*;
    use super::super::psm::*;
    use super::super::signaling::*;
    use super::super::types::*;
    use super::super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn test_psm_value_conversion() {
        // Test known PSM values
        assert_eq!(PSM::SDP.value(), 0x0001);
        assert_eq!(PSM::RFCOMM.value(), 0x0003);
        assert_eq!(PSM::ATT.value(), 0x001F);

        // Test dynamic PSM
        let dynamic_psm = PSM::Dynamic(0x1001);
        assert_eq!(dynamic_psm.value(), 0x1001);

        // Test PSM from value
        assert_eq!(PSM::from_value(0x0001), Some(PSM::SDP));
        assert_eq!(PSM::from_value(0x0003), Some(PSM::RFCOMM));
        assert_eq!(PSM::from_value(0x001F), Some(PSM::ATT));

        // Test dynamic PSM from value
        assert_eq!(PSM::from_value(0x1001), Some(PSM::Dynamic(0x1001)));

        // Test invalid PSM values (even values in dynamic range)
        assert_eq!(PSM::from_value(0x1002), None);

        // Test PSM validation
        assert!(PSM::SDP.is_valid());
        assert!(PSM::Dynamic(0x1001).is_valid());
        assert!(!PSM::Dynamic(0x0002).is_valid()); // Even value
        assert!(!PSM::Dynamic(0x0000).is_valid()); // Out of range
    }

    #[test]
    fn test_dynamic_psm_allocation() {
        // Get a dynamic PSM
        let psm1 = obtain_dynamic_psm();
        let psm2 = obtain_dynamic_psm();

        // Should be different values
        assert_ne!(psm1.value(), psm2.value());

        // Should be odd values in the dynamic range (0x1001-0xFFFF)
        assert!(psm1.value() >= 0x1001);
        assert!(psm1.value() <= 0xFFFF);
        assert_eq!(psm1.value() % 2, 1); // Odd value

        assert!(psm2.value() >= 0x1001);
        assert!(psm2.value() <= 0xFFFF);
        assert_eq!(psm2.value() % 2, 1); // Odd value
    }

    #[test]
    fn test_l2cap_header() {
        // Create a header
        let header = L2capHeader::new(10, 0x0040);

        // Check values
        assert_eq!(header.length, 10);
        assert_eq!(header.channel_id, 0x0040);

        // Serialize and parse
        let bytes = header.to_bytes();
        let parsed = L2capHeader::parse(&bytes).unwrap();

        // Check parsed values
        assert_eq!(parsed.length, 10);
        assert_eq!(parsed.channel_id, 0x0040);
    }

    #[test]
    fn test_l2cap_packet() {
        // Create a basic packet
        let data = vec![1, 2, 3, 4];
        let packet = L2capPacket::new(0x0040, data.clone());

        // Check values
        assert_eq!(packet.header.length, 4);
        assert_eq!(packet.header.channel_id, 0x0040);
        assert_eq!(packet.payload, data);
        assert!(packet.control.is_none());

        // Serialize and parse
        let bytes = packet.to_bytes();
        let parsed = L2capPacket::parse(&bytes).unwrap();

        // Check parsed values
        assert_eq!(parsed.header.length, 4);
        assert_eq!(parsed.header.channel_id, 0x0040);
        assert_eq!(parsed.payload, data);
        assert!(parsed.control.is_none());
    }

    #[test]
    fn test_l2cap_packet_with_control() {
        // Create a packet with control field
        let data = vec![1, 2, 3, 4];
        let control = L2capControlField::new_i_frame(5, 10, false, 0);
        let packet = L2capPacket::new_with_control(0x0040, control, data.clone());

        // Check values
        assert_eq!(packet.header.length, 6); // data (4) + control (2)
        assert_eq!(packet.header.channel_id, 0x0040);
        assert_eq!(packet.payload, data);
        assert!(packet.control.is_some());

        // Check control field
        let control = packet.control.unwrap();
        assert_eq!(control.frame_type, false); // I-frame
        assert_eq!(control.tx_seq, 5);
        assert_eq!(control.req_seq, 10);
        assert_eq!(control.poll, false);

        // Serialize and parse
        let bytes = packet.to_bytes();
        let parsed = L2capPacket::parse(&bytes).unwrap();

        // Check parsed values
        assert_eq!(parsed.header.length, 6);
        assert_eq!(parsed.header.channel_id, 0x0040);
        assert!(parsed.control.is_some());

        // Check parsed control field
        let parsed_control = parsed.control.unwrap();
        assert_eq!(parsed_control.frame_type, false); // I-frame
        assert_eq!(parsed_control.tx_seq, 5);
        assert_eq!(parsed_control.req_seq, 10);
        assert_eq!(parsed_control.poll, false);
    }

    #[test]
    fn test_signaling_message_connection_request() {
        // Create a connection request
        let request = SignalingMessage::ConnectionRequest {
            identifier: 1,
            psm: PSM::SDP,
            source_cid: 0x0040,
        };

        // Check command code
        assert_eq!(request.command_code(), L2CAP_CONNECTION_REQUEST);
        assert_eq!(request.identifier(), 1);

        // Serialize
        let bytes = request.serialize();

        // Parse
        let parsed = SignalingMessage::parse(&bytes, false).unwrap();

        // Check parsed values
        match parsed {
            SignalingMessage::ConnectionRequest {
                identifier,
                psm,
                source_cid,
            } => {
                assert_eq!(identifier, 1);
                assert_eq!(psm, PSM::SDP);
                assert_eq!(source_cid, 0x0040);
            }
            _ => panic!("Expected ConnectionRequest, got {:?}", parsed),
        }
    }

    #[test]
    fn test_signaling_message_config_request() {
        // Create a config request
        let mut options = ConfigOptions::default();
        options.mtu = Some(128);

        let request = SignalingMessage::ConfigureRequest {
            identifier: 2,
            destination_cid: 0x0041,
            flags: 0,
            options: options.clone(),
        };

        // Check command code
        assert_eq!(request.command_code(), L2CAP_CONFIGURE_REQUEST);
        assert_eq!(request.identifier(), 2);

        // Serialize
        let bytes = request.serialize();

        // Parse
        let parsed = SignalingMessage::parse(&bytes, false).unwrap();

        // Check parsed values
        match parsed {
            SignalingMessage::ConfigureRequest {
                identifier,
                destination_cid,
                flags,
                options: parsed_options,
            } => {
                assert_eq!(identifier, 2);
                assert_eq!(destination_cid, 0x0041);
                assert_eq!(flags, 0);
                assert_eq!(parsed_options.mtu, Some(128));
            }
            _ => panic!("Expected ConfigureRequest, got {:?}", parsed),
        }
    }

    #[test]
    fn test_l2cap_channel() {
        // Create a channel
        let mut channel = L2capChannel::new(
            0x0040,
            L2capChannelType::ConnectionOriented,
            ConnectionType::Classic,
        );

        // Check initial values
        assert_eq!(channel.local_cid(), 0x0040);
        assert_eq!(channel.remote_cid(), 0);
        assert_eq!(channel.state(), L2capChannelState::Closed);
        assert_eq!(channel.channel_type(), L2capChannelType::ConnectionOriented);

        // Update channel
        channel.set_remote_cid(0x0041);
        channel.set_state(L2capChannelState::Open);

        // Check updated values
        assert_eq!(channel.remote_cid(), 0x0041);
        assert_eq!(channel.state(), L2capChannelState::Open);

        // Test MTU handling
        assert_eq!(channel.mtu(), L2CAP_DEFAULT_MTU);
        channel.set_remote_mtu(128);
        assert_eq!(channel.remote_mtu(), 128);
        assert_eq!(channel.effective_mtu(), 128); // Min of local and remote
    }

    #[test]
    fn test_l2cap_manager() {
        // Create a manager
        let manager = L2capManager::new(ConnectionType::Classic);

        // Register a PSM
        let data_callback = Arc::new(Mutex::new(|_data: &[u8]| -> L2capResult<()> { Ok(()) }));

        let event_callback = Arc::new(Mutex::new(|_event: ChannelEvent| -> L2capResult<()> {
            Ok(())
        }));

        let policy = ConnectionPolicy {
            min_security_level: SecurityLevel::None,
            authorization_required: false,
            auto_accept: true,
        };

        // Register PSM
        let result = manager.register_psm(
            PSM::RFCOMM,
            Some(data_callback),
            Some(event_callback),
            policy,
        );
        assert!(result.is_ok());

        // Test PSM registration fails for duplicate
        let data_callback2 = Arc::new(Mutex::new(|_data: &[u8]| -> L2capResult<()> { Ok(()) }));

        let result = manager.register_psm(PSM::RFCOMM, Some(data_callback2), None, policy);
        assert!(result.is_err());

        // Unregister PSM
        let result = manager.unregister_psm(PSM::RFCOMM);
        assert!(result.is_ok());

        // Try to unregister again
        let result = manager.unregister_psm(PSM::RFCOMM);
        assert!(result.is_err());
    }

    // Create a mock connection for testing L2CAP manager
    struct MockConnection {
        local_cid: u16,
        remote_cid: u16,
        psm: PSM,
    }

    impl MockConnection {
        fn new(manager: &L2capManager, psm: PSM) -> L2capResult<Self> {
            // Register PSM
            let data_callback = Arc::new(Mutex::new(|_data: &[u8]| -> L2capResult<()> { Ok(()) }));

            let policy = ConnectionPolicy {
                min_security_level: SecurityLevel::None,
                authorization_required: false,
                auto_accept: true,
            };

            manager.register_psm(psm, Some(data_callback), None, policy)?;

            // Create channels directly
            let local_cid = manager.connect(psm, 0x0001)?;

            // Mock remote CID
            let remote_cid = 0x0041;

            // Manually set the remote CID (in a real scenario, this would come from the response)
            {
                let mut channels = manager.channels.write().unwrap();
                if let Some(channel) = channels.get_mut(&local_cid) {
                    channel.set_remote_cid(remote_cid);
                    channel.set_state(L2capChannelState::Open);
                }
            }

            Ok(Self {
                local_cid,
                remote_cid,
                psm,
            })
        }
    }

    #[test]
    fn test_l2cap_integration() {
        // Create a manager
        let manager = L2capManager::new(ConnectionType::Classic);

        // Create a mock connection
        let conn = MockConnection::new(&manager, PSM::RFCOMM);
        assert!(conn.is_ok());
        let conn = conn.unwrap();

        // Check channel state
        {
            let channels = manager.channels.read().unwrap();
            let channel = channels.get(&conn.local_cid).unwrap();
            assert_eq!(channel.state(), L2capChannelState::Open);
            assert_eq!(channel.remote_cid(), conn.remote_cid);
            assert_eq!(channel.psm(), Some(conn.psm));
        }

        // Create a data packet
        let data = vec![1, 2, 3, 4];
        let result = manager.send_data(conn.local_cid, &data);
        assert!(result.is_ok());

        // Test disconnect
        let result = manager.disconnect(conn.local_cid);
        assert!(result.is_ok());

        // Channel should be removed
        {
            let channels = manager.channels.read().unwrap();
            assert!(!channels.contains_key(&conn.local_cid));
        }
    }
}
