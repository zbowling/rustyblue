//! Protocol/Service Multiplexer (PSM) handling for L2CAP
//!
//! This module manages PSM values for L2CAP connections.

use std::sync::atomic::{AtomicU16, Ordering};
use std::fmt;

/// Protocol/Service Multiplexer (PSM) values used in L2CAP.
/// 
/// See Bluetooth Core Specification Vol 3, Part A, Section 4.
/// And assigned numbers: https://www.bluetooth.com/specifications/assigned-numbers/logical-link-control/
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum PSM {
    // Fixed PSM values for standard protocols
    /// Service Discovery Protocol
    SDP = 0x0001,
    /// RFCOMM protocol
    RFCOMM = 0x0003,
    /// Telephony Control Protocol
    TCS_BIN = 0x0005,
    /// TCS_BIN_CORDLESS
    TCS_BIN_CORDLESS = 0x0007,
    /// BNEP protocol
    BNEP = 0x000F,
    /// HID Control
    HID_CONTROL = 0x0011,
    /// HID Interrupt
    HID_INTERRUPT = 0x0013,
    /// UPnP protocol (ESDP)
    UPNP = 0x0015,
    /// AVCTP protocol
    AVCTP = 0x0017,
    /// AVDTP protocol
    AVDTP = 0x0019,
    /// AVCTP Browsing
    AVCTP_BROWSING = 0x001B,
    /// ATT protocol (fixed on LE only)
    ATT = 0x001F,
    /// 3DSP protocol
    _3DSP = 0x0021,
    
    // Dynamic PSM (assigned at runtime)
    /// Dynamically assigned PSM
    Dynamic(u16),
}

impl PSM {
    /// Check if the PSM is valid
    pub fn is_valid(&self) -> bool {
        match self {
            PSM::Dynamic(value) => {
                // Dynamic PSMs must be odd and in the valid range
                (*value % 2 == 1) && (*value >= 0x1001) && (*value <= 0xFFFF)
            },
            _ => true, // All fixed PSMs are valid
        }
    }
    
    /// Get the PSM value as u16
    pub fn value(&self) -> u16 {
        match self {
            PSM::SDP => 0x0001,
            PSM::RFCOMM => 0x0003,
            PSM::TCS_BIN => 0x0005,
            PSM::TCS_BIN_CORDLESS => 0x0007,
            PSM::BNEP => 0x000F,
            PSM::HID_CONTROL => 0x0011,
            PSM::HID_INTERRUPT => 0x0013,
            PSM::UPNP => 0x0015,
            PSM::AVCTP => 0x0017,
            PSM::AVDTP => 0x0019,
            PSM::AVCTP_BROWSING => 0x001B,
            PSM::ATT => 0x001F,
            PSM::_3DSP => 0x0021,
            PSM::Dynamic(value) => *value,
        }
    }
    
    /// Try to create a PSM from a u16 value
    pub fn from_value(value: u16) -> Option<Self> {
        match value {
            0x0001 => Some(PSM::SDP),
            0x0003 => Some(PSM::RFCOMM),
            0x0005 => Some(PSM::TCS_BIN),
            0x0007 => Some(PSM::TCS_BIN_CORDLESS),
            0x000F => Some(PSM::BNEP),
            0x0011 => Some(PSM::HID_CONTROL),
            0x0013 => Some(PSM::HID_INTERRUPT),
            0x0015 => Some(PSM::UPNP),
            0x0017 => Some(PSM::AVCTP),
            0x0019 => Some(PSM::AVDTP),
            0x001B => Some(PSM::AVCTP_BROWSING),
            0x001F => Some(PSM::ATT),
            0x0021 => Some(PSM::_3DSP),
            // Dynamic PSMs must be odd and in the dynamic range
            _ if value % 2 == 1 && value >= 0x1001 && value <= 0xFFFF => {
                Some(PSM::Dynamic(value))
            },
            _ => None,
        }
    }
}

impl fmt::Display for PSM {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PSM::SDP => write!(f, "SDP (0x0001)"),
            PSM::RFCOMM => write!(f, "RFCOMM (0x0003)"),
            PSM::TCS_BIN => write!(f, "TCS-BIN (0x0005)"),
            PSM::TCS_BIN_CORDLESS => write!(f, "TCS-BIN-CORDLESS (0x0007)"),
            PSM::BNEP => write!(f, "BNEP (0x000F)"),
            PSM::HID_CONTROL => write!(f, "HID-Control (0x0011)"),
            PSM::HID_INTERRUPT => write!(f, "HID-Interrupt (0x0013)"),
            PSM::UPNP => write!(f, "UPnP (0x0015)"),
            PSM::AVCTP => write!(f, "AVCTP (0x0017)"),
            PSM::AVDTP => write!(f, "AVDTP (0x0019)"),
            PSM::AVCTP_BROWSING => write!(f, "AVCTP-Browsing (0x001B)"),
            PSM::ATT => write!(f, "ATT (0x001F)"),
            PSM::_3DSP => write!(f, "3DSP (0x0021)"),
            PSM::Dynamic(value) => write!(f, "Dynamic PSM (0x{:04X})", value),
        }
    }
}

// Counter for dynamic PSM allocation
static NEXT_DYNAMIC_PSM: AtomicU16 = AtomicU16::new(0x1001);

/// Obtain a new dynamic PSM value
///
/// This function allocates a new dynamic PSM value that isn't currently in use.
/// Dynamic PSMs must be odd values in the range 0x1001-0xFFFF.
pub fn obtain_dynamic_psm() -> PSM {
    // Get the next PSM, ensuring it's odd
    let mut next_psm = NEXT_DYNAMIC_PSM.fetch_add(2, Ordering::SeqCst);
    
    // If we've wrapped around, reset to 0x1001
    if next_psm > 0xFFFF || next_psm < 0x1001 {
        next_psm = 0x1001;
        NEXT_DYNAMIC_PSM.store(0x1003, Ordering::SeqCst);
    }
    
    PSM::Dynamic(next_psm)
}