//! Protocol/Service Multiplexer (PSM) handling for L2CAP
//!
//! This module manages PSM values for L2CAP connections.

use std::fmt;
use std::sync::atomic::{AtomicU16, Ordering};

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
    /// Telephony Control Specification
    TcsBin = 0x0005,
    /// TCS-BIN-based cordless telephony
    TcsBinCordless = 0x0007,
    /// BNEP (used for PAN)
    BNEP = 0x000F,
    /// Human Interface Device
    HidControl = 0x0011,
    /// Human Interface Device
    HidInterrupt = 0x0013,
    /// UPnP protocol (ESDP)
    UPNP = 0x0015,
    /// Audio/Video Control Transport Protocol
    AVCTP = 0x0017,
    /// Audio/Video Distribution Transport Protocol
    AVDTP = 0x0019,
    /// Audio/Video Control Transport Protocol for browsing
    AvctpBrowsing = 0x001B,
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
                // Dynamic PSMs must be odd and >= 0x1001
                (value % 2 == 1) && (*value >= 0x1001)
            }
            _ => true,
        }
    }

    /// Get the PSM value as u16
    pub fn value(&self) -> u16 {
        match self {
            PSM::SDP => 0x0001,
            PSM::RFCOMM => 0x0003,
            PSM::TcsBin => 0x0005,
            PSM::TcsBinCordless => 0x0007,
            PSM::BNEP => 0x000F,
            PSM::HidControl => 0x0011,
            PSM::HidInterrupt => 0x0013,
            PSM::UPNP => 0x0015,
            PSM::AVCTP => 0x0017,
            PSM::AVDTP => 0x0019,
            PSM::AvctpBrowsing => 0x001B,
            PSM::ATT => 0x001F,
            PSM::_3DSP => 0x0021,
            PSM::Dynamic(value) => *value,
        }
    }

    /// Convert from u16 value
    pub fn from_value(value: u16) -> Option<Self> {
        match value {
            0x0001 => Some(PSM::SDP),
            0x0003 => Some(PSM::RFCOMM),
            0x0005 => Some(PSM::TcsBin),
            0x0007 => Some(PSM::TcsBinCordless),
            0x000F => Some(PSM::BNEP),
            0x0011 => Some(PSM::HidControl),
            0x0013 => Some(PSM::HidInterrupt),
            0x0015 => Some(PSM::UPNP),
            0x0017 => Some(PSM::AVCTP),
            0x0019 => Some(PSM::AVDTP),
            0x001B => Some(PSM::AvctpBrowsing),
            0x001F => Some(PSM::ATT),
            0x0021 => Some(PSM::_3DSP),
            _ if value % 2 == 1 && value >= 0x1001 => Some(PSM::Dynamic(value)),
            _ => None,
        }
    }
}

impl fmt::Display for PSM {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PSM::SDP => write!(f, "SDP (0x0001)"),
            PSM::RFCOMM => write!(f, "RFCOMM (0x0003)"),
            PSM::TcsBin => write!(f, "TCS-BIN (0x0005)"),
            PSM::TcsBinCordless => write!(f, "TCS-BIN-CORDLESS (0x0007)"),
            PSM::BNEP => write!(f, "BNEP (0x000F)"),
            PSM::HidControl => write!(f, "HID-Control (0x0011)"),
            PSM::HidInterrupt => write!(f, "HID-Interrupt (0x0013)"),
            PSM::UPNP => write!(f, "UPnP (0x0015)"),
            PSM::AVCTP => write!(f, "AVCTP (0x0017)"),
            PSM::AVDTP => write!(f, "AVDTP (0x0019)"),
            PSM::AvctpBrowsing => write!(f, "AVCTP-Browsing (0x001B)"),
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
    if next_psm < 0x1001 {
        next_psm = 0x1001;
        NEXT_DYNAMIC_PSM.store(0x1003, Ordering::SeqCst);
    }

    PSM::Dynamic(next_psm)
}

/// Get the next dynamic PSM
pub fn get_next_dynamic_psm(current_psm: u16) -> u16 {
    let mut next_psm = current_psm + 2; // Increment by 2 to maintain odd value

    if next_psm < 0x1001 {
        next_psm = 0x1001;
    }

    next_psm
}
