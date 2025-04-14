//! Type definitions for the Security Manager Protocol
use crate::gap::BdAddr;
use std::fmt;
use thiserror::Error;

/// SMP Error types
#[derive(Debug, Clone, Error)]
pub enum SmpError {
    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

    #[error("Pairing failed: {0}")]
    PairingFailed(String),

    #[error("Insufficient security level")]
    InsufficientSecurity,

    #[error("Passkey entry failed")]
    PasskeyEntryFailed,

    #[error("OOB data not available")]
    OobNotAvailable,

    #[error("Authentication requirements not met")]
    AuthenticationRequirements,

    #[error("Confirm value failed")]
    ConfirmValueFailed,

    #[error("Pairing not supported")]
    PairingNotSupported,

    #[error("Encryption key size issue")]
    EncryptionKeySize,

    #[error("Command not supported")]
    CommandNotSupported,

    #[error("Unspecified reason")]
    UnspecifiedReason,

    #[error("Too many pairing attempts")]
    RepeatedAttempts,

    #[error("Invalid parameters")]
    InvalidParameters,

    #[error("DHKey check failed")]
    DhKeyCheckFailed,

    #[error("Numeric comparison failed")]
    NumericComparisonFailed,

    #[error("BR/EDR pairing in progress")]
    BrEdrPairingInProgress,

    #[error("Cross-transport key not allowed")]
    CrossTransportKeyNotAllowed,

    #[error("Operation timeout")]
    Timeout,

    #[error("User canceled operation")]
    UserCanceled,

    #[error("IO error: {0}")]
    IoError(String),

    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    #[error("Invalid state for operation")]
    InvalidState,

    #[error("Not paired with device")]
    NotPaired,

    #[error("HCI error: {0}")]
    HciError(String),

    #[error("L2CAP error: {0}")]
    L2capError(String),

    #[error("Connection not found")]
    ConnectionNotFound,
}

/// Result type for SMP operations
pub type SmpResult<T> = Result<T, SmpError>;

/// IO Capability types for pairing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoCapability {
    /// Display only capability
    DisplayOnly,
    /// Display with yes/no capability
    DisplayYesNo,
    /// Keyboard only
    KeyboardOnly,
    /// No input, no output
    NoInputNoOutput,
    /// Both keyboard and display
    KeyboardDisplay,
}

impl IoCapability {
    /// Convert to u8 value for protocol
    pub fn to_u8(&self) -> u8 {
        match self {
            IoCapability::DisplayOnly => super::constants::SMP_IO_CAPABILITY_DISPLAY_ONLY,
            IoCapability::DisplayYesNo => super::constants::SMP_IO_CAPABILITY_DISPLAY_YES_NO,
            IoCapability::KeyboardOnly => super::constants::SMP_IO_CAPABILITY_KEYBOARD_ONLY,
            IoCapability::NoInputNoOutput => super::constants::SMP_IO_CAPABILITY_NO_INPUT_NO_OUTPUT,
            IoCapability::KeyboardDisplay => super::constants::SMP_IO_CAPABILITY_KEYBOARD_DISPLAY,
        }
    }

    /// Convert from u8 value from protocol
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            super::constants::SMP_IO_CAPABILITY_DISPLAY_ONLY => Some(IoCapability::DisplayOnly),
            super::constants::SMP_IO_CAPABILITY_DISPLAY_YES_NO => Some(IoCapability::DisplayYesNo),
            super::constants::SMP_IO_CAPABILITY_KEYBOARD_ONLY => Some(IoCapability::KeyboardOnly),
            super::constants::SMP_IO_CAPABILITY_NO_INPUT_NO_OUTPUT => {
                Some(IoCapability::NoInputNoOutput)
            }
            super::constants::SMP_IO_CAPABILITY_KEYBOARD_DISPLAY => {
                Some(IoCapability::KeyboardDisplay)
            }
            _ => None,
        }
    }
}

impl fmt::Display for IoCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IoCapability::DisplayOnly => write!(f, "Display Only"),
            IoCapability::DisplayYesNo => write!(f, "Display Yes/No"),
            IoCapability::KeyboardOnly => write!(f, "Keyboard Only"),
            IoCapability::NoInputNoOutput => write!(f, "No Input No Output"),
            IoCapability::KeyboardDisplay => write!(f, "Keyboard Display"),
        }
    }
}

/// Pairing methods
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingMethod {
    /// Just Works method - no user interaction
    JustWorks,
    /// Passkey Entry - one device enters a passkey
    PasskeyEntry,
    /// Numeric Comparison - user confirms matching numbers
    NumericComparison,
    /// Out of Band data
    OutOfBand,
}

impl PairingMethod {
    /// Convert to u8 value for protocol
    pub fn to_u8(&self) -> u8 {
        match self {
            PairingMethod::JustWorks => super::constants::SMP_PAIRING_METHOD_JUST_WORKS,
            PairingMethod::PasskeyEntry => super::constants::SMP_PAIRING_METHOD_PASSKEY_ENTRY,
            PairingMethod::NumericComparison => {
                super::constants::SMP_PAIRING_METHOD_NUMERIC_COMPARISON
            }
            PairingMethod::OutOfBand => super::constants::SMP_PAIRING_METHOD_OOB,
        }
    }

    /// Convert from u8 value from protocol
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            super::constants::SMP_PAIRING_METHOD_JUST_WORKS => Some(PairingMethod::JustWorks),
            super::constants::SMP_PAIRING_METHOD_PASSKEY_ENTRY => Some(PairingMethod::PasskeyEntry),
            super::constants::SMP_PAIRING_METHOD_NUMERIC_COMPARISON => {
                Some(PairingMethod::NumericComparison)
            }
            super::constants::SMP_PAIRING_METHOD_OOB => Some(PairingMethod::OutOfBand),
            _ => None,
        }
    }
}

impl fmt::Display for PairingMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PairingMethod::JustWorks => write!(f, "Just Works"),
            PairingMethod::PasskeyEntry => write!(f, "Passkey Entry"),
            PairingMethod::NumericComparison => write!(f, "Numeric Comparison"),
            PairingMethod::OutOfBand => write!(f, "Out of Band"),
        }
    }
}

/// Authentication requirements
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthRequirements {
    /// Whether bonding is required
    pub bonding: bool,
    /// Whether MITM protection is required
    pub mitm: bool,
    /// Whether Secure Connections is required
    pub secure_connections: bool,
    /// Whether keypress notifications are required
    pub keypress_notifications: bool,
    /// Whether CT2 feature is supported
    pub ct2: bool,
}

impl AuthRequirements {
    /// Create new authentication requirements
    pub fn new(bonding: bool, mitm: bool, secure_connections: bool) -> Self {
        Self {
            bonding,
            mitm,
            secure_connections,
            keypress_notifications: false,
            ct2: false,
        }
    }

    /// Create with default values (bonding enabled, others disabled)
    pub fn default() -> Self {
        Self {
            bonding: true,
            mitm: false,
            secure_connections: false,
            keypress_notifications: false,
            ct2: false,
        }
    }

    /// Create with secure connections
    pub fn secure() -> Self {
        Self {
            bonding: true,
            mitm: true,
            secure_connections: true,
            keypress_notifications: false,
            ct2: false,
        }
    }

    /// Convert to u8 value for protocol
    pub fn to_u8(&self) -> u8 {
        let mut value = 0;

        if self.bonding {
            value |= super::constants::SMP_AUTH_REQ_BONDING;
        }

        if self.mitm {
            value |= super::constants::SMP_AUTH_REQ_MITM;
        }

        if self.secure_connections {
            value |= super::constants::SMP_AUTH_REQ_SC;
        }

        if self.keypress_notifications {
            value |= super::constants::SMP_AUTH_REQ_KEYPRESS;
        }

        if self.ct2 {
            value |= super::constants::SMP_AUTH_REQ_CT2;
        }

        value
    }

    /// Convert from u8 value from protocol
    pub fn from_u8(value: u8) -> Self {
        Self {
            bonding: (value & super::constants::SMP_AUTH_REQ_BONDING) != 0,
            mitm: (value & super::constants::SMP_AUTH_REQ_MITM) != 0,
            secure_connections: (value & super::constants::SMP_AUTH_REQ_SC) != 0,
            keypress_notifications: (value & super::constants::SMP_AUTH_REQ_KEYPRESS) != 0,
            ct2: (value & super::constants::SMP_AUTH_REQ_CT2) != 0,
        }
    }
}

/// Key distribution preferences
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyDistribution {
    /// Encryption key (LTK, EDIV, RAND)
    pub encryption_key: bool,
    /// Identity key (IRK, public address)
    pub identity_key: bool,
    /// Signing key (CSRK)
    pub signing_key: bool,
    /// Link key derivation
    pub link_key: bool,
}

impl KeyDistribution {
    /// Create new key distribution preferences
    pub fn new(
        encryption_key: bool,
        identity_key: bool,
        signing_key: bool,
        link_key: bool,
    ) -> Self {
        Self {
            encryption_key,
            identity_key,
            signing_key,
            link_key,
        }
    }

    /// Create with default values (all keys distributed)
    pub fn all() -> Self {
        Self {
            encryption_key: true,
            identity_key: true,
            signing_key: true,
            link_key: false, // Link key is rarely used for LE
        }
    }

    /// Create with all keys disabled
    pub fn none() -> Self {
        Self {
            encryption_key: false,
            identity_key: false,
            signing_key: false,
            link_key: false,
        }
    }

    /// Convert to u8 value for protocol
    pub fn to_u8(&self) -> u8 {
        let mut value = 0;

        if self.encryption_key {
            value |= super::constants::SMP_KEY_DIST_ENC_KEY;
        }

        if self.identity_key {
            value |= super::constants::SMP_KEY_DIST_ID_KEY;
        }

        if self.signing_key {
            value |= super::constants::SMP_KEY_DIST_SIGN_KEY;
        }

        if self.link_key {
            value |= super::constants::SMP_KEY_DIST_LINK_KEY;
        }

        value
    }

    /// Convert from u8 value from protocol
    pub fn from_u8(value: u8) -> Self {
        Self {
            encryption_key: (value & super::constants::SMP_KEY_DIST_ENC_KEY) != 0,
            identity_key: (value & super::constants::SMP_KEY_DIST_ID_KEY) != 0,
            signing_key: (value & super::constants::SMP_KEY_DIST_SIGN_KEY) != 0,
            link_key: (value & super::constants::SMP_KEY_DIST_LINK_KEY) != 0,
        }
    }
}

/// SMP OOB (Out of Band) data
#[derive(Debug, Clone)]
pub struct OobData {
    /// Random value (r)
    pub r: [u8; 16],
    /// Confirm value (c = f4(PKx, PKx, r, 0))
    pub c: [u8; 16],
}

impl Default for OobData {
    fn default() -> Self {
        Self {
            r: [0; 16],
            c: [0; 16],
        }
    }
}

/// SMP Pairing Features
#[derive(Debug, Clone)]
pub struct PairingFeatures {
    /// IO Capability
    pub io_capability: IoCapability,
    /// OOB data flag
    pub oob_data_present: bool,
    /// Authentication requirements
    pub auth_req: AuthRequirements,
    /// Maximum encryption key size (7-16)
    pub max_key_size: u8,
    /// Initiator key distribution
    pub initiator_key_dist: KeyDistribution,
    /// Responder key distribution
    pub responder_key_dist: KeyDistribution,
}

impl Default for PairingFeatures {
    fn default() -> Self {
        Self {
            io_capability: IoCapability::NoInputNoOutput,
            oob_data_present: false,
            auth_req: AuthRequirements::default(),
            max_key_size: super::constants::SMP_MAX_ENCRYPTION_KEY_SIZE,
            initiator_key_dist: KeyDistribution::all(),
            responder_key_dist: KeyDistribution::all(),
        }
    }
}

/// Pairing Role
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingRole {
    /// Initiator of the pairing (typically Central device)
    Initiator,
    /// Responder to pairing (typically Peripheral device)
    Responder,
}

/// Transport type for pairing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportType {
    /// LE transport
    Le,
    /// BR/EDR transport
    BrEdr,
}

impl TransportType {
    /// Convert to u8 value for protocol
    pub fn to_u8(&self) -> u8 {
        match self {
            TransportType::Le => super::constants::SMP_TRANSPORT_LE,
            TransportType::BrEdr => super::constants::SMP_TRANSPORT_BR_EDR,
        }
    }

    /// Convert from u8 value from protocol
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            super::constants::SMP_TRANSPORT_LE => Some(TransportType::Le),
            super::constants::SMP_TRANSPORT_BR_EDR => Some(TransportType::BrEdr),
            _ => None,
        }
    }
}

/// SMP Event types for callbacks
#[derive(Debug, Clone)]
pub enum SmpEvent {
    /// Pairing request received
    PairingRequest(BdAddr, PairingFeatures),
    /// Pairing response received
    PairingResponse(BdAddr, PairingFeatures),
    /// Pairing complete
    PairingComplete(BdAddr, bool),
    /// Pairing failed
    PairingFailed(BdAddr, SmpError),
    /// Display passkey request
    DisplayPasskey(BdAddr, u32),
    /// Passkey entry request
    PasskeyRequest(BdAddr),
    /// Numeric comparison request
    NumericComparisonRequest(BdAddr, u32),
    /// Keys received
    KeysReceived(BdAddr),
    /// Identity resolving key (IRK) received
    IdentityResolvingKeyReceived(BdAddr, [u8; 16]),
    /// Signing key (CSRK) received
    SigningKeyReceived(BdAddr, [u8; 16]),
    /// Long term key (LTK) received
    LongTermKeyReceived(BdAddr, [u8; 16], u16, [u8; 8]),
    /// Security level changed
    SecurityLevelChanged(BdAddr, SecurityLevel),
}

/// Security level for a connection
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecurityLevel {
    /// No security (unencrypted)
    None = 0,
    /// Encryption without authentication (Just Works)
    EncryptionOnly = 1,
    /// Encryption with authentication (MITM protection)
    EncryptionWithAuthentication = 2,
    /// Secure Connections with encryption and authentication
    SecureConnections = 3,
}

impl SecurityLevel {
    /// Check if this security level includes encryption
    pub fn is_encrypted(&self) -> bool {
        *self >= SecurityLevel::EncryptionOnly
    }

    /// Check if this security level includes authentication
    pub fn is_authenticated(&self) -> bool {
        *self >= SecurityLevel::EncryptionWithAuthentication
    }

    /// Check if this security level uses Secure Connections
    pub fn is_secure_connections(&self) -> bool {
        *self >= SecurityLevel::SecureConnections
    }
}

/// Keypress notification type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeypressNotificationType {
    /// Entry started
    EntryStarted,
    /// Digit entered
    DigitEntered,
    /// Digit erased
    DigitErased,
    /// Cleared
    Cleared,
    /// Entry completed
    EntryCompleted,
}

impl KeypressNotificationType {
    /// Convert to u8 value for protocol
    pub fn to_u8(&self) -> u8 {
        match self {
            KeypressNotificationType::EntryStarted => super::constants::SMP_KEYPRESS_ENTRY_STARTED,
            KeypressNotificationType::DigitEntered => super::constants::SMP_KEYPRESS_DIGIT_ENTERED,
            KeypressNotificationType::DigitErased => super::constants::SMP_KEYPRESS_DIGIT_ERASED,
            KeypressNotificationType::Cleared => super::constants::SMP_KEYPRESS_CLEARED,
            KeypressNotificationType::EntryCompleted => {
                super::constants::SMP_KEYPRESS_ENTRY_COMPLETED
            }
        }
    }

    /// Convert from u8 value from protocol
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            super::constants::SMP_KEYPRESS_ENTRY_STARTED => {
                Some(KeypressNotificationType::EntryStarted)
            }
            super::constants::SMP_KEYPRESS_DIGIT_ENTERED => {
                Some(KeypressNotificationType::DigitEntered)
            }
            super::constants::SMP_KEYPRESS_DIGIT_ERASED => {
                Some(KeypressNotificationType::DigitErased)
            }
            super::constants::SMP_KEYPRESS_CLEARED => Some(KeypressNotificationType::Cleared),
            super::constants::SMP_KEYPRESS_ENTRY_COMPLETED => {
                Some(KeypressNotificationType::EntryCompleted)
            }
            _ => None,
        }
    }
}

/// SMP Identity Address Information
#[derive(Debug, Clone)]
pub struct IdentityAddressInfo {
    /// Address type (public or random)
    pub addr_type: u8,
    /// Bluetooth device address
    pub bd_addr: BdAddr,
}

/// SMP Key Store handle
pub type KeyStoreHandle = Box<dyn crate::smp::KeyStore + Send + Sync>;
