use crate::gap::constants::*;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Central,
    Peripheral,
    Observer,
    Broadcaster,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryMode {
    NonDiscoverable,
    LimitedDiscoverable,
    GeneralDiscoverable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionMode {
    NonConnectable,
    DirectConnectable,
    UndirectedConnectable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticationMode {
    NoAuthentication,
    NoBondingAuthentication,
    BondingAuthentication,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressType {
    Public,
    Random,
    PublicIdentity,
    RandomIdentity,
}

impl From<u8> for AddressType {
    fn from(value: u8) -> Self {
        match value {
            PUBLIC_DEVICE_ADDRESS => AddressType::Public,
            RANDOM_DEVICE_ADDRESS => AddressType::Random,
            PUBLIC_IDENTITY_ADDRESS => AddressType::PublicIdentity,
            RANDOM_IDENTITY_ADDRESS => AddressType::RandomIdentity,
            _ => AddressType::Public,
        }
    }
}

impl From<AddressType> for u8 {
    fn from(value: AddressType) -> Self {
        match value {
            AddressType::Public => PUBLIC_DEVICE_ADDRESS,
            AddressType::Random => RANDOM_DEVICE_ADDRESS,
            AddressType::PublicIdentity => PUBLIC_IDENTITY_ADDRESS,
            AddressType::RandomIdentity => RANDOM_IDENTITY_ADDRESS,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BdAddr {
    pub bytes: [u8; 6],
}

impl BdAddr {
    pub fn new(bytes: [u8; 6]) -> Self {
        Self { bytes }
    }

    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        if slice.len() >= 6 {
            let mut bytes = [0u8; 6];
            bytes.copy_from_slice(&slice[0..6]);
            Some(Self { bytes })
        } else {
            None
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Display for BdAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.bytes[5],
            self.bytes[4],
            self.bytes[3],
            self.bytes[2],
            self.bytes[1],
            self.bytes[0]
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    pub address: BdAddr,
    pub address_type: AddressType,
    pub name: Option<String>,
    pub rssi: Option<i8>,
    pub tx_power: Option<i8>,
    pub manufacturer_data: Option<Vec<u8>>,
    pub service_uuids: Vec<crate::gatt::Uuid>,
    pub service_data: Vec<(crate::gatt::Uuid, Vec<u8>)>,
    pub appearance: Option<u16>,
    pub flags: Option<u8>,
}

impl Device {
    pub fn new(address: BdAddr, address_type: AddressType) -> Self {
        Self {
            address,
            address_type,
            name: None,
            rssi: None,
            tx_power: None,
            manufacturer_data: None,
            service_uuids: Vec::new(),
            service_data: Vec::new(),
            appearance: None,
            flags: None,
        }
    }
}
