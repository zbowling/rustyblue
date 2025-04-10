use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceRecord {
    pub service_class_id_list: Vec<Uuid>,
    pub attributes: HashMap<u16, DataElement>,
    pub handle: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Uuid {
    Uuid16(u16),
    Uuid32(u32),
    Uuid128([u8; 16]),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataElement {
    Nil,
    Unsigned8(u8),
    Unsigned16(u16),
    Unsigned32(u32),
    Unsigned64(u64),
    Signed8(i8),
    Signed16(i16),
    Signed32(i32),
    Signed64(i64),
    TextString(String),
    Boolean(bool),
    Uuid(Uuid),
    Sequence(Vec<DataElement>),
    Alternative(Vec<DataElement>),
    Url(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttributeId {
    ServiceRecordHandle = 0x0000,
    ServiceClassIdList = 0x0001,
    ServiceRecordState = 0x0002,
    ServiceId = 0x0003,
    ProtocolDescriptorList = 0x0004,
    BrowseGroupList = 0x0005,
    LanguageBaseAttributeIdList = 0x0006,
    ServiceInfoTimeToLive = 0x0007,
    ServiceAvailability = 0x0008,
    BluetoothProfileDescriptorList = 0x0009,
    DocumentationUrl = 0x000A,
    ClientExecutableUrl = 0x000B,
    IconUrl = 0x000C,
    AdditionalProtocolDescriptorLists = 0x000D,
}

pub const SDP_PSM: u16 = 0x0001;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdpPdu {
    ErrorResponse = 0x01,
    ServiceSearchRequest = 0x02,
    ServiceSearchResponse = 0x03,
    ServiceAttributeRequest = 0x04,
    ServiceAttributeResponse = 0x05,
    ServiceSearchAttributeRequest = 0x06,
    ServiceSearchAttributeResponse = 0x07,
}