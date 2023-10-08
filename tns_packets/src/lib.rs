#![allow(dead_code)]
use std::{fmt, error::Error, num::TryFromIntError, str::{self, Utf8Error}};
use error_stack::Report;

#[derive(Debug)]
struct ConvertBytesToUIntError;

impl fmt::Display for ConvertBytesToUIntError {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.write_str("Byte conversion error: invalid number of bytes in conversion to u16 or u32")
    }
}

impl Error for ConvertBytesToUIntError {}

/* Helper functions - convert bytes to u32 and vice-versa. Big endian format */
fn bytes_to_u16_be(bytes: &[u8]) -> Result<u16, Report<ConvertBytesToUIntError>> {
    let num_bytes = bytes.len();
    let expected_bytes = 2;

    if num_bytes != expected_bytes {
        return Err(Report::new(ConvertBytesToUIntError)
            .attach_printable(format!("Incorrect number of bytes. Expected 2 but received {}: {:?}", num_bytes, bytes)));
    }

    Ok(((bytes[0] as u16) << 8) + ((bytes[1] as u16) << 0))
}

fn bytes_to_u32_be(bytes: &[u8]) -> Result<u32, Report<ConvertBytesToUIntError>> {
    let num_bytes = bytes.len();

    match num_bytes {
        4 => Ok(((bytes[0] as u32) << 24)
            + ((bytes[1] as u32) << 16)
            + ((bytes[2] as u32) << 8)
            + ((bytes[3] as u32) << 0)),
        2 => Ok(((bytes[0] as u32) << 8) + ((bytes[1] as u32) << 0)),
        _ => Err(Report::new(ConvertBytesToUIntError)
                .attach_printable(format!("Incorrect number of bytes. Expected 2 or 4 but received {}: {:?}", num_bytes, bytes))),
    }
}

fn u16_to_bytes_be(n: u16) -> Vec<u8> {
    let b2 = (n >> 8) as u8;
    let b1 = (n >> 0) as u8;

    vec![b2, b1]
}

fn u32_to_bytes_be(n: u32) -> Vec<u8> {
    let b4 = (n >> 24) as u8;
    let b3 = (n >> 16) as u8;
    let b2 = (n >> 8) as u8;
    let b1 = (n >> 0) as u8;

    vec![b4, b3, b2, b1]
}

#[derive(PartialEq, Debug)]
pub enum TnsPacketType {
    CONNECT,
    ACCEPT,
    ACK,
    REFUSE,
    REDIRECT,
    DATA,
    NULL,
    ABORT,
    RESEND,
    MARKER,
    ATTENTION,
    CONTROL
}

#[derive(Debug)]
pub struct PacketHeaderError;

impl fmt::Display for PacketHeaderError {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.write_str("Error reading TNS packet header")
    }
}

impl Error for PacketHeaderError {}


#[derive(Debug)]
pub struct TnsPacketHeader {
    packet_length: u32,
    packet_checksum: [u8; 2],
    packet_type: u8,
    reserved: u8,
    header_checksum: [u8; 2],
}

impl TnsPacketHeader {
    pub fn new(header: [u8; 8]) -> Self {
        /* In versions prior to 12c, bytes 3 and 4 are a packet checksum which seems to always be 0 or 4 (in rare cases)
        Later versions use bytes 1-4 as packet length, which would result in the 3rd and 4th byte having a value greater than 4 */
        let mut packet_checksum = [header[2], header[3]];
        let packet_length_bytes = match bytes_to_u32_be(&packet_checksum).unwrap() {
            0 | 4 => { log::debug!("Packet header with 2 bytes packet length received!"); &header[..2]},
            _ => {
                packet_checksum = [0u8; 2];
                log::debug!("Packet header with 4 bytes packet length received!");
                &header[..4]
            },
        };

        Self {
            packet_length: bytes_to_u32_be(packet_length_bytes).unwrap(),
            packet_checksum,
            packet_type: header[4],
            reserved: header[5],
            header_checksum: [header[6], header[7]],
        }
    }

    pub fn get_packet_type(&self) -> Result<TnsPacketType, Report<PacketHeaderError>> {
        match self.packet_type {
            1 => Ok(TnsPacketType::CONNECT),
            2 => Ok(TnsPacketType::ACCEPT),
            3 => Ok(TnsPacketType::ACK),
            4 => Ok(TnsPacketType::REFUSE),
            5 => Ok(TnsPacketType::REDIRECT),
            6 => Ok(TnsPacketType::DATA),
            7 => Ok(TnsPacketType::NULL),
            9 => Ok(TnsPacketType::ABORT),
            11 => Ok(TnsPacketType::RESEND),
            12 => Ok(TnsPacketType::MARKER),
            13 => Ok(TnsPacketType::ATTENTION),
            14 => Ok(TnsPacketType::CONTROL),
            _ => Err(Report::new(PacketHeaderError)
            .attach_printable(format!("Invalid packet type in stream. Received header with packet type {}", self.packet_type))),
        }
    }

    pub fn get_packet_length(&self) -> u32 {
        self.packet_length
    }

    fn set_packet_length(&mut self, length: u32) {
        self.packet_length = length;
    }

    fn set_packet_type(&mut self, packet_type: u8) {
        self.packet_type = packet_type;
    }
}

impl Default for TnsPacketHeader {
    fn default() -> Self {
        Self {
            packet_length: 0,
            packet_checksum: [0x00, 0x00],
            packet_type: 0x01,
            reserved: 0x00,
            header_checksum: [0x00, 0x00],
        }
    }
}

#[derive(Debug)]
pub struct TnsAcceptPacket {
    tns_version: u16,
    service_options: u16,
    sdu_size: u16,
    mtdu_size: u16,
    hardware_1: [u8; 2],
    data_length: u16,
    data_offset: u16,
    connect_flag0: u8,
    connect_flag1: u8,
    misc: [u8; 8],
    data: Vec<u8>,
}

impl TnsAcceptPacket {
    pub fn new(body: &Vec<u8>) -> Self {
        let data_length = bytes_to_u16_be(&body[10..=11]).unwrap();
        let data_offset = bytes_to_u16_be(&body[12..=13]).unwrap() - 8; // -8 due to packet header not being read seperately
        log::debug!("Accept packet received with data length of {}, at offset of {}", data_length, data_offset);

        Self {
            tns_version: bytes_to_u16_be(&body[0..=1]).unwrap(),
            service_options: bytes_to_u16_be(&body[2..=3]).unwrap(),
            sdu_size: bytes_to_u16_be(&body[4..=5]).unwrap(),
            mtdu_size: bytes_to_u16_be(&body[6..=7]).unwrap(),
            hardware_1: [body[8], body[9]],
            data_length,
            data_offset,
            connect_flag0: body[14],
            connect_flag1: body[15],
            misc: [
                body[16], body[17], body[18], body[19], body[20], body[21], body[22], body[23],
            ],
            data: body[data_offset as usize..].to_vec(),
        }   
    }

    pub fn get_data_len(&self) -> u16 {
        self.data_length
    }

    pub fn get_data(&self) -> Vec<u8> {
        self.data.clone()
    }

    pub fn get_data_as_str(&self) -> Result<&str, Utf8Error> {
        str::from_utf8(&self.data)
    }
}

#[derive(Debug)]
pub struct TnsRefusePacket {
    reason_user: u8,
    reason_sys: u8,
    data_length: u16,
    data: Vec<u8>,
}

impl TnsRefusePacket {
    pub fn new(body: &Vec<u8>) -> Self {
        Self {
            reason_user: body[0],
            reason_sys: body[1],
            data_length: bytes_to_u16_be(&body[2..=3]).unwrap(),
            data: body[4..].to_vec(),
        }
    }

    pub fn get_data_length(&self) -> u16 {
        self.data_length
    }

    pub fn get_data(&self) -> Vec<u8> {
        self.data.clone()
    }

    pub fn get_data_as_str(&self) -> Result<&str, Utf8Error> {
        str::from_utf8(&self.data)
    }
}

#[derive(Debug)]
pub struct TnsDataPacket {
    flag: [u8; 2],
    data: Vec<u8>
}

impl TnsDataPacket {
    pub fn new(body: &Vec<u8>) -> Result<Self, String> {
        if body.len() >= 2 {
            return Ok(Self {
                flag: [body[0], body[1]],
                data: Vec::from_iter(body[2..].to_owned()),
            });
        }
        Err(format!("Invalid data packet received. Received {} data bytes", body.len()))
    }

    pub fn is_end_of_data(&self) -> bool {
        self.flag == [0x00, 0x40]
    }

    pub fn get_data(&self) -> Vec<u8> {
        self.data.clone()
    }

    pub fn get_data_as_str(&self) -> Result<&str, Utf8Error> {
        str::from_utf8(&self.data)
    }
}

#[derive(Debug)]
pub struct TnsConnectPacket {
    header: TnsPacketHeader,
    version: u16,
    version_compatible: u16,
    service_operations: [u8; 2],
    sdu_size: u16,
    mtdu_size: u16,
    nt_characteristics: [u8; 2],
    line_turnaround: u16,
    hardware_1: [u8; 2],
    data_length: u16,
    data_offset: u16,
    max_receivable_connect_data: u32,
    connect_flag0: u8,
    connect_flag1: u8,
    trace_facility1: [u8; 4],
    trace_facility2: [u8; 4],
    trace_conn_id: [u8; 8],
    misc: Vec<u8>,
    data: Vec<u8>,
}

impl TnsConnectPacket {
    pub fn new(connect_data: String, packet_version: &str) -> Result<Self, TryFromIntError> {
        let mut header = TnsPacketHeader::default();

        /* Different client versions have different values for some fields in the metadata 
        Default version = 19c */
        let (version, sdu_size, mtdu_size, misc) = match packet_version {
            "8g" => (310, 2048, 32767, vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            "9i" => (312, 2048, 32767, vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            "10g" => (313, 2048, 32767, vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            "11g" => (314, 8192, 32767, vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            _ => (318, 8192, 65535, vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
        };

        let data_length: u16 = match connect_data.len().try_into() {
            Ok(n) => n,
            Err(e) => return Err(e),
        };
        let misc_length = misc.len() as u16;

        /* Packet length in connect packets only ever uses first two bytes of header, regardless of client version */
        let packet_length: u16 =  50 + misc_length + data_length;
        let data_offset = packet_length - data_length;
        header.set_packet_length(packet_length as u32);

        Ok(Self {
            header,
            version,
            version_compatible: 300,
            service_operations: [0x00, 0x81],
            sdu_size,
            mtdu_size,
            nt_characteristics: [0x7f, 0x08],
            line_turnaround: 0,
            hardware_1: [0x01, 0x00],
            data_length,
            data_offset,
            max_receivable_connect_data: 2040,
            connect_flag0: 0x0c,
            connect_flag1: 0x0c,
            trace_facility1: [0x00; 4], // First two bytes seem to always be different in real requests. Not sure if random or calculated somehow. Doesn't stop requests working anyway
            trace_facility2: [0x00; 4],
            trace_conn_id: [0x00; 8],
            misc,
            data: connect_data.as_bytes().to_vec(),
        })
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();

        bytes.extend(u16_to_bytes_be(self.header.packet_length as u16));
        bytes.extend(self.header.header_checksum);
        bytes.push(self.header.packet_type);
        bytes.push(self.header.reserved);
        bytes.extend(self.header.header_checksum);
        bytes.extend(u16_to_bytes_be(self.version));
        bytes.extend(u16_to_bytes_be(self.version_compatible));
        bytes.extend(self.service_operations);
        bytes.extend(u16_to_bytes_be(self.sdu_size));
        bytes.extend(u16_to_bytes_be(self.mtdu_size));
        bytes.extend(self.nt_characteristics);
        bytes.extend(u16_to_bytes_be(self.line_turnaround));
        bytes.extend(self.hardware_1);
        bytes.extend(u16_to_bytes_be(self.data_length));
        bytes.extend(u16_to_bytes_be(self.data_offset));
        bytes.extend(u32_to_bytes_be(self.max_receivable_connect_data));
        bytes.push(self.connect_flag0);
        bytes.push(self.connect_flag1);
        bytes.extend(self.trace_facility1);
        bytes.extend(self.trace_facility2);
        bytes.extend(self.trace_conn_id);
        bytes.extend(&self.misc);
        bytes.extend(&self.data);

        bytes
    }
}