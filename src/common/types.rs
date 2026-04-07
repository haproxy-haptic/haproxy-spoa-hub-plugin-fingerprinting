/// Parsed representation of TLS ClientHello fields from SPOE message arguments.
#[derive(Debug, Clone)]
pub struct ClientHelloData {
    pub protocol_version: u16,
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub elliptic_curves: Vec<u16>,
    pub ec_point_formats: Vec<u8>,
}
