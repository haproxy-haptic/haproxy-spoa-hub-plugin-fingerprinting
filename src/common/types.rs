/// Parsed representation of TLS ClientHello fields from SPOE message arguments.
#[derive(Debug, Clone)]
pub struct ClientHelloData {
    // JA3/JA3N fields
    pub protocol_version: u16,
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub elliptic_curves: Vec<u16>,
    pub ec_point_formats: Vec<u8>,
    // JA4-specific fields
    pub supported_versions: Vec<u16>,
    pub signature_algorithms: Vec<u16>,
    pub alpn: Option<String>,
    pub sni_present: bool,
}
