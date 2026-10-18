// Keep the RFC 1057 Appendix A name for the GETPORT argument.
#![allow(non_camel_case_types)]

use crate::rpc::codec::{DecodeError, Decoder};

/// A portmapper `mapping` argument: program, version, transport protocol,
/// and (ignored for GETPORT) port.
#[derive(Copy, Clone, Debug, Default)]
pub struct mapping {
    pub prog: u32,
    pub vers: u32,
    pub prot: u32,
    pub port: u32,
}

impl mapping {
    /// Decodes a complete GETPORT argument, rejecting trailing bytes.
    pub fn decode(arguments: &[u8]) -> Result<Self, DecodeError> {
        let mut decoder = Decoder::new(arguments);
        let mapping = Self {
            prog: decoder.read_u32()?,
            vers: decoder.read_u32()?,
            prot: decoder.read_u32()?,
            port: decoder.read_u32()?,
        };
        decoder.finish()?;
        Ok(mapping)
    }
}

pub const IPPROTO_TCP: u32 = 6; /* protocol number for TCP/IP */
pub const IPPROTO_UDP: u32 = 17; /* protocol number for UDP/IP */
pub const PROGRAM: u32 = 100000;
pub const VERSION: u32 = 2;
