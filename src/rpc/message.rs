//! ONC RPC version 2 message constants and reply builders (RFC 5531) shared by
//! the NFS/MOUNT connection path and the standalone portmapper.

use crate::rpc::auth::AUTH_NONE;
use crate::rpc::codec::Encoder;

pub const RPC_VERSION: u32 = 2;
pub(crate) const CALL: u32 = 0;
pub(crate) const REPLY: u32 = 1;
pub(crate) const MSG_ACCEPTED: u32 = 0;
pub(crate) const MSG_DENIED: u32 = 1;
pub(crate) const RPC_MISMATCH: u32 = 0;
pub(crate) const AUTH_ERROR: u32 = 1;

/// Size of an accepted reply header carrying an empty `AUTH_NONE` verifier:
/// XID, message type, reply status, verifier flavor and length, and the
/// accept status.
pub const ACCEPTED_REPLY_HEADER_SIZE: usize = 24;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CallHeader {
    pub xid: u32,
    pub rpc_version: u32,
    pub program: u32,
    pub version: u32,
    pub procedure: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum AcceptStatus {
    Success = 0,
    ProgramUnavailable = 1,
    ProgramMismatch = 2,
    ProcedureUnavailable = 3,
    GarbageArguments = 4,
    SystemError = 5,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum AuthStatus {
    BadCredential = 1,
    RejectedCredential = 2,
    BadVerifier = 3,
    RejectedVerifier = 4,
    TooWeak = 5,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VersionRange {
    pub low: u32,
    pub high: u32,
}

impl VersionRange {
    pub fn exact(version: u32) -> Self {
        Self {
            low: version,
            high: version,
        }
    }
}

/// Starts an accepted reply. Typed result encoders append directly after the
/// header, avoiding a temporary body buffer and a second copy.
pub(crate) fn accepted_reply_encoder(xid: u32, status: AcceptStatus, body_capacity: usize) -> Encoder {
    let mut reply = Encoder::with_capacity(ACCEPTED_REPLY_HEADER_SIZE.saturating_add(body_capacity));
    reply.write_u32(xid);
    reply.write_u32(REPLY);
    reply.write_u32(MSG_ACCEPTED);
    reply.write_u32(AUTH_NONE);
    reply.write_u32(0);
    reply.write_u32(status as u32);
    reply
}

pub(crate) fn accepted_reply(xid: u32, status: AcceptStatus, body: &[u8]) -> Vec<u8> {
    let mut reply = accepted_reply_encoder(xid, status, body.len());
    reply.write_fixed(body);
    reply.into_bytes()
}

pub(crate) fn program_mismatch(xid: u32, supported: VersionRange) -> Vec<u8> {
    let mut reply = accepted_reply_encoder(xid, AcceptStatus::ProgramMismatch, 8);
    reply.write_u32(supported.low);
    reply.write_u32(supported.high);
    reply.into_bytes()
}

/// Rejects a call whose RPC protocol version is not 2.
pub(crate) fn rpc_mismatch(xid: u32) -> Vec<u8> {
    let mut reply = Encoder::with_capacity(24);
    reply.write_u32(xid);
    reply.write_u32(REPLY);
    reply.write_u32(MSG_DENIED);
    reply.write_u32(RPC_MISMATCH);
    reply.write_u32(RPC_VERSION);
    reply.write_u32(RPC_VERSION);
    reply.into_bytes()
}

pub(crate) fn auth_error(xid: u32, status: AuthStatus) -> Vec<u8> {
    let mut reply = Encoder::with_capacity(20);
    reply.write_u32(xid);
    reply.write_u32(REPLY);
    reply.write_u32(MSG_DENIED);
    reply.write_u32(AUTH_ERROR);
    reply.write_u32(status as u32);
    reply.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(bytes: &[u8]) -> Vec<u32> {
        bytes
            .chunks_exact(4)
            .map(|word| u32::from_be_bytes(word.try_into().unwrap()))
            .collect()
    }

    #[test]
    fn reply_shapes_match_rfc_5531() {
        assert_eq!(words(&accepted_reply(7, AcceptStatus::GarbageArguments, &[])), [7, 1, 0, 0, 0, 4]);
        assert_eq!(accepted_reply(7, AcceptStatus::Success, &[]).len(), ACCEPTED_REPLY_HEADER_SIZE);
        assert_eq!(words(&accepted_reply(7, AcceptStatus::Success, &9u32.to_be_bytes())), [7, 1, 0, 0, 0, 0, 9]);
        assert_eq!(words(&program_mismatch(8, VersionRange { low: 2, high: 3 })), [8, 1, 0, 0, 0, 2, 2, 3]);
        assert_eq!(words(&rpc_mismatch(9)), [9, 1, 1, 0, 2, 2]);
        assert_eq!(words(&auth_error(10, AuthStatus::TooWeak)), [10, 1, 1, 1, 5]);
    }
}
