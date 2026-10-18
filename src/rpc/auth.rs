use crate::rpc::codec::{DecodeError, Decoder};
use crate::vfs::Principal;

pub const AUTH_NONE: u32 = 0;
pub const AUTH_SYS: u32 = 1;
pub const MAX_MACHINE_NAME: usize = 255;
pub const MAX_GROUPS: usize = 16;

pub fn decode_principal(flavor: u32, body: &[u8]) -> Result<Principal, DecodeError> {
    match flavor {
        AUTH_NONE => {
            if body.is_empty() {
                Ok(Principal::Anonymous)
            } else {
                Err(DecodeError::TrailingBytes)
            }
        },
        AUTH_SYS => {
            let mut decoder = Decoder::new(body);
            let _stamp = decoder.read_u32()?;
            let machine_name = decoder.read_string("AUTH_SYS machine name", MAX_MACHINE_NAME)?;
            let uid = decoder.read_u32()?;
            let gid = decoder.read_u32()?;
            let supplementary_gids = decoder.read_array("AUTH_SYS groups", MAX_GROUPS, |decoder| decoder.read_u32())?;
            decoder.finish()?;
            Ok(Principal::AuthSys {
                uid,
                gid,
                supplementary_gids,
                machine_name,
            })
        },
        value => Err(DecodeError::InvalidDiscriminant {
            kind: "authentication flavor",
            value,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::codec::Encoder;

    #[test]
    fn auth_sys_credentials_decode_every_identity_field() {
        let mut body = Encoder::new();
        body.write_u32(0x1234);
        body.write_opaque(b"host").unwrap();
        body.write_u32(1000);
        body.write_u32(100);
        body.write_u32(2);
        body.write_u32(10);
        body.write_u32(20);
        assert_eq!(
            decode_principal(AUTH_SYS, &body.into_bytes()),
            Ok(Principal::AuthSys {
                uid: 1000,
                gid: 100,
                supplementary_gids: vec![10, 20],
                machine_name: b"host".to_vec(),
            })
        );
    }

    #[test]
    fn malformed_and_unsupported_credentials_are_rejected() {
        assert_eq!(decode_principal(AUTH_NONE, &[]), Ok(Principal::Anonymous));
        assert_eq!(decode_principal(AUTH_NONE, &[0; 4]), Err(DecodeError::TrailingBytes));
        assert_eq!(
            decode_principal(6, &[]),
            Err(DecodeError::InvalidDiscriminant {
                kind: "authentication flavor",
                value: 6,
            })
        );
        let mut trailing = Encoder::new();
        trailing.write_u32(0);
        trailing.write_opaque(b"").unwrap();
        trailing.write_u32(0);
        trailing.write_u32(0);
        trailing.write_u32(0);
        trailing.write_u32(0);
        assert_eq!(decode_principal(AUTH_SYS, &trailing.into_bytes()), Err(DecodeError::TrailingBytes));
        let mut long_name = Encoder::new();
        long_name.write_u32(0);
        long_name.write_opaque(&[b'x'; MAX_MACHINE_NAME + 1]).unwrap();
        assert!(matches!(
            decode_principal(AUTH_SYS, &long_name.into_bytes()),
            Err(DecodeError::LimitExceeded { .. })
        ));
    }

    #[test]
    fn auth_sys_group_limit_is_enforced() {
        let mut body = Encoder::new();
        body.write_u32(0);
        body.write_opaque(b"client").unwrap();
        body.write_u32(1);
        body.write_u32(1);
        body.write_u32((MAX_GROUPS + 1) as u32);
        for _ in 0..=MAX_GROUPS {
            body.write_u32(1);
        }
        assert!(matches!(decode_principal(AUTH_SYS, &body.into_bytes()), Err(DecodeError::LimitExceeded { .. })));
    }
}
