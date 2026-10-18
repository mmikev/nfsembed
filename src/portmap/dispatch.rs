use super::{mapping, IPPROTO_TCP};

pub fn get_port(request: &mapping, nfs_port: u16, mount_port: u16) -> u32 {
    if request.prot != IPPROTO_TCP {
        return 0;
    }
    match (request.prog, request.vers) {
        (crate::nfs3::types::PROGRAM, crate::nfs3::types::VERSION) => u32::from(nfs_port),
        (crate::mount3::types::PROGRAM, crate::mount3::types::VERSION) => u32::from(mount_port),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::codec::{DecodeError, Encoder};

    #[test]
    fn getport_arguments_decode_exactly() {
        let mut arguments = Encoder::new();
        for value in [100_003, 3, super::IPPROTO_TCP, 0] {
            arguments.write_u32(value);
        }
        let arguments = arguments.into_bytes();
        let request = mapping::decode(&arguments).unwrap();
        assert_eq!((request.prog, request.vers, request.prot, request.port), (100_003, 3, 6, 0));
        assert_eq!(mapping::decode(&arguments[..12]).unwrap_err(), DecodeError::Truncated);
        assert_eq!(mapping::decode(&[arguments.as_slice(), &[0; 4]].concat()).unwrap_err(), DecodeError::TrailingBytes);
    }

    #[test]
    fn only_exact_tcp_nfs_and_mount_v3_mappings_are_advertised() {
        for (prog, vers, prot, expected) in [
            (crate::nfs3::types::PROGRAM, crate::nfs3::types::VERSION, super::IPPROTO_TCP, 20_049),
            (crate::mount3::types::PROGRAM, crate::mount3::types::VERSION, super::IPPROTO_TCP, 20_048),
            (crate::nfs3::types::PROGRAM, crate::nfs3::types::VERSION, crate::portmap::IPPROTO_UDP, 0),
            (crate::nfs3::types::PROGRAM, 2, super::IPPROTO_TCP, 0),
            (crate::mount3::types::PROGRAM, 1, super::IPPROTO_TCP, 0),
            (100_021, 4, super::IPPROTO_TCP, 0),
        ] {
            assert_eq!(
                get_port(
                    &mapping {
                        prog,
                        vers,
                        prot,
                        port: u32::MAX,
                    },
                    20_049,
                    20_048,
                ),
                expected,
            );
        }
    }
}
