#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use nfsembed::handles::HandleCodec;
use nfsembed::nfs3::codec::{encode_readdir_reply, ReadDirLimits, FATTR3_SIZE};
use nfsembed::nfs3::procedures::{NfsArguments, ReadDirEntry, ReadDirEntryExtension};
use nfsembed::rpc::codec::{Decoder, Encoder};
use nfsembed::vfs::{ExportId, FileAttributes, FileType, NfsTime, ObjectKey};

const TOO_SMALL: u32 = 10005;

fn attributes() -> FileAttributes {
    FileAttributes {
        file_type: FileType::Regular,
        mode: 0o644,
        links: 1,
        uid: 0,
        gid: 0,
        size: 0,
        used: 0,
        device: None,
        fs_id: 1,
        file_id: 2,
        access_time: NfsTime::default(),
        modify_time: NfsTime::default(),
        change_time: NfsTime::default(),
    }
}

fuzz_target!(|data: &[u8]| {
    static HANDLES: OnceLock<HandleCodec> = OnceLock::new();
    let handles = HANDLES.get_or_init(HandleCodec::random);
    for procedure in [16, 17] {
        if let Ok(arguments) = NfsArguments::decode(procedure, data, 4096) {
            let handle = match arguments {
                NfsArguments::ReadDir(arguments) => arguments.directory,
                NfsArguments::ReadDirPlus(arguments) => arguments.directory,
                _ => Vec::new(),
            };
            let _ = handles.decode(ExportId(1), &handle);
        }
    }

    // Drive the production READDIR/READDIRPLUS encoder with fuzzed limits and
    // entries, then decode the reply and check every sizing invariant.
    let byte = |index: usize| data.get(index).copied().unwrap_or_default();
    let plus = byte(0) & 1 == 1;
    let max_size = usize::from(u16::from_be_bytes([byte(1), byte(2)]));
    let directory_size = plus.then(|| usize::from(u16::from_be_bytes([byte(3), byte(4)])));
    let directory_attributes = (byte(5) & 1 == 1).then(attributes);
    let eof = byte(5) & 2 == 2;
    let handle = handles.encode(
        ExportId(1),
        ObjectKey {
            file_id: u64::from(byte(6)),
            generation: 1,
        },
    );
    let entries: Vec<ReadDirEntry> = data
        .get(7..)
        .unwrap_or_default()
        .chunks(9)
        .take(64)
        .enumerate()
        .map(|(index, chunk)| ReadDirEntry {
            file_id: index as u64 + 1,
            name: if chunk.len() > 1 {
                chunk[1..].to_vec()
            } else {
                vec![b'x']
            },
            cookie: index as u64 + 1,
            extension: if plus {
                ReadDirEntryExtension::Plus {
                    attributes: (chunk[0] & 1 == 1).then(attributes),
                    handle: (chunk[0] & 2 == 2).then(|| handle.to_vec()),
                }
            } else {
                ReadDirEntryExtension::Basic
            },
        })
        .collect();
    let limits = ReadDirLimits {
        max_size,
        directory_size,
    };
    let mut encoder = Encoder::new();
    encode_readdir_reply(&mut encoder, directory_attributes.as_ref(), [0; 8], entries.clone(), eof, limits).unwrap();
    let reply = encoder.into_bytes();

    let mut decoder = Decoder::new(&reply);
    match decoder.read_u32().unwrap() {
        0 => {
            assert!(reply.len() - 4 <= max_size);
            if decoder.read_bool().unwrap() {
                decoder.read_fixed::<FATTR3_SIZE>().unwrap();
            }
            assert_eq!(decoder.read_fixed::<8>().unwrap(), [0; 8]);
            let mut kept = 0;
            let mut directory_bytes = 0;
            while decoder.read_bool().unwrap() {
                let expected = &entries[kept];
                let start = decoder.position();
                assert_eq!(decoder.read_u64().unwrap(), expected.file_id);
                assert_eq!(decoder.read_opaque("fuzz READDIR name", 8).unwrap(), expected.name);
                assert_eq!(decoder.read_u64().unwrap(), expected.cookie);
                directory_bytes += 4 + decoder.position() - start;
                if plus {
                    if decoder.read_bool().unwrap() {
                        decoder.read_fixed::<FATTR3_SIZE>().unwrap();
                    }
                    if decoder.read_bool().unwrap() {
                        assert_eq!(decoder.read_opaque("fuzz READDIR handle", 64).unwrap(), handle);
                    }
                }
                kept += 1;
            }
            if let Some(limit) = directory_size {
                assert!(kept == 0 || directory_bytes + 4 <= limit);
            }
            assert_eq!(decoder.read_bool().unwrap(), eof && kept == entries.len());
            decoder.finish().unwrap();
        },
        TOO_SMALL => {
            assert!(max_size < 20 || !entries.is_empty());
            if decoder.read_bool().unwrap() {
                decoder.read_fixed::<FATTR3_SIZE>().unwrap();
            }
            decoder.finish().unwrap();
        },
        status => panic!("unexpected READDIR status {status}"),
    }
});
