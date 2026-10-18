#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Procedure {
    Null = 0,
    GetAttr = 1,
    SetAttr = 2,
    Lookup = 3,
    Access = 4,
    ReadLink = 5,
    Read = 6,
    Write = 7,
    Create = 8,
    Mkdir = 9,
    Symlink = 10,
    Mknod = 11,
    Remove = 12,
    Rmdir = 13,
    Rename = 14,
    Link = 15,
    ReadDir = 16,
    ReadDirPlus = 17,
    FsStat = 18,
    FsInfo = 19,
    PathConf = 20,
    Commit = 21,
}

impl Procedure {
    pub fn from_wire(value: u32) -> Option<Self> {
        Some(match value {
            0 => Self::Null,
            1 => Self::GetAttr,
            2 => Self::SetAttr,
            3 => Self::Lookup,
            4 => Self::Access,
            5 => Self::ReadLink,
            6 => Self::Read,
            7 => Self::Write,
            8 => Self::Create,
            9 => Self::Mkdir,
            10 => Self::Symlink,
            11 => Self::Mknod,
            12 => Self::Remove,
            13 => Self::Rmdir,
            14 => Self::Rename,
            15 => Self::Link,
            16 => Self::ReadDir,
            17 => Self::ReadDirPlus,
            18 => Self::FsStat,
            19 => Self::FsInfo,
            20 => Self::PathConf,
            21 => Self::Commit,
            _ => return None,
        })
    }

    /// The RFC 1813 procedure name, used in tracing.
    pub fn name(self) -> &'static str {
        match self {
            Self::Null => "NULL",
            Self::GetAttr => "GETATTR",
            Self::SetAttr => "SETATTR",
            Self::Lookup => "LOOKUP",
            Self::Access => "ACCESS",
            Self::ReadLink => "READLINK",
            Self::Read => "READ",
            Self::Write => "WRITE",
            Self::Create => "CREATE",
            Self::Mkdir => "MKDIR",
            Self::Symlink => "SYMLINK",
            Self::Mknod => "MKNOD",
            Self::Remove => "REMOVE",
            Self::Rmdir => "RMDIR",
            Self::Rename => "RENAME",
            Self::Link => "LINK",
            Self::ReadDir => "READDIR",
            Self::ReadDirPlus => "READDIRPLUS",
            Self::FsStat => "FSSTAT",
            Self::FsInfo => "FSINFO",
            Self::PathConf => "PATHCONF",
            Self::Commit => "COMMIT",
        }
    }

    /// Whether re-executing a retransmitted call could observe or cause a
    /// different outcome than the original execution. Only these procedures
    /// need the duplicate-request cache's at-most-once guarantee; every other
    /// procedure is simply executed again when it is retransmitted.
    pub fn is_non_idempotent(self) -> bool {
        matches!(
            self,
            Self::SetAttr
                | Self::Write
                | Self::Create
                | Self::Mkdir
                | Self::Symlink
                | Self::Mknod
                | Self::Remove
                | Self::Rmdir
                | Self::Rename
                | Self::Link
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_numbers_names_and_idempotency_are_consistent() {
        for value in 0..crate::nfs3::types::PROCEDURE_COUNT {
            let procedure = Procedure::from_wire(value).unwrap();
            assert_eq!(procedure as u32, value);
            assert!(!procedure.name().is_empty());
        }
        assert_eq!(Procedure::from_wire(crate::nfs3::types::PROCEDURE_COUNT), None);
        let non_idempotent: Vec<_> = (0..crate::nfs3::types::PROCEDURE_COUNT)
            .filter_map(Procedure::from_wire)
            .filter(|procedure| procedure.is_non_idempotent())
            .map(Procedure::name)
            .collect();
        assert_eq!(
            non_idempotent,
            ["SETATTR", "WRITE", "CREATE", "MKDIR", "SYMLINK", "MKNOD", "REMOVE", "RMDIR", "RENAME", "LINK"]
        );
    }
}
