use std::sync::Arc;

use super::{AuthPolicy, ExportState, NfsServer, PortmapperMode, ServerError, ServerLimits};
use crate::vfs::{ExportId, VirtualFileSystem};

pub struct NfsServerBuilder {
    pub(crate) exports: Vec<ExportState>,
    pub(crate) limits: ServerLimits,
    pub(crate) auth_policy: AuthPolicy,
    pub(crate) portmapper: PortmapperMode,
}

impl NfsServerBuilder {
    pub(crate) fn new(vfs: Arc<dyn VirtualFileSystem>) -> Self {
        Self {
            exports: vec![ExportState {
                vfs,
                id: ExportId(1),
                path: "/".to_owned(),
            }],
            limits: ServerLimits::default(),
            auth_policy: AuthPolicy::default(),
            portmapper: PortmapperMode::Disabled,
        }
    }

    /// Sets the primary export's MOUNT path. A leading `/` is added when it
    /// is missing.
    pub fn export_name(mut self, name: impl Into<String>) -> Self {
        self.exports[0].path = absolute_export_path(name.into());
        self
    }

    pub fn export_id(mut self, export_id: ExportId) -> Self {
        self.exports[0].id = export_id;
        self
    }

    /// Adds an independent export backed by another virtual filesystem.
    pub fn add_export(mut self, export_id: ExportId, name: impl Into<String>, vfs: impl VirtualFileSystem) -> Self {
        self.push_export(export_id, name.into(), Arc::new(vfs));
        self
    }

    /// Adds an independent export from a trait object.
    pub fn add_export_arc(
        mut self,
        export_id: ExportId,
        name: impl Into<String>,
        vfs: Arc<dyn VirtualFileSystem>,
    ) -> Self {
        self.push_export(export_id, name.into(), vfs);
        self
    }

    fn push_export(&mut self, export_id: ExportId, name: String, vfs: Arc<dyn VirtualFileSystem>) {
        self.exports.push(ExportState {
            vfs,
            id: export_id,
            path: absolute_export_path(name),
        });
    }

    pub fn limits(mut self, limits: ServerLimits) -> Self {
        self.limits = limits;
        self
    }

    pub fn auth_policy(mut self, auth_policy: AuthPolicy) -> Self {
        self.auth_policy = auth_policy;
        self
    }

    pub fn portmapper(mut self, mode: PortmapperMode) -> Self {
        self.portmapper = mode;
        self
    }

    pub fn build(self) -> Result<NfsServer, ServerError> {
        self.limits.validate().map_err(ServerError::InvalidConfiguration)?;
        for (index, export) in self.exports.iter().enumerate() {
            if export.path.as_bytes().contains(&0) || export.path.len() > 1024 {
                return Err(ServerError::InvalidConfiguration("export path is invalid"));
            }
            if !export.path.starts_with('/') || (export.path.len() > 1 && export.path.ends_with('/')) {
                return Err(ServerError::InvalidConfiguration(
                    "export path must be absolute and must not have a trailing slash",
                ));
            }
            if self.exports[..index]
                .iter()
                .any(|other| other.id == export.id || other.path.as_bytes() == export.path.as_bytes())
            {
                return Err(ServerError::InvalidConfiguration("export IDs and paths must be unique"));
            }
        }
        Ok(NfsServer::from_builder(self))
    }
}

fn absolute_export_path(name: String) -> String {
    if name.starts_with('/') {
        name
    } else {
        format!("/{name}")
    }
}
