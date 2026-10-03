//! Unix-socket IPC. Endpoint `name` lives at `<root>/<name>`; paths longer than
//! a Unix socket allows move to `/tmp/chitala-<hash of root>/<hash>.sock`, a private
//! (0700, owner-checked, non-symlink) directory — otherwise another local user
//! could pre-create the path and impersonate the node (v10 §1).

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use chitala_platform::{Endpoint, IpcListener, IpcStream, IpcTransport, PlatformError, Result};
use sha2::{Digest, Sha256};

/// Longest socket path used as is (SUN_LEN is ~104 on macOS, 108 on Linux).
pub const MAX_SOCKET_PATH: usize = 100;

pub struct UnixIpc {
    root: PathBuf,
    owner: u32,
}

impl UnixIpc {
    pub fn new(root: &Path) -> Result<Self> {
        let root = fs::canonicalize(root)?;
        let owner = fs::metadata(&root)?.uid();
        Ok(Self { root, owner })
    }

    pub fn socket_path(&self, endpoint: &Endpoint) -> Result<PathBuf> {
        let wanted = self.root.join(endpoint.as_str());
        if wanted.as_os_str().len() < MAX_SOCKET_PATH {
            return Ok(wanted);
        }
        // one private directory per platform root, named after the root (the
        // owner's uid is only compared, never written into names or messages)
        let tag = hex::encode(&Sha256::digest(self.root.as_os_str().as_encoded_bytes())[..8]);
        let private = PathBuf::from(format!("/tmp/chitala-{tag}"));
        match fs::DirBuilder::new().mode(0o700).create(&private) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
        let m = fs::symlink_metadata(&private)?;
        if !m.file_type().is_dir() || m.uid() != self.owner || m.permissions().mode() & 0o077 != 0 {
            return Err(PlatformError::Insecure(format!(
                "{} is not a private directory (a real directory, mode 700, owned by the owner of {}); \
                 refusing to place a socket there",
                private.display(),
                self.root.display()
            )));
        }
        let digest = Sha256::digest(wanted.as_os_str().as_encoded_bytes());
        Ok(private.join(format!("{}.sock", hex::encode(&digest[..8]))))
    }
}

struct Stream(UnixStream);

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

impl IpcStream for Stream {
    fn try_clone(&self) -> Result<Box<dyn IpcStream>> {
        Ok(Box::new(Stream(self.0.try_clone()?)))
    }
    fn set_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        self.0.set_read_timeout(timeout)?;
        self.0.set_write_timeout(timeout)?;
        Ok(())
    }
}

struct Listener(UnixListener);

impl IpcListener for Listener {
    fn accept(&self) -> Result<Box<dyn IpcStream>> {
        Ok(Box::new(Stream(self.0.accept()?.0)))
    }
}

impl IpcTransport for UnixIpc {
    fn listen(&self, endpoint: &Endpoint) -> Result<Box<dyn IpcListener>> {
        let socket = self.socket_path(endpoint)?;
        match fs::symlink_metadata(&socket) {
            Ok(m) if m.file_type().is_socket() => {
                // a stale socket from a previous run; refuse if someone is listening
                if UnixStream::connect(&socket).is_ok() {
                    return Err(PlatformError::AlreadyExists(format!("{} is in use", socket.display())));
                }
                fs::remove_file(&socket)?;
            }
            Ok(_) => {
                return Err(PlatformError::Insecure(format!(
                    "{} exists and is not a socket; refusing to replace it",
                    socket.display()
                )))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let listener = UnixListener::bind(&socket)?;
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
        Ok(Box::new(Listener(listener)))
    }

    fn connect(&self, endpoint: &Endpoint) -> Result<Box<dyn IpcStream>> {
        let socket = self.socket_path(endpoint)?;
        let stream = UnixStream::connect(&socket)
            .map_err(|e| PlatformError::Unreachable(format!("{}: {e}", socket.display())))?;
        Ok(Box::new(Stream(stream)))
    }

    fn describe(&self, endpoint: &Endpoint) -> String {
        self.socket_path(endpoint).map(|p| p.display().to_string()).unwrap_or_else(|e| e.to_string())
    }
}
