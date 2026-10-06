//! Files under a root directory. `Private` = owner-only (`0600` files, `0700`
//! directories); existing private data that group/others can access, or that is
//! a symlink, is refused (`Insecure`) rather than used.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use chitala_platform::{AppendLog, Claim, PlatformError, Result, Storage, StoragePath, Visibility};

/// How long a busy claim is tried again before its holder is taken to keep it.
pub const CLAIM_WAIT: Duration = Duration::from_secs(2);

pub struct FsStorage {
    root: PathBuf,
}

fn file_mode(v: Visibility) -> u32 {
    match v {
        Visibility::Private => 0o600,
        Visibility::Shared => 0o644,
    }
}

impl FsStorage {
    pub fn new(root: &Path) -> Result<Self> {
        fs::create_dir_all(root)?;
        Ok(Self { root: fs::canonicalize(root)? })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn file(&self, p: &StoragePath) -> PathBuf {
        p.as_str().split('/').fold(self.root.clone(), |acc, seg| acc.join(seg))
    }

    /// Refuse symlinks and, for private data, any access by group/others.
    fn check(&self, f: &Path, wanted: Visibility) -> Result<()> {
        let meta = fs::symlink_metadata(f)?;
        if meta.file_type().is_symlink() {
            return Err(PlatformError::Insecure(format!("{} is a symlink", f.display())));
        }
        if wanted == Visibility::Private {
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                return Err(PlatformError::Insecure(format!(
                    "{} has permissions {mode:03o}; private data must not be accessible by group/others (chmod 600)",
                    f.display()
                )));
            }
        }
        Ok(())
    }

    fn parent_dir(f: &Path) -> Result<&Path> {
        f.parent().ok_or_else(|| PlatformError::Invalid(format!("{} has no parent", f.display())))
    }
}

/// A claim held by an open, locked file.
struct FsClaim {
    _file: File,
}

impl Claim for FsClaim {}

struct FsLog {
    file: File,
}

impl AppendLog for FsLog {
    fn append(&mut self, record: &[u8]) -> Result<()> {
        self.file.write_all(record)?;
        self.file.flush()?;
        self.file.sync_data()?;
        Ok(())
    }
}

impl Storage for FsStorage {
    fn read(&self, p: &StoragePath, visibility: Visibility) -> Result<Option<Vec<u8>>> {
        let f = self.file(p);
        match fs::symlink_metadata(&f) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
            Ok(_) => {}
        }
        self.check(&f, visibility)?;
        Ok(Some(fs::read(&f)?))
    }

    fn write_atomic(&self, p: &StoragePath, data: &[u8], visibility: Visibility) -> Result<()> {
        let f = self.file(p);
        let dir = Self::parent_dir(&f)?;
        fs::create_dir_all(dir)?;
        let tmp = f.with_extension("tmp");
        let _ = fs::remove_file(&tmp);
        {
            let mut out = OpenOptions::new().write(true).create_new(true).mode(file_mode(visibility)).open(&tmp)?;
            out.write_all(data)?;
            out.sync_all()?;
        }
        fs::rename(&tmp, &f)?;
        // make the rename itself durable
        File::open(dir)?.sync_all()?;
        Ok(())
    }

    fn create_new(&self, p: &StoragePath, data: &[u8], visibility: Visibility) -> Result<()> {
        let f = self.file(p);
        fs::create_dir_all(Self::parent_dir(&f)?)?;
        let mut out = OpenOptions::new().write(true).create_new(true).mode(file_mode(visibility)).open(&f)?;
        out.write_all(data)?;
        out.sync_all()?;
        Ok(())
    }

    fn open_append(&self, p: &StoragePath, visibility: Visibility) -> Result<Box<dyn AppendLog>> {
        let f = self.file(p);
        if fs::symlink_metadata(&f).is_ok() {
            self.check(&f, visibility)?;
        } else {
            fs::create_dir_all(Self::parent_dir(&f)?)?;
        }
        let file = OpenOptions::new().create(true).append(true).mode(file_mode(visibility)).open(&f)?;
        Ok(Box::new(FsLog { file }))
    }

    fn exists(&self, p: &StoragePath) -> Result<bool> {
        Ok(fs::symlink_metadata(self.file(p)).is_ok())
    }

    fn remove(&self, p: &StoragePath) -> Result<()> {
        Ok(fs::remove_file(self.file(p))?)
    }

    fn ensure_dir(&self, p: &StoragePath, visibility: Visibility) -> Result<()> {
        let d = self.file(p);
        if fs::symlink_metadata(&d).is_err() {
            let mut b = fs::DirBuilder::new();
            b.recursive(true).mode(match visibility {
                Visibility::Private => 0o700,
                Visibility::Shared => 0o755,
            });
            b.create(&d)?;
        }
        let meta = fs::symlink_metadata(&d)?;
        if !meta.file_type().is_dir() {
            return Err(PlatformError::Insecure(format!("{} is not a directory", d.display())));
        }
        if visibility == Visibility::Private && meta.permissions().mode() & 0o077 != 0 {
            return Err(PlatformError::Insecure(format!("{} is accessible by group/others (chmod 700)", d.display())));
        }
        Ok(())
    }

    /// An advisory lock (`flock`) on a private lock file, held by the open
    /// file: the kernel ends it with the process, however it ends.
    ///
    /// The lock belongs to the open file, and a child process holds a copy of
    /// every open file from its fork until it executes its program (the files
    /// are opened close-on-exec, so not after). A claim just released while
    /// another thread starts a process can therefore look held for that
    /// moment. A busy lock is tried again for up to [`CLAIM_WAIT`]: a holder
    /// that keeps it (another node) is still refused.
    fn claim(&self, p: &StoragePath) -> Result<Box<dyn Claim>> {
        let f = self.file(p);
        fs::create_dir_all(Self::parent_dir(&f)?)?;
        let file = OpenOptions::new().read(true).write(true).create(true).truncate(false).mode(0o600).open(&f)?;
        self.check(&f, Visibility::Private)?;
        let deadline = Instant::now() + CLAIM_WAIT;
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(Box::new(FsClaim { _file: file })),
                Err(std::fs::TryLockError::WouldBlock) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(std::fs::TryLockError::WouldBlock) => {
                    return Err(PlatformError::AlreadyExists(format!("{} is claimed by another process", f.display())))
                }
                Err(std::fs::TryLockError::Error(e)) => return Err(e.into()),
            }
        }
    }
}
