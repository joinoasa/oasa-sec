//! Safe handling of secret files: owner-only, written atomically, never
//! read through a symlink.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::{Error, Result};

/// Make sure `dir` is a safe place for secrets. Creates it (mode 0700) if it
/// doesn't exist. If it already exists, refuses it when other users could
/// write into it, rather than changing permissions on someone's folder.
pub(crate) fn ensure_private_dir(dir: &Path) -> Result<()> {
    if !dir.exists() {
        fs::create_dir_all(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        }
        return Ok(());
    }
    if !dir.is_dir() {
        return Err(Error::BadKeyFile(format!(
            "{} is not a directory",
            dir.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(dir)?.permissions().mode();
        if mode & 0o022 != 0 {
            return Err(Error::BadKeyFile(format!(
                "{} can be written by other users (mode {:o}); use a private directory",
                dir.display(),
                mode & 0o777
            )));
        }
    }
    Ok(())
}

/// Write `bytes` to `path` atomically, owner-only. Replaces any existing file.
/// A crash leaves either the old file or the new one, never a partial one.
pub(crate) fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = write_temp(path, bytes)?;
    fs::rename(&tmp, path).inspect_err(|_| {
        let _ = fs::remove_file(&tmp);
    })?;
    sync_parent(path);
    Ok(())
}

/// Like [`write_private_file`] but fails if `path` already exists, so two
/// processes can never overwrite each other's keys.
pub(crate) fn write_new_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = write_temp(path, bytes)?;
    let r = fs::hard_link(&tmp, path);
    let _ = fs::remove_file(&tmp);
    r.map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            Error::BadKeyFile(format!(
                "{} already exists; not overwriting",
                path.display()
            ))
        } else {
            e.into()
        }
    })?;
    sync_parent(path);
    Ok(())
}

/// Read a secret file. Refuses symlinks and files others can read or write.
/// Checks and reads the same open file, so it can't be swapped in between.
pub(crate) fn read_private_file(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let link = fs::symlink_metadata(path)?;
    if link.file_type().is_symlink() {
        return Err(Error::BadKeyFile(format!(
            "{} is a symlink; refusing",
            path.display()
        )));
    }
    let mut f = fs::File::open(path)?;
    let meta = f.metadata()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if meta.dev() != link.dev() || meta.ino() != link.ino() {
            return Err(Error::BadKeyFile(format!(
                "{} changed while opening",
                path.display()
            )));
        }
        let mode = meta.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(Error::BadKeyFile(format!(
                "{} can be read by others (mode {:o}); run chmod 600 on it",
                path.display(),
                mode & 0o777
            )));
        }
    }
    if !meta.is_file() || meta.len() > 1 << 20 {
        return Err(Error::BadKeyFile(format!(
            "{} is not a small regular file",
            path.display()
        )));
    }
    let mut buf = Zeroizing::new(Vec::with_capacity(meta.len() as usize));
    f.read_to_end(&mut buf)?;
    Ok(buf)
}

fn write_temp(path: &Path, bytes: &[u8]) -> Result<PathBuf> {
    let dir = path.parent().unwrap_or(Path::new("."));
    ensure_private_dir(dir)?;
    let mut r = [0u8; 6];
    getrandom::fill(&mut r).map_err(|e| Error::Io(std::io::Error::other(e)))?;
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("key");
    let tmp = dir.join(format!(
        ".{name}.tmp-{}",
        data_encoding::HEXLOWER.encode(&r)
    ));
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp)?;
    let res = (|| {
        f.write_all(bytes)?;
        f.sync_all()
    })();
    if let Err(e) = res {
        let _ = fs::remove_file(&tmp);
        return Err(e.into());
    }
    Ok(tmp)
}

fn sync_parent(path: &Path) {
    if let Some(dir) = path.parent()
        && let Ok(d) = fs::File::open(dir)
    {
        let _ = d.sync_all();
    }
}

/// A fresh, empty, private temporary directory for tests.
#[cfg(test)]
pub(crate) fn tempdir(name: &str) -> PathBuf {
    let mut r = [0u8; 8];
    getrandom::fill(&mut r).unwrap();
    let p = std::env::temp_dir().join(format!(
        "oasa-sec-test-{name}-{}",
        data_encoding::HEXLOWER.encode(&r)
    ));
    ensure_private_dir(&p).unwrap();
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_read_and_no_overwrite() {
        let d = tempdir("files");
        let p = d.join("secret");
        write_new_private_file(&p, b"one").unwrap();
        assert!(write_new_private_file(&p, b"two").is_err());
        assert_eq!(&read_private_file(&p).unwrap()[..], b"one");
        write_private_file(&p, b"three").unwrap();
        assert_eq!(&read_private_file(&p).unwrap()[..], b"three");
        // No temp files left behind.
        assert_eq!(fs::read_dir(&d).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlinks_and_open_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempdir("files-perm");
        let p = d.join("secret");
        write_private_file(&p, b"x").unwrap();
        std::os::unix::fs::symlink(&p, d.join("link")).unwrap();
        assert!(read_private_file(&d.join("link")).is_err());
        fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_private_file(&p).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn refuses_shared_directory_without_changing_it() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempdir("files-dir");
        fs::set_permissions(&d, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(write_private_file(&d.join("k"), b"x").is_err());
        let mode = fs::metadata(&d).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o777, "must not chmod a directory it didn't create");
    }
}
