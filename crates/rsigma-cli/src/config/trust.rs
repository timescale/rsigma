//! Ownership checks for discovered config files.
//!
//! The system and user config files, and the project files found from the
//! current directory, are read only when no other account could have written
//! them: the file and its directory must belong to the invoking user or an
//! administrator. A file named with `--config` is read as given.

use std::io;
use std::path::{Path, PathBuf};

/// Who owns a file or directory, relative to the invoking user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Owner {
    /// The invoking user.
    Invoker,
    /// root on Unix; Administrators, SYSTEM, or TrustedInstaller on Windows.
    Admin,
    /// Any other account, named for the diagnostic.
    Other(String),
}

/// The ownership facts the check reads for one file or directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Facts {
    pub owner: Owner,
    /// An account other than the owner and the administrators that may
    /// write the entry, named for the diagnostic.
    pub writable_by: Option<String>,
}

/// Reads ownership facts from the filesystem. Tests substitute a fake.
pub(crate) trait Probe {
    /// The facts for `path`, following symlinks.
    fn facts(&self, path: &Path) -> io::Result<Facts>;

    /// An identifier of the filesystem holding the directory `path`, where
    /// the platform has one.
    fn device(&self, path: &Path) -> Option<u64>;
}

/// The administrators a trusted file may also belong to, as the diagnostic
/// names them.
#[cfg(not(windows))]
const ADMINS: &str = "root";
#[cfg(windows)]
const ADMINS: &str = "Administrators or SYSTEM";

/// Windows grants every authenticated user write access to new folders on
/// secondary drives, so a project checkout there cannot pass a write check.
/// Unix modes carry no such default.
const PROJECT_FILE_WRITE_CHECKED: bool = cfg!(not(windows));

/// A Windows config directory under `%ProgramData%` inherits the right of
/// every user to create files in it; the owner check on each file covers a
/// file created that way.
const DIRECTORY_WRITE_CHECKED: bool = cfg!(not(windows));

/// Why the discovered config file at `path` may not be read, or `None` when
/// it may. `trusted` is set for the system and user layers.
pub(crate) fn untrusted_reason(path: &Path, trusted: bool, probe: &dyn Probe) -> Option<String> {
    let check = |entry: &Path, what: String, write_checked: bool| -> Option<String> {
        let facts = match probe.facts(entry) {
            Ok(facts) => facts,
            Err(error) => return Some(format!("could not read the owner of {what}: {error}")),
        };
        if let Owner::Other(name) = &facts.owner {
            return Some(format!("{what} is owned by {name}, not by you or {ADMINS}"));
        }
        match facts.writable_by {
            Some(who) if write_checked => Some(format!("{what} is writable by {who}")),
            _ => None,
        }
    };

    if let Some(reason) = check(
        path,
        "the file".to_string(),
        trusted || PROJECT_FILE_WRITE_CHECKED,
    ) {
        return Some(reason);
    }
    for dir in directories(path) {
        let what = format!("its directory {}", dir.display());
        if let Some(reason) = check(&dir, what, DIRECTORY_WRITE_CHECKED) {
            return Some(reason);
        }
    }
    None
}

/// The directory holding `path`, and the one holding its target when `path`
/// is a symlink into another directory. Whoever can write either one can
/// replace the file.
fn directories(path: &Path) -> Vec<PathBuf> {
    let parent = |p: &Path| match p.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let mut dirs = vec![parent(path)];
    if let Ok(real) = std::fs::canonicalize(path) {
        let real_dir = parent(&real);
        let same = std::fs::canonicalize(&dirs[0]).is_ok_and(|dir| dir == real_dir);
        if !same {
            dirs.push(real_dir);
        }
    }
    dirs
}

/// The [`Probe`] for the running platform.
pub(crate) struct SystemProbe;

#[cfg(unix)]
impl Probe for SystemProbe {
    fn facts(&self, path: &Path) -> io::Result<Facts> {
        use std::os::unix::fs::MetadataExt;
        let metadata = std::fs::metadata(path)?;
        Ok(unix::facts(
            metadata.uid(),
            metadata.gid(),
            metadata.mode(),
            unix::Invoker::current(),
        ))
    }

    fn device(&self, path: &Path) -> Option<u64> {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(path).ok().map(|metadata| metadata.dev())
    }
}

#[cfg(windows)]
impl Probe for SystemProbe {
    fn facts(&self, path: &Path) -> io::Result<Facts> {
        windows::facts(path)
    }

    fn device(&self, _path: &Path) -> Option<u64> {
        None
    }
}

#[cfg(not(any(unix, windows)))]
impl Probe for SystemProbe {
    fn facts(&self, _path: &Path) -> io::Result<Facts> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "file ownership is not available on this platform",
        ))
    }

    fn device(&self, _path: &Path) -> Option<u64> {
        None
    }
}

/// The trusted system config directory: `/etc/rsigma` on Unix and
/// `%ProgramData%\rsigma` on Windows, read from the known-folder API rather
/// than the environment. `None` where the platform has none.
pub(crate) fn system_config_dir() -> Option<PathBuf> {
    #[cfg(unix)]
    {
        Some(PathBuf::from("/etc/rsigma"))
    }
    #[cfg(windows)]
    {
        windows::program_data().map(|dir| dir.join("rsigma"))
    }
    #[cfg(not(any(unix, windows)))]
    {
        None
    }
}

#[cfg(unix)]
pub(crate) mod unix {
    use std::ffi::CStr;
    use std::sync::OnceLock;

    use super::{Facts, Owner};

    /// The invoking user, as the mode check needs it.
    #[derive(Debug, Clone, Copy)]
    pub(crate) struct Invoker {
        pub uid: u32,
        /// The user's primary group when no one else belongs to it (a user
        /// private group), so a group-writable file in it is still private.
        pub private_gid: Option<u32>,
    }

    impl Invoker {
        pub(crate) fn current() -> Self {
            static CURRENT: OnceLock<Invoker> = OnceLock::new();
            *CURRENT.get_or_init(|| {
                // SAFETY: geteuid has no preconditions and cannot fail.
                let uid = unsafe { libc::geteuid() };
                Invoker {
                    uid,
                    private_gid: private_group(uid),
                }
            })
        }
    }

    /// Decide ownership from a file's owner, group, and mode bits.
    pub(crate) fn facts(uid: u32, gid: u32, mode: u32, invoker: Invoker) -> Facts {
        let owner = if uid == invoker.uid {
            Owner::Invoker
        } else if uid == 0 {
            Owner::Admin
        } else {
            Owner::Other(format!("uid {uid}"))
        };
        let writable_by = if mode & 0o002 != 0 {
            Some("all users".to_string())
        } else if mode & 0o020 != 0 && invoker.private_gid != Some(gid) {
            Some(format!("group {gid}"))
        } else {
            None
        };
        Facts { owner, writable_by }
    }

    /// Run a reentrant `get*_r` lookup, growing the string buffer while it
    /// reports `ERANGE`. Returns whether an entry was found.
    fn lookup(mut call: impl FnMut(&mut [u8]) -> (libc::c_int, bool)) -> Option<Vec<u8>> {
        let mut buffer = vec![0u8; 16 * 1024];
        loop {
            let (status, found) = call(&mut buffer);
            if status == libc::ERANGE && buffer.len() < 1 << 20 {
                buffer.resize(buffer.len() * 2, 0);
                continue;
            }
            return (status == 0 && found).then_some(buffer);
        }
    }

    /// The primary group of `uid` when it is named after the user and lists
    /// no other member.
    fn private_group(uid: u32) -> Option<u32> {
        // SAFETY: an all-zero passwd is a valid value for getpwuid_r to fill.
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let user_buffer = lookup(|buffer| {
            let mut result = std::ptr::null_mut();
            // SAFETY: every pointer is valid for the call; the strings it
            // stores in `pwd` point into `buffer`, which is returned and kept
            // alive while they are read.
            let status = unsafe {
                libc::getpwuid_r(
                    uid,
                    &mut pwd,
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    &mut result,
                )
            };
            (status, !result.is_null())
        })?;
        // SAFETY: getpwuid_r succeeded, so pw_name is a NUL-terminated string
        // inside `user_buffer`.
        let user = unsafe { CStr::from_ptr(pwd.pw_name) }.to_owned();
        let gid = pwd.pw_gid;
        drop(user_buffer);

        // SAFETY: an all-zero group is a valid value for getgrgid_r to fill.
        let mut grp: libc::group = unsafe { std::mem::zeroed() };
        let group_buffer = lookup(|buffer| {
            let mut result = std::ptr::null_mut();
            // SAFETY: as for getpwuid_r above.
            let status = unsafe {
                libc::getgrgid_r(
                    gid,
                    &mut grp,
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    &mut result,
                )
            };
            (status, !result.is_null())
        })?;
        // SAFETY: getgrgid_r succeeded, so gr_name is a NUL-terminated string
        // and gr_mem a NULL-terminated array of them, all inside
        // `group_buffer`, which lives until the end of this function.
        let private = unsafe {
            let mut private = CStr::from_ptr(grp.gr_name) == user.as_c_str();
            let mut member = grp.gr_mem;
            while private && !member.is_null() && !(*member).is_null() {
                private = CStr::from_ptr(*member) == user.as_c_str();
                member = member.add(1);
            }
            private
        };
        drop(group_buffer);
        private.then_some(gid)
    }
}

#[cfg(windows)]
mod windows {
    use std::ffi::OsString;
    use std::io;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::path::{Path, PathBuf};
    use std::ptr::null_mut;
    use std::sync::OnceLock;

    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, HANDLE, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, GetAce,
        GetTokenInformation, INHERIT_ONLY_ACE, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
        PSID, TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows_sys::Win32::UI::Shell::{FOLDERID_ProgramData, SHGetKnownFolderPath};

    use super::{Facts, Owner};

    /// Accounts that administer the machine and may own a trusted file.
    const ADMIN_SIDS: [&str; 3] = [
        "S-1-5-32-544",
        "S-1-5-18",
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
    ];

    /// `CREATOR OWNER` and `OWNER RIGHTS` stand for the owner, which is
    /// checked on its own.
    const OWNER_ALIASES: [&str; 2] = ["S-1-3-0", "S-1-3-4"];

    /// Access rights that let an account change a file's content, its
    /// access list, or its owner, or delete it.
    const WRITE_RIGHTS: u32 = 0x0000_0002 // FILE_WRITE_DATA
        | 0x0000_0004 // FILE_APPEND_DATA
        | 0x0001_0000 // DELETE
        | 0x0004_0000 // WRITE_DAC
        | 0x0008_0000 // WRITE_OWNER
        | 0x1000_0000 // GENERIC_ALL
        | 0x4000_0000; // GENERIC_WRITE

    /// Read a NUL-terminated UTF-16 string.
    ///
    /// # Safety
    ///
    /// `raw` must point at a NUL-terminated UTF-16 string.
    unsafe fn wide_to_os(raw: *const u16) -> OsString {
        let mut len = 0;
        // SAFETY: the caller guarantees a terminating NUL.
        while unsafe { *raw.add(len) } != 0 {
            len += 1;
        }
        // SAFETY: `len` units before the NUL are initialized.
        OsString::from_wide(unsafe { std::slice::from_raw_parts(raw, len) })
    }

    /// Render `sid` as `S-1-...`.
    ///
    /// # Safety
    ///
    /// `sid` must point at a valid SID.
    unsafe fn sid_string(sid: PSID) -> io::Result<String> {
        let mut raw = null_mut();
        // SAFETY: the caller guarantees `sid`; the call allocates `raw`.
        if unsafe { ConvertSidToStringSidW(sid, &mut raw) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: on success `raw` is a NUL-terminated string from LocalAlloc.
        let text = unsafe { wide_to_os(raw) }.to_string_lossy().into_owned();
        // SAFETY: `raw` was allocated by ConvertSidToStringSidW.
        unsafe { LocalFree(raw.cast()) };
        Ok(text)
    }

    /// The SID of the account running this process.
    fn current_user() -> io::Result<String> {
        static CURRENT: OnceLock<Result<String, String>> = OnceLock::new();
        CURRENT
            .get_or_init(|| read_current_user().map_err(|error| error.to_string()))
            .clone()
            .map_err(io::Error::other)
    }

    fn read_current_user() -> io::Result<String> {
        let mut token: HANDLE = null_mut();
        // SAFETY: GetCurrentProcess returns a pseudo-handle; `token` receives
        // a handle closed below.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut len = 0u32;
        // SAFETY: a size query with no buffer.
        unsafe { GetTokenInformation(token, TokenUser, null_mut(), 0, &mut len) };
        let mut buffer = vec![0u64; (len as usize).div_ceil(8)];
        // SAFETY: `buffer` holds `len` bytes, aligned for TOKEN_USER.
        let ok = unsafe {
            GetTokenInformation(token, TokenUser, buffer.as_mut_ptr().cast(), len, &mut len)
        };
        // SAFETY: `token` was opened above.
        unsafe { CloseHandle(token) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: GetTokenInformation filled `buffer` with a TOKEN_USER whose
        // SID points into the same buffer.
        unsafe {
            let user = &*buffer.as_ptr().cast::<TOKEN_USER>();
            sid_string(user.User.Sid)
        }
    }

    pub(super) fn facts(path: &Path) -> io::Result<Facts> {
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut owner: PSID = null_mut();
        let mut dacl: *mut ACL = null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
        // SAFETY: `wide` is NUL-terminated; the out pointers are valid and
        // point into `descriptor`, freed below.
        let status = unsafe {
            GetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut descriptor,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        // SAFETY: `owner` and `dacl` point into `descriptor`, alive until the
        // LocalFree below.
        let result = unsafe { read_facts(owner, dacl) };
        // SAFETY: `descriptor` was allocated by GetNamedSecurityInfoW.
        unsafe { LocalFree(descriptor.cast()) };
        result
    }

    /// # Safety
    ///
    /// `owner` must be null or a valid SID, and `dacl` null or a valid ACL.
    unsafe fn read_facts(owner: PSID, dacl: *mut ACL) -> io::Result<Facts> {
        let user = current_user()?;
        let owner = if owner.is_null() {
            Owner::Other("no account".to_string())
        } else {
            // SAFETY: the caller guarantees a valid SID.
            let sid = unsafe { sid_string(owner) }?;
            if sid == user {
                Owner::Invoker
            } else if ADMIN_SIDS.contains(&sid.as_str()) {
                Owner::Admin
            } else {
                Owner::Other(sid)
            }
        };
        if dacl.is_null() {
            return Ok(Facts {
                owner,
                writable_by: Some("every account (it has no access list)".to_string()),
            });
        }
        // SAFETY: the caller guarantees a valid ACL.
        let count = unsafe { (*dacl).AceCount };
        for index in 0..u32::from(count) {
            let mut ace = null_mut();
            // SAFETY: `index` is below the ACL's entry count.
            if unsafe { GetAce(dacl, index, &mut ace) } == 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: every entry starts with an ACE_HEADER.
            let header = unsafe { &*ace.cast::<ACE_HEADER>() };
            if u32::from(header.AceType) != ACCESS_ALLOWED_ACE_TYPE
                || u32::from(header.AceFlags) & INHERIT_ONLY_ACE != 0
            {
                continue;
            }
            // SAFETY: an access-allowed entry is an ACCESS_ALLOWED_ACE whose
            // SID starts at `SidStart`.
            let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
            if allowed.Mask & WRITE_RIGHTS == 0 {
                continue;
            }
            let sid_ptr: PSID = std::ptr::addr_of!(allowed.SidStart).cast_mut().cast();
            // SAFETY: as above.
            let sid = unsafe { sid_string(sid_ptr) }?;
            if sid != user
                && !ADMIN_SIDS.contains(&sid.as_str())
                && !OWNER_ALIASES.contains(&sid.as_str())
            {
                return Ok(Facts {
                    owner,
                    writable_by: Some(sid),
                });
            }
        }
        Ok(Facts {
            owner,
            writable_by: None,
        })
    }

    /// The `%ProgramData%` known folder.
    pub(super) fn program_data() -> Option<PathBuf> {
        let mut raw = null_mut();
        // SAFETY: the GUID is a static; `raw` receives a CoTaskMemAlloc
        // string freed below, which the API requires even on failure.
        let status =
            unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramData, 0, null_mut(), &mut raw) };
        let path = (status >= 0 && !raw.is_null())
            // SAFETY: on success `raw` is a NUL-terminated string.
            .then(|| PathBuf::from(unsafe { wide_to_os(raw) }));
        // SAFETY: `raw` is null or was allocated by SHGetKnownFolderPath.
        unsafe { CoTaskMemFree(raw.cast()) };
        path.filter(|path| path.is_absolute())
    }
}

/// A probe that reports configured facts and devices by canonical path, and
/// a private entry of the invoker on device 1 for anything else.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct FakeProbe {
    pub facts: std::collections::HashMap<PathBuf, Facts>,
    pub devices: std::collections::HashMap<PathBuf, u64>,
}

#[cfg(test)]
impl Probe for FakeProbe {
    fn facts(&self, path: &Path) -> io::Result<Facts> {
        let key = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        Ok(self.facts.get(&key).cloned().unwrap_or(Facts {
            owner: Owner::Invoker,
            writable_by: None,
        }))
    }

    fn device(&self, path: &Path) -> Option<u64> {
        let key = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        Some(self.devices.get(&key).copied().unwrap_or(1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn other_user() -> Facts {
        Facts {
            owner: Owner::Other("uid 1001".into()),
            writable_by: None,
        }
    }

    fn writable() -> Facts {
        Facts {
            owner: Owner::Invoker,
            writable_by: Some("all users".into()),
        }
    }

    fn file_in(dir: &Path) -> PathBuf {
        let path = dir.join("config.yaml");
        std::fs::write(&path, "version: 1\n").unwrap();
        path
    }

    #[test]
    fn own_and_admin_files_are_trusted() {
        let dir = tempfile::tempdir().unwrap();
        let path = file_in(dir.path());
        let mut probe = FakeProbe::default();
        assert_eq!(untrusted_reason(&path, true, &probe), None);
        probe.facts.insert(
            std::fs::canonicalize(&path).unwrap(),
            Facts {
                owner: Owner::Admin,
                writable_by: None,
            },
        );
        assert_eq!(untrusted_reason(&path, false, &probe), None);
    }

    #[test]
    fn a_file_owned_by_another_user_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = file_in(dir.path());
        let mut probe = FakeProbe::default();
        probe
            .facts
            .insert(std::fs::canonicalize(&path).unwrap(), other_user());
        for trusted in [true, false] {
            let reason = untrusted_reason(&path, trusted, &probe).unwrap();
            assert!(
                reason.starts_with("the file is owned by uid 1001"),
                "{reason}"
            );
        }
    }

    #[test]
    fn a_directory_owned_by_another_user_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = file_in(dir.path());
        let mut probe = FakeProbe::default();
        probe
            .facts
            .insert(std::fs::canonicalize(dir.path()).unwrap(), other_user());
        let reason = untrusted_reason(&path, true, &probe).unwrap();
        assert!(reason.starts_with("its directory "), "{reason}");
        assert!(reason.contains("owned by uid 1001"), "{reason}");
    }

    #[test]
    fn a_writable_trusted_file_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = file_in(dir.path());
        let mut probe = FakeProbe::default();
        probe
            .facts
            .insert(std::fs::canonicalize(&path).unwrap(), writable());
        assert_eq!(
            untrusted_reason(&path, true, &probe).as_deref(),
            Some("the file is writable by all users")
        );
        assert_eq!(
            untrusted_reason(&path, false, &probe).is_some(),
            cfg!(not(windows))
        );
    }

    #[test]
    fn a_writable_directory_is_rejected_on_unix() {
        let dir = tempfile::tempdir().unwrap();
        let path = file_in(dir.path());
        let mut probe = FakeProbe::default();
        probe
            .facts
            .insert(std::fs::canonicalize(dir.path()).unwrap(), writable());
        assert_eq!(
            untrusted_reason(&path, true, &probe).is_some(),
            cfg!(not(windows))
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_target_directory_is_checked() {
        let dir = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let target = file_in(elsewhere.path());
        let link = dir.path().join("config.yaml");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let mut probe = FakeProbe::default();
        probe.facts.insert(
            std::fs::canonicalize(elsewhere.path()).unwrap(),
            other_user(),
        );
        let reason = untrusted_reason(&link, true, &probe).unwrap();
        assert!(reason.starts_with("its directory "), "{reason}");
    }

    #[cfg(unix)]
    #[test]
    fn unix_modes_decide_who_may_write() {
        use unix::{Invoker, facts};
        let invoker = Invoker {
            uid: 501,
            private_gid: Some(501),
        };
        assert_eq!(facts(501, 20, 0o644, invoker).owner, Owner::Invoker);
        assert_eq!(facts(0, 0, 0o644, invoker).owner, Owner::Admin);
        assert_eq!(
            facts(1001, 1001, 0o644, invoker).owner,
            Owner::Other("uid 1001".into())
        );
        assert_eq!(facts(501, 20, 0o644, invoker).writable_by, None);
        assert_eq!(
            facts(501, 20, 0o664, invoker).writable_by.as_deref(),
            Some("group 20")
        );
        assert_eq!(facts(501, 501, 0o664, invoker).writable_by, None);
        assert_eq!(
            facts(501, 501, 0o666, invoker).writable_by.as_deref(),
            Some("all users")
        );
        assert_eq!(
            facts(0, 0, 0o1777, invoker).writable_by.as_deref(),
            Some("all users")
        );
        let shared = Invoker {
            uid: 501,
            private_gid: None,
        };
        assert_eq!(
            facts(501, 501, 0o664, shared).writable_by.as_deref(),
            Some("group 501")
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_real_probe_trusts_a_private_file_and_rejects_a_world_writable_one() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = file_in(dir.path());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(untrusted_reason(&path, true, &SystemProbe), None);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o606)).unwrap();
        assert_eq!(
            untrusted_reason(&path, true, &SystemProbe).as_deref(),
            Some("the file is writable by all users")
        );
    }

    /// Runs only as root, which can hand a file to another account.
    #[cfg(unix)]
    #[test]
    fn the_real_probe_rejects_a_file_owned_by_another_user() {
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = file_in(dir.path());
        std::os::unix::fs::chown(&path, Some(65534), None).unwrap();
        let reason = untrusted_reason(&path, true, &SystemProbe).unwrap();
        assert!(
            reason.starts_with("the file is owned by uid 65534"),
            "{reason}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_unix_system_directory_is_etc_rsigma() {
        assert_eq!(system_config_dir(), Some(PathBuf::from("/etc/rsigma")));
    }

    #[cfg(windows)]
    #[test]
    fn the_windows_system_directory_is_under_program_data() {
        let dir = system_config_dir().expect("ProgramData is a known folder");
        assert!(dir.is_absolute(), "{}", dir.display());
        assert!(dir.has_root(), "{}", dir.display());
        assert!(
            matches!(
                dir.components().next(),
                Some(std::path::Component::Prefix(_))
            ),
            "{}",
            dir.display()
        );
        assert!(dir.ends_with("rsigma"), "{}", dir.display());
        if let Some(env) = std::env::var_os("ProgramData") {
            assert!(
                dir.parent().unwrap().as_os_str().eq_ignore_ascii_case(&env),
                "{} vs {}",
                dir.display(),
                PathBuf::from(env).display()
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn the_real_probe_trusts_an_own_file_and_rejects_one_everyone_may_write() {
        let dir = tempfile::tempdir().unwrap();
        let path = file_in(dir.path());
        assert_eq!(untrusted_reason(&path, true, &SystemProbe), None);
        let status = std::process::Command::new("icacls")
            .arg(&path)
            .args(["/grant", "*S-1-1-0:(W)"])
            .status()
            .unwrap();
        assert!(status.success());
        let reason = untrusted_reason(&path, true, &SystemProbe).unwrap();
        assert_eq!(reason, "the file is writable by S-1-1-0");
        assert_eq!(untrusted_reason(&path, false, &SystemProbe), None);
    }
}
