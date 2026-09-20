//! Set and configure disk quotas for users, groups, or projects.
//!
//! # Examples
//!
//! Enabling and setting a quota:
//!
//! ```rust,no_run
//! # use nix::sys::quota::{Dqblk, quotactl_on, quotactl_set, QuotaFmt, QuotaType, QuotaValidFlags};
//! quotactl_on(QuotaType::USRQUOTA, "/dev/sda1", QuotaFmt::QFMT_VFS_V1, "aquota.user").unwrap();
//! let mut dqblk: Dqblk = Default::default();
//! dqblk.set_blocks_hard_limit(10000);
//! dqblk.set_blocks_soft_limit(8000);
//! quotactl_set(QuotaType::USRQUOTA, "/dev/sda1", 50, &dqblk, QuotaValidFlags::QIF_BLIMITS).unwrap();
//! ```
use crate::errno::Errno;
use crate::{NixPath, Result};
use libc::{self, c_char, c_int};
use std::default::Default;
#[cfg(linux_android)]
use std::os::fd::{AsFd, AsRawFd};
use std::{mem, ptr};

struct QuotaCmd(QuotaSubCmd, QuotaType);

impl QuotaCmd {
    fn as_int(&self) -> c_int {
        libc::QCMD(self.0 as i32, self.1 as i32)
    }
}

// linux quota version >= 2
libc_enum! {
    #[repr(i32)]
    enum QuotaSubCmd {
        Q_SYNC,
        Q_QUOTAON,
        Q_QUOTAOFF,
        Q_GETQUOTA,
        Q_SETQUOTA,
        Q_GETINFO,
    }
}

/// The scope of the quota.
///
/// `PRJQUOTA` is a Linux UAPI constant which is not yet exposed by libc.
#[repr(i32)]
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum QuotaType {
    /// Specify a user quota.
    USRQUOTA = libc::USRQUOTA,
    /// Specify a group quota.
    GRPQUOTA = libc::GRPQUOTA,
    /// Specify a project quota (Linux only).
    #[cfg(linux_android)]
    PRJQUOTA = 2,
}

impl TryFrom<i32> for QuotaType {
    type Error = crate::Error;

    fn try_from(value: i32) -> Result<Self> {
        match value {
            libc::USRQUOTA => Ok(Self::USRQUOTA),
            libc::GRPQUOTA => Ok(Self::GRPQUOTA),
            #[cfg(linux_android)]
            2 => Ok(Self::PRJQUOTA),
            _ => Err(Errno::EINVAL),
        }
    }
}

/// A Linux project identifier accepted by `quotactl`.
///
/// Linux stores project identifiers as `u32`, but the `quotactl` ABI accepts
/// its identifier in a signed `int`.  Values greater than `i32::MAX` are
/// therefore rejected instead of being silently reinterpreted.
#[cfg(linux_android)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProjectId(u32);

#[cfg(linux_android)]
impl ProjectId {
    /// Construct a project identifier which is representable by `quotactl`.
    pub fn new(id: u32) -> Result<Self> {
        if id > c_int::MAX as u32 {
            return Err(Errno::EINVAL);
        }
        Ok(Self(id))
    }

    /// Return the Linux project identifier.
    pub fn as_u32(self) -> u32 {
        self.0
    }
}

/// Project attributes associated with an inode or directory.
#[cfg(linux_android)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProjectAttributes {
    project_id: ProjectId,
    project_inherit: bool,
}

#[cfg(linux_android)]
impl ProjectAttributes {
    /// Project identifier assigned to this inode.
    pub fn project_id(self) -> ProjectId {
        self.project_id
    }

    /// Whether new children inherit this directory's project identifier.
    pub fn project_inherit(self) -> bool {
        self.project_inherit
    }
}

/// Exact finite project quota limits in bytes.
///
/// Linux quota block limits are measured in 1024-byte units.  This type does
/// not permit zero (unlimited) limits or inexact byte values.
#[cfg(linux_android)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProjectQuota {
    soft_limit_bytes: u64,
    hard_limit_bytes: u64,
}

/// Information returned by the active Linux project-quota interface.
#[cfg(linux_android)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProjectQuotaInfo {
    flags: u32,
}

#[cfg(linux_android)]
impl ProjectQuotaInfo {
    /// Filesystem-specific quota flags reported by `Q_GETINFO`.
    pub fn flags(self) -> u32 {
        self.flags
    }
}

#[cfg(linux_android)]
impl ProjectQuota {
    /// Construct finite, exactly representable soft and hard byte limits.
    pub fn new(soft_limit_bytes: u64, hard_limit_bytes: u64) -> Result<Self> {
        quota_blocks_from_bytes(soft_limit_bytes)?;
        quota_blocks_from_bytes(hard_limit_bytes)?;
        Ok(Self {
            soft_limit_bytes,
            hard_limit_bytes,
        })
    }

    /// The finite soft limit in bytes.
    pub fn soft_limit_bytes(self) -> u64 {
        self.soft_limit_bytes
    }

    /// The finite hard limit in bytes.
    pub fn hard_limit_bytes(self) -> u64 {
        self.hard_limit_bytes
    }

    fn from_dqblk(dqblk: &Dqblk) -> Result<Self> {
        if !QuotaValidFlags::from_bits_truncate(dqblk.0.dqb_valid)
            .contains(QuotaValidFlags::QIF_BLIMITS)
        {
            return Err(Errno::EINVAL);
        }
        Self::new(
            quota_bytes_from_blocks(dqblk.0.dqb_bsoftlimit)?,
            quota_bytes_from_blocks(dqblk.0.dqb_bhardlimit)?,
        )
    }
}

/// Convert a finite exact byte limit to Linux quota blocks.
#[cfg(linux_android)]
pub fn quota_blocks_from_bytes(bytes: u64) -> Result<u64> {
    const QUOTA_BLOCK_BYTES: u64 = 1024;
    if bytes == 0 || bytes % QUOTA_BLOCK_BYTES != 0 {
        return Err(Errno::EINVAL);
    }
    Ok(bytes / QUOTA_BLOCK_BYTES)
}

/// Convert a finite Linux quota-block limit to exact bytes.
#[cfg(linux_android)]
pub fn quota_bytes_from_blocks(blocks: u64) -> Result<u64> {
    const QUOTA_BLOCK_BYTES: u64 = 1024;
    if blocks == 0 {
        return Err(Errno::EINVAL);
    }
    blocks.checked_mul(QUOTA_BLOCK_BYTES).ok_or(Errno::EINVAL)
}

// The Linux UAPI has not yet exposed these two payload types through libc.
// Keep them private: callers only receive the project-specific safe view.
#[cfg(linux_android)]
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Fsxattr {
    fsx_xflags: u32,
    fsx_extsize: u32,
    fsx_nextents: u32,
    fsx_projid: u32,
    fsx_cowextsize: u32,
    fsx_pad: [u8; 8],
}

#[cfg(linux_android)]
#[repr(C)]
struct Dqinfo {
    dqi_bgrace: u64,
    dqi_igrace: u64,
    dqi_flags: u32,
    dqi_valid: u32,
}

#[cfg(linux_android)]
const FS_XFLAG_PROJINHERIT: u32 = 0x0000_0200;

// FS_IOC_FSGETXATTR and FS_IOC_FSSETXATTR, encoded from Linux _IOR/_IOW.
// libc owns the per-architecture ioctl layout and request ABI type.
#[cfg(linux_android)]
const FS_IOC_FSGETXATTR: libc::Ioctl = libc::_IOR::<Fsxattr>(b'X' as u32, 31);
#[cfg(linux_android)]
const FS_IOC_FSSETXATTR: libc::Ioctl = libc::_IOW::<Fsxattr>(b'X' as u32, 32);

libc_enum! {
    /// The type of quota format to use.
    #[repr(i32)]
    #[non_exhaustive]
    pub enum QuotaFmt {
        /// Use the original quota format.
        QFMT_VFS_OLD,
        /// Use the standard VFS v0 quota format.
        ///
        /// Handles 32-bit UIDs/GIDs and quota limits up to 2<sup>32</sup> bytes/2<sup>32</sup> inodes.
        QFMT_VFS_V0,
        /// Use the VFS v1 quota format.
        ///
        /// Handles 32-bit UIDs/GIDs and quota limits of 2<sup>64</sup> bytes/2<sup>64</sup> inodes.
        QFMT_VFS_V1,
    }
}

libc_bitflags!(
    /// Indicates the quota fields that are valid to read from.
    #[derive(Default)]
    pub struct QuotaValidFlags: u32 {
        /// The block hard & soft limit fields.
        QIF_BLIMITS;
        /// The current space field.
        QIF_SPACE;
        /// The inode hard & soft limit fields.
        QIF_ILIMITS;
        /// The current inodes field.
        QIF_INODES;
        /// The disk use time limit field.
        QIF_BTIME;
        /// The file quote time limit field.
        QIF_ITIME;
        /// All block & inode limits.
        QIF_LIMITS;
        /// The space & inodes usage fields.
        QIF_USAGE;
        /// The time limit fields.
        QIF_TIMES;
        /// All fields.
        QIF_ALL;
    }
);

/// Wrapper type for `if_dqblk`
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Dqblk(libc::dqblk);

impl Default for Dqblk {
    fn default() -> Dqblk {
        Dqblk(libc::dqblk {
            dqb_bhardlimit: 0,
            dqb_bsoftlimit: 0,
            dqb_curspace: 0,
            dqb_ihardlimit: 0,
            dqb_isoftlimit: 0,
            dqb_curinodes: 0,
            dqb_btime: 0,
            dqb_itime: 0,
            dqb_valid: 0,
        })
    }
}

impl Dqblk {
    /// The absolute limit on disk quota blocks allocated.
    pub fn blocks_hard_limit(&self) -> Option<u64> {
        let valid_fields =
            QuotaValidFlags::from_bits_truncate(self.0.dqb_valid);
        if valid_fields.contains(QuotaValidFlags::QIF_BLIMITS) {
            Some(self.0.dqb_bhardlimit)
        } else {
            None
        }
    }

    /// Set the absolute limit on disk quota blocks allocated.
    pub fn set_blocks_hard_limit(&mut self, limit: u64) {
        self.0.dqb_bhardlimit = limit;
    }

    /// Preferred limit on disk quota blocks
    pub fn blocks_soft_limit(&self) -> Option<u64> {
        let valid_fields =
            QuotaValidFlags::from_bits_truncate(self.0.dqb_valid);
        if valid_fields.contains(QuotaValidFlags::QIF_BLIMITS) {
            Some(self.0.dqb_bsoftlimit)
        } else {
            None
        }
    }

    /// Set the preferred limit on disk quota blocks allocated.
    pub fn set_blocks_soft_limit(&mut self, limit: u64) {
        self.0.dqb_bsoftlimit = limit;
    }

    /// Current occupied space (bytes).
    pub fn occupied_space(&self) -> Option<u64> {
        let valid_fields =
            QuotaValidFlags::from_bits_truncate(self.0.dqb_valid);
        if valid_fields.contains(QuotaValidFlags::QIF_SPACE) {
            Some(self.0.dqb_curspace)
        } else {
            None
        }
    }

    /// Maximum number of allocated inodes.
    pub fn inodes_hard_limit(&self) -> Option<u64> {
        let valid_fields =
            QuotaValidFlags::from_bits_truncate(self.0.dqb_valid);
        if valid_fields.contains(QuotaValidFlags::QIF_ILIMITS) {
            Some(self.0.dqb_ihardlimit)
        } else {
            None
        }
    }

    /// Set the maximum number of allocated inodes.
    pub fn set_inodes_hard_limit(&mut self, limit: u64) {
        self.0.dqb_ihardlimit = limit;
    }

    /// Preferred inode limit
    pub fn inodes_soft_limit(&self) -> Option<u64> {
        let valid_fields =
            QuotaValidFlags::from_bits_truncate(self.0.dqb_valid);
        if valid_fields.contains(QuotaValidFlags::QIF_ILIMITS) {
            Some(self.0.dqb_isoftlimit)
        } else {
            None
        }
    }

    /// Set the preferred limit of allocated inodes.
    pub fn set_inodes_soft_limit(&mut self, limit: u64) {
        self.0.dqb_isoftlimit = limit;
    }

    /// Current number of allocated inodes.
    pub fn allocated_inodes(&self) -> Option<u64> {
        let valid_fields =
            QuotaValidFlags::from_bits_truncate(self.0.dqb_valid);
        if valid_fields.contains(QuotaValidFlags::QIF_INODES) {
            Some(self.0.dqb_curinodes)
        } else {
            None
        }
    }

    /// Time limit for excessive disk use.
    pub fn block_time_limit(&self) -> Option<u64> {
        let valid_fields =
            QuotaValidFlags::from_bits_truncate(self.0.dqb_valid);
        if valid_fields.contains(QuotaValidFlags::QIF_BTIME) {
            Some(self.0.dqb_btime)
        } else {
            None
        }
    }

    /// Set the time limit for excessive disk use.
    pub fn set_block_time_limit(&mut self, limit: u64) {
        self.0.dqb_btime = limit;
    }

    /// Time limit for excessive files.
    pub fn inode_time_limit(&self) -> Option<u64> {
        let valid_fields =
            QuotaValidFlags::from_bits_truncate(self.0.dqb_valid);
        if valid_fields.contains(QuotaValidFlags::QIF_ITIME) {
            Some(self.0.dqb_itime)
        } else {
            None
        }
    }

    /// Set the time limit for excessive files.
    pub fn set_inode_time_limit(&mut self, limit: u64) {
        self.0.dqb_itime = limit;
    }
}

fn quotactl<P: ?Sized + NixPath>(
    cmd: QuotaCmd,
    special: Option<&P>,
    id: c_int,
    addr: *mut c_char,
) -> Result<()> {
    unsafe {
        Errno::clear();
        let res = match special {
            Some(dev) => dev.with_nix_path(|path| {
                libc::quotactl(cmd.as_int(), path.as_ptr(), id, addr)
            }),
            None => Ok(libc::quotactl(cmd.as_int(), ptr::null(), id, addr)),
        }?;

        Errno::result(res).map(drop)
    }
}

#[cfg(linux_android)]
fn fsxattr_get<Fd: AsFd>(fd: Fd) -> Result<Fsxattr> {
    let mut attributes = Fsxattr::default();
    // FS_IOC_FSGETXATTR has a fixed request number and a pointer to our
    // ABI-checked `Fsxattr`; the buffer is live and writable for this call.
    let result = unsafe {
        libc::ioctl(
            fd.as_fd().as_raw_fd(),
            FS_IOC_FSGETXATTR,
            (&mut attributes as *mut Fsxattr).cast::<libc::c_void>(),
        )
    };
    Errno::result(result).map(|_| attributes)
}

#[cfg(linux_android)]
fn fsxattr_set<Fd: AsFd>(fd: Fd, attributes: &Fsxattr) -> Result<()> {
    // FS_IOC_FSSETXATTR has a fixed request number and `attributes` remains
    // valid and immutable for the duration of this synchronous ioctl.
    let result = unsafe {
        libc::ioctl(
            fd.as_fd().as_raw_fd(),
            FS_IOC_FSSETXATTR,
            (attributes as *const Fsxattr).cast::<libc::c_void>(),
        )
    };
    Errno::result(result).map(drop)
}

/// Read a file or directory's Linux project identifier and inheritance bit.
///
/// Filesystems which do not implement `FS_IOC_FSGETXATTR` return their normal
/// filesystem error, commonly `EINVAL`, `ENOTTY`, or `EOPNOTSUPP`.
#[cfg(linux_android)]
pub fn project_attributes<Fd: AsFd>(fd: Fd) -> Result<ProjectAttributes> {
    let attributes = fsxattr_get(fd)?;
    Ok(ProjectAttributes {
        project_id: ProjectId::new(attributes.fsx_projid)?,
        project_inherit: attributes.fsx_xflags & FS_XFLAG_PROJINHERIT != 0,
    })
}

/// Assign a project identifier and inheritance bit while preserving all other
/// filesystem project attributes.
#[cfg(linux_android)]
pub fn set_project_attributes<Fd: AsFd>(
    fd: Fd,
    project_id: ProjectId,
    project_inherit: bool,
) -> Result<()> {
    let mut attributes = fsxattr_get(&fd)?;
    set_project_values(&mut attributes, project_id, project_inherit);
    fsxattr_set(fd, &attributes)
}

#[cfg(linux_android)]
fn set_project_values(attributes: &mut Fsxattr, project_id: ProjectId, project_inherit: bool) {
    attributes.fsx_projid = project_id.as_u32();
    if project_inherit {
        attributes.fsx_xflags |= FS_XFLAG_PROJINHERIT;
    } else {
        attributes.fsx_xflags &= !FS_XFLAG_PROJINHERIT;
    }
}

/// Turn on disk quotas for a block device.
pub fn quotactl_on<P: ?Sized + NixPath>(
    which: QuotaType,
    special: &P,
    format: QuotaFmt,
    quota_file: &P,
) -> Result<()> {
    quota_file.with_nix_path(|path| {
        let mut path_copy = path.to_bytes_with_nul().to_owned();
        let p: *mut c_char = path_copy.as_mut_ptr().cast();
        quotactl(
            QuotaCmd(QuotaSubCmd::Q_QUOTAON, which),
            Some(special),
            format as c_int,
            p,
        )
    })?
}

/// Disable disk quotas for a block device.
pub fn quotactl_off<P: ?Sized + NixPath>(
    which: QuotaType,
    special: &P,
) -> Result<()> {
    quotactl(
        QuotaCmd(QuotaSubCmd::Q_QUOTAOFF, which),
        Some(special),
        0,
        ptr::null_mut(),
    )
}

/// Update the on-disk copy of quota usages for a filesystem.
///
/// If `special` is `None`, then all file systems with active quotas are sync'd.
pub fn quotactl_sync<P: ?Sized + NixPath>(
    which: QuotaType,
    special: Option<&P>,
) -> Result<()> {
    quotactl(
        QuotaCmd(QuotaSubCmd::Q_SYNC, which),
        special,
        0,
        ptr::null_mut(),
    )
}

/// Get disk quota limits and current usage for the given user/group id.
pub fn quotactl_get<P: ?Sized + NixPath>(
    which: QuotaType,
    special: &P,
    id: c_int,
) -> Result<Dqblk> {
    let mut dqblk = mem::MaybeUninit::<libc::dqblk>::uninit();
    quotactl(
        QuotaCmd(QuotaSubCmd::Q_GETQUOTA, which),
        Some(special),
        id,
        dqblk.as_mut_ptr().cast(),
    )?;
    Ok(unsafe { Dqblk(dqblk.assume_init()) })
}

/// Read active project-quota information for a filesystem.
///
/// A successful `Q_GETINFO` with the flags validity bit proves that the kernel
/// has an active project-quota interface for `special`; it is not inferred
/// merely from the presence of a quota record.
#[cfg(linux_android)]
pub fn project_quota_active<P: ?Sized + NixPath>(special: &P) -> Result<ProjectQuotaInfo> {
    let mut info = mem::MaybeUninit::<Dqinfo>::uninit();
    quotactl(
        QuotaCmd(QuotaSubCmd::Q_GETINFO, QuotaType::PRJQUOTA),
        Some(special),
        0,
        info.as_mut_ptr().cast(),
    )?;
    let info = unsafe { info.assume_init() };
    const IIF_FLAGS: u32 = 4;
    if info.dqi_valid & IIF_FLAGS == 0 {
        return Err(Errno::EINVAL);
    }
    Ok(ProjectQuotaInfo {
        flags: info.dqi_flags,
    })
}

/// Read finite exact project quota limits for `project_id`.
#[cfg(linux_android)]
pub fn project_quota<P: ?Sized + NixPath>(
    special: &P,
    project_id: ProjectId,
) -> Result<ProjectQuota> {
    let dqblk = quotactl_get(QuotaType::PRJQUOTA, special, project_id.as_u32() as c_int)?;
    ProjectQuota::from_dqblk(&dqblk)
}

/// Set finite exact project quota limits for `project_id`.
///
/// Call [`project_quota_active`] first when setup needs to prove that project
/// quota accounting is active before assigning limits.
#[cfg(linux_android)]
pub fn set_project_quota<P: ?Sized + NixPath>(
    special: &P,
    project_id: ProjectId,
    quota: ProjectQuota,
) -> Result<()> {
    let mut dqblk = Dqblk::default();
    dqblk.set_blocks_soft_limit(quota_blocks_from_bytes(quota.soft_limit_bytes())?);
    dqblk.set_blocks_hard_limit(quota_blocks_from_bytes(quota.hard_limit_bytes())?);
    quotactl_set(
        QuotaType::PRJQUOTA,
        special,
        project_id.as_u32() as c_int,
        &dqblk,
        QuotaValidFlags::QIF_BLIMITS,
    )
}

/// Configure quota values for the specified fields for a given user/group id.
pub fn quotactl_set<P: ?Sized + NixPath>(
    which: QuotaType,
    special: &P,
    id: c_int,
    dqblk: &Dqblk,
    fields: QuotaValidFlags,
) -> Result<()> {
    let mut dqblk_copy = *dqblk;
    dqblk_copy.0.dqb_valid = fields.bits();
    quotactl(
        QuotaCmd(QuotaSubCmd::Q_SETQUOTA, which),
        Some(special),
        id,
        &mut dqblk_copy as *mut _ as *mut c_char,
    )
}

#[cfg(all(test, linux_android))]
mod tests {
    use super::*;

    #[test]
    fn project_quota_command_uses_linux_project_selector() {
        assert_eq!(
            QuotaCmd(QuotaSubCmd::Q_GETQUOTA, QuotaType::PRJQUOTA).as_int(),
            libc::QCMD(libc::Q_GETQUOTA, 2),
        );
    }

    #[test]
    fn fsxattr_layout_matches_linux_uapi() {
        let attributes = Fsxattr::default();
        let base = (&attributes as *const Fsxattr) as usize;
        assert_eq!(mem::size_of::<Fsxattr>(), 28);
        assert_eq!(mem::align_of::<Fsxattr>(), 4);
        assert_eq!(ptr::addr_of!(attributes.fsx_xflags) as usize - base, 0);
        assert_eq!(ptr::addr_of!(attributes.fsx_extsize) as usize - base, 4);
        assert_eq!(ptr::addr_of!(attributes.fsx_nextents) as usize - base, 8);
        assert_eq!(ptr::addr_of!(attributes.fsx_projid) as usize - base, 12);
        assert_eq!(ptr::addr_of!(attributes.fsx_cowextsize) as usize - base, 16);
        assert_eq!(ptr::addr_of!(attributes.fsx_pad) as usize - base, 20);
    }

    #[cfg(feature = "ioctl")]
    #[test]
    fn fsxattr_requests_match_ioctl_macros() {
        assert_eq!(
            FS_IOC_FSGETXATTR,
            request_code_read!(b'X', 31, mem::size_of::<Fsxattr>()) as libc::Ioctl
        );
        assert_eq!(
            FS_IOC_FSSETXATTR,
            request_code_write!(b'X', 32, mem::size_of::<Fsxattr>()) as libc::Ioctl
        );
    }

    #[cfg(target_arch = "sparc64")]
    #[test]
    fn fsxattr_requests_use_sparc64_legacy_encoding() {
        assert_eq!(FS_IOC_FSGETXATTR as u64, 0x401c_581f);
        assert_eq!(FS_IOC_FSSETXATTR as u64, 0x801c_5820);
    }

    #[test]
    fn setting_project_values_preserves_other_fsxattr_fields() {
        let mut attributes = Fsxattr {
            fsx_xflags: 0x40,
            fsx_extsize: 10,
            fsx_nextents: 11,
            fsx_projid: 12,
            fsx_cowextsize: 13,
            fsx_pad: [14; 8],
        };
        set_project_values(&mut attributes, ProjectId::new(42).unwrap(), true);
        assert_eq!(attributes.fsx_projid, 42);
        assert_eq!(attributes.fsx_xflags, 0x40 | FS_XFLAG_PROJINHERIT);
        assert_eq!(attributes.fsx_extsize, 10);
        assert_eq!(attributes.fsx_nextents, 11);
        assert_eq!(attributes.fsx_cowextsize, 13);
        assert_eq!(attributes.fsx_pad, [14; 8]);
        set_project_values(&mut attributes, ProjectId::new(42).unwrap(), false);
        assert_eq!(attributes.fsx_xflags, 0x40);
    }

    #[test]
    fn project_id_boundaries_are_checked() {
        assert_eq!(ProjectId::new(0).unwrap().as_u32(), 0);
        assert_eq!(ProjectId::new(c_int::MAX as u32).unwrap().as_u32(), c_int::MAX as u32);
        assert_eq!(ProjectId::new(c_int::MAX as u32 + 1), Err(Errno::EINVAL));
    }

    #[test]
    fn exact_quota_block_conversions() {
        let sixteen_gib = 16 * 1024 * 1024 * 1024;
        assert_eq!(quota_blocks_from_bytes(sixteen_gib), Ok(16_777_216));
        assert_eq!(quota_bytes_from_blocks(16_777_216), Ok(sixteen_gib));
        assert_eq!(quota_blocks_from_bytes(sixteen_gib - 1), Err(Errno::EINVAL));
        assert_eq!(quota_blocks_from_bytes(sixteen_gib + 1), Err(Errno::EINVAL));
        assert_eq!(quota_blocks_from_bytes(0), Err(Errno::EINVAL));
        assert_eq!(quota_bytes_from_blocks(0), Err(Errno::EINVAL));
        assert_eq!(quota_bytes_from_blocks(u64::MAX), Err(Errno::EINVAL));
    }

    #[test]
    fn project_quota_requires_limit_validity() {
        let dqblk = Dqblk::default();
        assert_eq!(ProjectQuota::from_dqblk(&dqblk), Err(Errno::EINVAL));
        let mut dqblk = Dqblk::default();
        dqblk.0.dqb_valid = QuotaValidFlags::QIF_BLIMITS.bits();
        dqblk.0.dqb_bsoftlimit = 1;
        dqblk.0.dqb_bhardlimit = 1;
        assert_eq!(ProjectQuota::from_dqblk(&dqblk).unwrap().soft_limit_bytes(), 1024);
    }
}
