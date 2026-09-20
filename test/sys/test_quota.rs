use nix::errno::Errno;
use nix::sys::quota::{
    project_attributes, project_quota, project_quota_active,
    set_project_attributes, set_project_quota, ProjectId, ProjectQuota,
};
use nix::unistd::geteuid;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::Path;
use std::path::PathBuf;

fn validate_qualification_target(
    device: &Path,
    directory_fd: &File,
) -> std::io::Result<()> {
    let device_metadata = device.metadata()?;
    let directory_metadata = directory_fd.metadata()?;

    validate_qualification_target_metadata(
        device_metadata.file_type().is_block_device(),
        device_metadata.rdev(),
        directory_metadata.dev(),
    )
}

fn validate_qualification_target_metadata(
    device_is_block_device: bool,
    device_rdev: u64,
    directory_dev: u64,
) -> std::io::Result<()> {
    if !device_is_block_device {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "project-quota device must be block-special",
        ));
    }
    if device_rdev != directory_dev {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "project-quota device does not back the qualification directory",
        ));
    }
    Ok(())
}

#[test]
fn qualification_target_rejects_non_block_devices_and_mismatched_filesystems() {
    let directory = tempfile::tempdir().unwrap();
    let directory_fd = File::open(directory.path()).unwrap();
    let regular_file = directory.path().join("not-a-block-device");
    File::create(&regular_file).unwrap();

    assert!(
        validate_qualification_target(&regular_file, &directory_fd).is_err()
    );
    assert!(validate_qualification_target_metadata(true, 1, 2).is_err());
}

#[test]
fn project_attributes_use_a_safe_descriptor_api() {
    let directory = tempfile::tempdir().unwrap();
    let fd = File::open(directory.path()).unwrap();

    // A supporting filesystem succeeds.  Other filesystems document their
    // ordinary ioctl error instead; this test deliberately makes no quota
    // enforcement claim and never changes the temporary directory.
    if let Err(error) = project_attributes(&fd) {
        assert!(matches!(
            error,
            Errno::EINVAL
                | Errno::ENOTTY
                | Errno::EOPNOTSUPP
                | Errno::EPERM
                | Errno::EACCES
        ));
    }
}

/// This is an explicit qualification contract, not an ordinary CI test.
///
/// It changes project quota state and writes past a limit.  Run only as root
/// on a dedicated disposable project-quota filesystem, for example:
/// `NIX_PROJECT_QUOTA_TEST_DEVICE=/dev/loop0 NIX_PROJECT_QUOTA_TEST_DIRECTORY=/mnt/test \
///  NIX_PROJECT_QUOTA_TEST_ID=1000 cargo test --features quota,ioctl,fs \
///  --test test project_quota_enforces_on_disposable_filesystem -- --ignored`.
#[test]
#[ignore = "requires root and a dedicated disposable project-quota filesystem"]
fn project_quota_enforces_on_disposable_filesystem() {
    assert!(geteuid().is_root(), "this contract requires root");
    let device =
        PathBuf::from(std::env::var("NIX_PROJECT_QUOTA_TEST_DEVICE").unwrap());
    let directory = PathBuf::from(
        std::env::var("NIX_PROJECT_QUOTA_TEST_DIRECTORY").unwrap(),
    );
    let id = std::env::var("NIX_PROJECT_QUOTA_TEST_ID")
        .unwrap()
        .parse()
        .unwrap();
    let project_id = ProjectId::new(id).unwrap();
    let directory_fd = File::open(&directory).unwrap();

    validate_qualification_target(&device, &directory_fd).unwrap();
    project_quota_active(&device).unwrap();
    set_project_attributes(&directory_fd, project_id, true).unwrap();
    const MEBIBYTE: usize = 1024 * 1024;
    const HARD_LIMIT_BYTES: usize = 16 * MEBIBYTE;
    const PROBE_LIMIT_BYTES: usize = HARD_LIMIT_BYTES + MEBIBYTE;

    let quota = ProjectQuota::new(8 * MEBIBYTE as u64, HARD_LIMIT_BYTES as u64)
        .unwrap();
    set_project_quota(&device, project_id, quota).unwrap();
    assert_eq!(project_quota(&device, project_id).unwrap(), quota);

    let child = directory.join("project-quota-limit-probe");
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(child)
        .unwrap();
    let block = [0u8; MEBIBYTE];
    let mut written = 0;
    while written < PROBE_LIMIT_BYTES {
        match file.write_all(&block) {
            Ok(()) => written += block.len(),
            Err(error) if error.raw_os_error() == Some(Errno::EDQUOT as i32) => return,
            Err(error) => panic!(
                "unexpected error after writing {written} bytes while qualifying project quota enforcement: {error}"
            ),
        }
    }
    panic!(
        "project quota enforcement was not observed: wrote {PROBE_LIMIT_BYTES} bytes without EDQUOT (hard limit: {HARD_LIMIT_BYTES} bytes)"
    );
}
