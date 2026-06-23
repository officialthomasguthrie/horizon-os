// The Linux executor: walk a Plan against the real kernel. Each Step maps to a
// mount/overlay/bind/move/switch_root syscall. Everything here is gated to Linux so
// the workspace still builds on darwin; the plan that drives it is pure and lives in
// lib.rs.

use std::ffi::CString;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use nix::errno::Errno;
use nix::mount::{mount, MsFlags};
use nix::unistd::{chdir, chroot, execv};

use crate::{
    luks_close_args, luks_open_args, mapper_path, verity_close_args, verity_open_args, Error,
    MountFlags, Plan, Source, Spec, Step, MASTER_KEY_SIZE,
};

// A typed None for the source/fstype/data arguments mount does not need.
const NONE: Option<&Path> = None;

fn io(e: Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(e as i32)
}

fn flags(f: MountFlags) -> MsFlags {
    let mut m = MsFlags::empty();
    if f.rdonly {
        m |= MsFlags::MS_RDONLY;
    }
    if f.nosuid {
        m |= MsFlags::MS_NOSUID;
    }
    if f.nodev {
        m |= MsFlags::MS_NODEV;
    }
    if f.noexec {
        m |= MsFlags::MS_NOEXEC;
    }
    m
}

// The kernel virtual filesystems; re-mounting one is harmless (the binary mounts proc
// before reading the command line, then the plan mounts it again), so EBUSY on these
// is ignored rather than failing the boot.
fn is_pseudo(fstype: &str) -> bool {
    matches!(fstype, "proc" | "sysfs" | "devtmpfs" | "tmpfs")
}

/// Run a whole plan. Returns only if it ends before the `switch_root` step (the
/// executor for a real boot does not return: `switch_root` execs the init).
pub fn execute(plan: &Plan) -> Result<(), Error> {
    for step in &plan.steps {
        run(step)?;
    }
    Ok(())
}

fn run(step: &Step) -> Result<(), Error> {
    match step {
        Step::Mkdir(p) => std::fs::create_dir_all(p).map_err(|e| Error::step("mkdir", p, e)),
        Step::Mount { source, target } => do_mount(source, target),
        Step::Overlay {
            lower,
            upper,
            work,
            target,
        } => do_overlay(lower, upper, work, target),
        Step::Bind { from, to } => bind(from, to),
        Step::Move { from, to } => move_mount(from, to),
        Step::SwitchRoot {
            new_root,
            init,
            args,
        } => switch_root(new_root, init, args),
    }
}

fn do_mount(s: &Source, target: &Path) -> Result<(), Error> {
    let res = mount(
        Some(s.dev.as_path()),
        target,
        Some(s.fstype.as_str()),
        flags(s.flags),
        NONE,
    );
    match res {
        Ok(()) => Ok(()),
        // A kernel filesystem already present is not an error in an init.
        Err(Errno::EBUSY) if is_pseudo(&s.fstype) => Ok(()),
        Err(e) => Err(Error::step("mount", target, io(e))),
    }
}

fn do_overlay(lower: &Path, upper: &Path, work: &Path, target: &Path) -> Result<(), Error> {
    let data = format!(
        "lowerdir={},upperdir={},workdir={}",
        lower.display(),
        upper.display(),
        work.display()
    );
    mount(
        Some("overlay"),
        target,
        Some("overlay"),
        MsFlags::empty(),
        Some(data.as_str()),
    )
    .map_err(|e| Error::step("overlay", target, io(e)))
}

fn bind(from: &Path, to: &Path) -> Result<(), Error> {
    mount(
        Some(from),
        to,
        NONE,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        NONE,
    )
    .map_err(|e| Error::step("bind", to, io(e)))
}

fn move_mount(from: &Path, to: &Path) -> Result<(), Error> {
    mount(Some(from), to, NONE, MsFlags::MS_MOVE, NONE).map_err(|e| Error::step("move", to, io(e)))
}

// The initramfs switch_root: make the assembled root the new /, drop the initramfs
// rootfs, and exec the real init. pivot_root cannot be used on the initramfs rootfs,
// so the kernel-documented move-and-chroot sequence is used instead.
fn switch_root(new_root: &Path, init: &Path, args: &[String]) -> Result<(), Error> {
    chdir(new_root).map_err(|e| Error::step("chdir", new_root, io(e)))?;
    mount(Some(new_root), Path::new("/"), NONE, MsFlags::MS_MOVE, NONE)
        .map_err(|e| Error::step("move-root", new_root, io(e)))?;
    chroot(Path::new(".")).map_err(|e| Error::step("chroot", new_root, io(e)))?;
    chdir(Path::new("/")).map_err(|e| Error::step("chdir", Path::new("/"), io(e)))?;

    let prog = cstr(init.as_os_str().as_bytes(), init)?;
    let mut argv = vec![prog.clone()];
    for a in args {
        argv.push(cstr(a.as_bytes(), init)?);
    }
    // execv returns only on failure.
    let err = execv(&prog, &argv).unwrap_err();
    Err(Error::step("exec", init, io(err)))
}

fn cstr(bytes: &[u8], at: &Path) -> Result<CString, Error> {
    CString::new(bytes).map_err(|_| {
        Error::step(
            "exec",
            at,
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "interior nul byte"),
        )
    })
}

/// Mount proc at /proc, so the binary can read the kernel command line before it has
/// planned anything. Idempotent: the plan mounts proc again and the executor ignores
/// the resulting EBUSY.
pub fn mount_proc() -> Result<(), Error> {
    do_mount(
        &Source::new("proc", "proc", MountFlags::PSEUDO),
        Path::new("/proc"),
    )
}

/// Resolve a [`Spec`] to a [`Source`]: turn a label/UUID/path into a present block
/// device with the given filesystem type. A label or UUID is looked up under
/// `/dev/disk/by-*`, the symlinks udev maintains, so the image needs no device path
/// hardcoded. An absent device is an error the caller decides how to handle (a missing
/// base aborts the boot; a missing data device falls back to Ghost).
pub fn resolve(spec: &Spec, fstype: &str) -> Result<Source, Error> {
    let resolved = match spec {
        Spec::Path(p) => p.exists().then(|| p.clone()),
        Spec::Label(l) => resolve_label(l),
        Spec::Uuid(u) => {
            let p = Path::new("/dev/disk/by-uuid").join(u);
            p.exists().then_some(p)
        }
    };
    match resolved {
        Some(path) => Ok(Source::new(path, fstype, MountFlags::default())),
        None => Err(Error::Resolve(format!("{spec:?}"))),
    }
}

/// Resolve a label to a device. On a full system udev maintains the `/dev/disk/by-label` and
/// `/dev/disk/by-partlabel` symlinks, so those are tried first; a minimal initramfs has no udev,
/// so the fallback reads the GPT directly ([`resolve_partlabel`]). The labels a Key uses are GPT
/// partition names, which every partition has, including the label-less squashfs base and the
/// filesystem-less dm-verity hash device, so the partition-name path is what a Key relies on.
fn resolve_label(label: &str) -> Option<PathBuf> {
    for dir in ["/dev/disk/by-label", "/dev/disk/by-partlabel"] {
        let p = Path::new(dir).join(label);
        if p.exists() {
            return Some(p);
        }
    }
    resolve_partlabel(label)
}

/// Find the partition whose GPT name is `label` by reading the partition tables of the whole-disk
/// block devices directly, the resolution a minimal initramfs relies on with no udev to maintain
/// the by-label symlinks. Returns `/dev/<disk><N>` for the first match. Only the Key's disk
/// carries `HORIZON-*` partition names, so scanning every disk and matching the name needs no
/// guess at which disk is the Key.
fn resolve_partlabel(label: &str) -> Option<PathBuf> {
    for disk in whole_disks() {
        let dev = Path::new("/dev").join(&disk);
        let Some(parts) = read_disk_gpt(&dev, sector_size(&disk)) else {
            continue;
        };
        if let Some(p) = parts.into_iter().find(|p| p.name == label) {
            // Return the partition node only once it exists: the GPT on the whole disk is
            // readable before the kernel finishes the asynchronous partition scan, so a node
            // named but not yet created would resolve to a path that cannot be mounted. The
            // caller polls, so a not-yet-created node simply retries.
            let node = partition_dev(&disk, p.number);
            if node.exists() {
                return Some(node);
            }
        }
    }
    None
}

// The whole-disk block devices the kernel knows, from /sys/block, minus the pseudo devices that
// never hold a Key (ram disks, loop devices). Reading a non-GPT disk's table returns None, so
// this list need not be exact, only a superset of the real disks.
fn whole_disks() -> Vec<String> {
    let mut disks = Vec::new();
    if let Ok(rd) = std::fs::read_dir("/sys/block") {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if name.starts_with("ram") || name.starts_with("loop") {
                continue;
            }
            disks.push(name);
        }
    }
    disks
}

// A disk's logical sector size, read from sysfs (the unit the GPT's LBAs count in); 512 if it
// cannot be read, the near-universal default the Key is built with.
fn sector_size(disk: &str) -> u64 {
    std::fs::read_to_string(format!("/sys/block/{disk}/queue/logical_block_size"))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(512)
}

// Read a disk's primary GPT (the header at LBA 1, then the entry array it points at) and parse
// it. None if the disk is not GPT or cannot be read, so a non-Key disk is silently skipped.
fn read_disk_gpt(dev: &Path, sector: u64) -> Option<Vec<crate::GptPart>> {
    let mut f = std::fs::File::open(dev).ok()?;
    let mut header = [0u8; 512];
    f.seek(SeekFrom::Start(sector)).ok()?; // LBA 1
    f.read_exact(&mut header).ok()?;
    if &header[0..8] != b"EFI PART" {
        return None;
    }
    let entry_lba = u64::from_le_bytes(header[72..80].try_into().ok()?);
    let num = u32::from_le_bytes(header[80..84].try_into().ok()?) as usize;
    let size = u32::from_le_bytes(header[84..88].try_into().ok()?) as usize;
    let total = num.checked_mul(size)?;
    // A sane GPT entry array is small (128 entries x 128 bytes = 16 KiB); cap it so a corrupt
    // header cannot ask for a huge allocation.
    if total == 0 || total > 1 << 20 {
        return None;
    }
    let mut entries = vec![0u8; total];
    f.seek(SeekFrom::Start(entry_lba.checked_mul(sector)?))
        .ok()?;
    f.read_exact(&mut entries).ok()?;
    crate::parse_gpt(&header, &entries)
}

// The device node of partition `number` on `disk`: nvme0n1 -> nvme0n1p2, vda -> vda2. A disk
// whose name ends in a digit takes the `p` separator, the kernel's partition-naming rule.
fn partition_dev(disk: &str, number: u32) -> PathBuf {
    let sep = if disk.ends_with(|c: char| c.is_ascii_digit()) {
        "p"
    } else {
        ""
    };
    Path::new("/dev").join(format!("{disk}{sep}{number}"))
}

/// Load the boot-path kernel modules the initramfs carries, in dependency order, so the Key's
/// partitions appear under `/dev` and the dm-verity and dm-crypt layers can be opened. A
/// Debian-class kernel ships squashfs, overlay, ext4, the device-mapper targets, and the virtio
/// block drivers as modules, and a minimal initramfs has no udev or modprobe to load them on
/// demand, so the init loads them itself: read the `modules.dep` keybuild wrote, order it with
/// [`crate::module_load_order`], and `finit_module` each `.ko`. The modules are uncompressed, so
/// no decompression and no compressed-file flag is needed. A module already loaded (`EEXIST`) is
/// fine; any other failure is logged and the load continues, so a module that will not load
/// surfaces at the mount that needs it rather than wedging the whole boot here. Returns how many
/// loaded. A kernel with these drivers built in carries no modules directory ([`modules_dir`]
/// returns `None`), so the caller does no work.
pub fn load_modules(dir: &Path) -> Result<usize, Error> {
    let dep_path = dir.join("modules.dep");
    let text = match std::fs::read_to_string(&dep_path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(Error::step("modules.dep", &dep_path, e)),
    };
    let deps = crate::parse_modules_dep(&text);
    let mut loaded = 0;
    for rel in crate::module_load_order(&deps) {
        let ko = dir.join(&rel);
        match finit_module(&ko) {
            Ok(()) => loaded += 1,
            // Already loaded (a dependency pulled in earlier, or a built-in stub): not an error.
            Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {}
            Err(e) => eprintln!("horizon-init: module {}: {e}", rel.display()),
        }
    }
    Ok(loaded)
}

// finit_module(2): load an uncompressed .ko by file descriptor, with no module parameters and no
// flags. The kernel reads the module image straight from the fd, so nothing is copied through
// userspace; uncompressed modules need no MODULE_INIT_COMPRESSED_FILE.
fn finit_module(ko: &Path) -> std::io::Result<()> {
    let file = std::fs::File::open(ko)?;
    let params = c"";
    let rc = unsafe {
        libc::syscall(
            libc::SYS_finit_module,
            file.as_raw_fd(),
            params.as_ptr(),
            0 as libc::c_int,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// The initramfs's kernel-modules directory (`/lib/modules/<version>`), or `None` when the kernel
/// ships its drivers built in (no such directory). Prefers the running kernel's release (`uname`),
/// falling back to the single versioned directory a Horizon initramfs carries.
pub fn modules_dir() -> Option<PathBuf> {
    let base = Path::new("/lib/modules");
    if let Some(release) = uname_release() {
        let d = base.join(&release);
        if d.join("modules.dep").exists() {
            return Some(d);
        }
    }
    std::fs::read_dir(base)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .find(|p| p.join("modules.dep").exists())
}

// The running kernel's release string (`uname -r`), used to find its modules directory.
fn uname_release() -> Option<String> {
    let u = nix::sys::utsname::uname().ok()?;
    u.release().to_str().map(str::to_string)
}

/// Open the encrypted Home layer at `container` with the 32-byte `master`, exposing the
/// decrypted volume at `/dev/mapper/<mapper>`, and return that path. The master is fed to
/// cryptsetup on stdin (exactly [`MASTER_KEY_SIZE`] bytes), so it never lands in a key
/// file or an argument; a wrong master, or device-mapper being unavailable, fails here.
/// This is the boot-time consumer of what keybuild's formatter wrote: the init recovers
/// the master from the store, opens this layer with it, then assembles the overlay over
/// the decrypted device.
pub fn luks_open(
    container: &Path,
    mapper: &str,
    master: &[u8; MASTER_KEY_SIZE],
) -> Result<PathBuf, Error> {
    cryptsetup_with_key(
        "luksOpen",
        container,
        &luks_open_args(container, mapper),
        master,
    )?;
    Ok(mapper_path(mapper))
}

/// Close the device-mapper node `mapper` (tear down the decrypted mapping). Paired with
/// [`luks_open`] so a teardown path never leaves the layer open.
pub fn luks_close(mapper: &str) -> Result<(), Error> {
    let out = Command::new("cryptsetup")
        .args(luks_close_args(mapper))
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| Error::step("luksClose", Path::new(mapper), e))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(Error::step(
            "luksClose",
            Path::new(mapper),
            tool_error(&out.stderr),
        ))
    }
}

/// Open the dm-verity device over the immutable base: verify the base partition at
/// `data_dev` against the Merkle tree on `hash_dev` anchored by `root_hash` (lowercase
/// hex), exposing the verified read-only base at `/dev/mapper/<mapper>`, and return that
/// path. Unlike the LUKS master, the root hash is a public trust anchor (it comes from the
/// signed or measured loader config), so it is passed as an argument, not on stdin.
///
/// A base that does not hash to `root_hash`, or device-mapper being unavailable, fails
/// here, which is the point: a tampered base does not mount. This is the boot-time consumer
/// of what keybuild's `verity::format` wrote, the read side to its write side, exactly as
/// [`luks_open`] consumes the LUKS layer keybuild's formatter built.
pub fn verity_open(
    data_dev: &Path,
    hash_dev: &Path,
    mapper: &str,
    root_hash: &str,
) -> Result<PathBuf, Error> {
    let out = Command::new("veritysetup")
        .args(verity_open_args(data_dev, hash_dev, mapper, root_hash))
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| Error::step("verityOpen", data_dev, e))?;
    if out.status.success() {
        Ok(mapper_path(mapper))
    } else {
        Err(Error::step("verityOpen", data_dev, tool_error(&out.stderr)))
    }
}

/// Close the device-mapper node `mapper` (tear down the verified base mapping). Paired
/// with [`verity_open`] so a teardown path never leaves the mapping open.
pub fn verity_close(mapper: &str) -> Result<(), Error> {
    let out = Command::new("veritysetup")
        .args(verity_close_args(mapper))
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| Error::step("verityClose", Path::new(mapper), e))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(Error::step(
            "verityClose",
            Path::new(mapper),
            tool_error(&out.stderr),
        ))
    }
}

// Run a cryptsetup command that reads the master from stdin and check its exit. Writing
// the key to the child's stdin and closing the pipe is what keeps the master off disk and
// out of the process arguments; cryptsetup reads exactly MASTER_KEY_SIZE bytes.
fn cryptsetup_with_key(
    op: &'static str,
    at: &Path,
    args: &[String],
    master: &[u8; MASTER_KEY_SIZE],
) -> Result<(), Error> {
    let mut child = Command::new("cryptsetup")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Error::step(op, at, e))?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(master);
    }
    let out = child
        .wait_with_output()
        .map_err(|e| Error::step(op, at, e))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(Error::step(op, at, tool_error(&out.stderr)))
    }
}

// A cryptsetup failure (a wrong key, device-mapper unavailable) as an io::Error carrying
// its stderr, so the boot log says why the layer would not open.
fn tool_error(stderr: &[u8]) -> std::io::Error {
    std::io::Error::other(String::from_utf8_lossy(stderr).trim().to_string())
}

/// Whether an error is the host refusing a privileged operation (mount and friends),
/// so a test can skip gracefully on an unprivileged runner rather than fail. The
/// privileged container runs these steps for real; a CI runner without privilege
/// skips them, exactly as the cells tests do.
pub fn is_unprivileged_error(e: &Error) -> bool {
    matches!(
        e,
        Error::Step { source, .. } if matches!(
            source.raw_os_error(),
            Some(libc::EPERM) | Some(libc::EACCES) | Some(libc::ENODEV) | Some(libc::ENOSYS)
        )
    )
}
