//! Keybuild: assemble the filesystems of a Horizon Key.
//!
//! A Horizon Key carries two filesystems (see `docs/03-PORTABILITY-AND-BOOT.md`): an
//! immutable base image, mounted read-only, holding the OS, and a persistent data
//! partition holding the writable overlay layer and the identity store. This crate is
//! the host-side tool that builds them. It is the producer side of the contract the
//! `init` crate consumes: keybuild writes the partition labels and emits the kernel
//! command line, and init finds the partitions by those labels and parses that command
//! line, so the two agree by sharing `init`'s types rather than by convention.
//!
//! [`build_base`] materializes a minimal base skeleton (the standard mount directories
//! and an os-release) and, when a spec names them, populates the real userland: each
//! binary at `/usr/bin/<name>` together with its shared-library closure ([`ldd_closure`])
//! and an `ld.so.cache`, the kernel modules a spec lists at `/lib/modules/<version>` with
//! their `modules.dep` closure ([`module_closure`]), and the named firmware blobs at
//! `/lib/firmware`, so the base runs a program and drives real hardware. It then packs
//! the tree into a reproducible squashfs, so the same inputs yield byte-identical bytes
//! and the base can be verified by hash. The build shells out to `mksquashfs` (and
//! `ldd`/`ldconfig` when installing binaries), doing no kernel work itself, so the crate
//! builds and the pure parts ([`parse_ldd`], [`parse_modules_dep`], [`module_closure`],
//! the install-path mapping) test on every host; only the tests that mount and run the
//! result need a Linux kernel and are gated, run for real in a privileged container. The
//! module dependency closure and placement are plain filesystem work, so they are proven
//! everywhere; producing the binary module index (`modules.dep.bin`) the kernel's module
//! autoloader consults is a `depmod` pass that lands with the real kernel toolchain.
//!
//! [`build_verity`] then makes the base tamper-evident: it builds a SHA-256 dm-verity
//! Merkle hash tree over `base.squashfs` (see [`mod@verity`]) and writes the hash device to
//! `base.verity`, returning the root hash that anchors it. The tree is owned pure Rust, not
//! a shell-out, so it builds and the hashing tests run on any host; a gated test proves the
//! bytes match `veritysetup format` exactly, and the kernel's `dm-verity` open is
//! eye-verified by booting.
//!
//! [`build_home`] builds the writable side a Home Surface persists into: a LUKS2 container
//! (`home.img`) keyed by the identity master, holding the OverlayFS upper encrypted at
//! rest (see [`mod@luks`]). Unlike verity this shells out to `cryptsetup`, because LUKS2's
//! format is complex and security-critical and the kernel's `dm-crypt` open is testable
//! here, so the whole round-trip is proven for real in the container rather than matched
//! byte-for-byte.
//!
//! [`build_esp`] builds the one partition UEFI firmware reads directly: a FAT EFI System
//! Partition (`esp.img`) holding the bootloader, kernel, and initramfs. Like verity and the
//! GPT it owns the format (a minimal FAT16/FAT32 writer, see [`mod@fat`]) rather than
//! shelling out, because the container has no `mkfs.fat`; it is proven by loop-mounting the
//! self-built ESP as `vfat` in the container. [`build_disk`] then lays the ESP, base, data,
//! and Home images side by side under one GPT into a bootable `key.img` (see [`mod@gpt`]).
//!
//! [`build_initramfs`] builds the root filesystem the kernel unpacks before any disk is
//! mounted: a gzip-compressed newc cpio archive (`initramfs.img`) holding `/init`
//! (`horizon-init`) with its shared-library closure, `cryptsetup` (the one tool the init
//! shells out to), and the boot-path kernel modules. It owns the cpio format (see
//! [`mod@cpio`]) for the same reasons verity, the GPT, and FAT are owned, because the
//! container has no `cpio` or `busybox`; the init does its mounting, overlay assembly, and
//! `switch_root` with syscalls, so no shell or coreutils are vendored, only `cryptsetup`.
//! The compression shells out to `gzip` (present, like `mksquashfs`/`cryptsetup`), while the
//! archive itself is owned. There is no cpio tool to cross-check, so it is proven by the
//! reader half ([`cpio::read`]) round-tripping the writer and a gated container test that
//! gunzips and inspects a built archive; the kernel unpacking it is eye-verified at boot.

pub mod cpio;
mod error;
pub mod fat;
pub mod gpt;
pub mod luks;
pub mod verity;

pub use error::{Error, Result};
pub use gpt::Guid;
pub use verity::{Verity, VerityParams};
// The HORIZON-HOME label is part of the build/boot contract, so it lives in `init`
// alongside the base and data labels and is re-exported here, shared by type rather than
// duplicated. build_home writes it on the Home layer's inner filesystem.
pub use init::HOME_LABEL;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

pub use init::ModeChoice;
use init::{BASE_LABEL, DATA_LABEL};

/// The immutable base image's filename under a spec's output directory.
pub const BASE_IMAGE: &str = "base.squashfs";

/// The persistent data image's filename under a spec's output directory.
pub const DATA_IMAGE: &str = "data.img";

/// The base image's dm-verity hash device filename under a spec's output directory.
pub const VERITY_IMAGE: &str = "base.verity";

/// The encrypted Home writable layer's filename under a spec's output directory: a LUKS2
/// container holding the OverlayFS upper, keyed by the identity master.
pub const HOME_IMAGE: &str = "home.img";

/// The EFI System Partition image's filename: a FAT filesystem firmware reads the bootloader,
/// kernel, and initramfs from.
pub const ESP_IMAGE: &str = "esp.img";

/// The partition label (GPT PARTLABEL) and FAT volume label of the ESP.
pub const ESP_LABEL: &str = "HORIZON-ESP";

/// The initramfs image's filename: a gzip-compressed newc cpio archive holding `/init`
/// (`horizon-init`), `cryptsetup`, and the boot-path kernel modules, the root filesystem the
/// kernel unpacks before the real root is mounted. A bootloader loads it alongside the
/// kernel; the bootloader step writes it into the ESP.
pub const INITRAMFS_IMAGE: &str = "initramfs.img";

/// The assembled bootable disk's filename: a GPT image with the base, data, and Home
/// partitions laid side by side, the artifact a bootloader and a kernel are written onto.
pub const DISK_IMAGE: &str = "key.img";

/// The parameters of a Key to build: where to write it, the partition labels and
/// filesystems init looks for, the default boot mode, and how the system names itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySpec {
    /// The directory build artifacts are written into.
    pub out: PathBuf,
    /// The label written on the base partition and named on the boot command line.
    pub base_label: String,
    /// The label written on the data partition and named on the boot command line.
    pub data_label: String,
    pub basefs: String,
    pub datafs: String,
    /// The size of the data partition image, in mebibytes.
    pub data_size_mb: u64,
    /// The size of the encrypted Home writable layer image, in mebibytes. Larger than
    /// the data partition because it holds the bulk OS state; the LUKS2 header takes a
    /// fixed ~16 MiB off the top, so a tiny value leaves little usable space.
    pub home_size_mb: u64,
    /// The size of the FAT EFI System Partition image, in mebibytes. At or above 64 MiB the
    /// ESP is formatted FAT32 (the firmware-friendly default); below it, FAT16. Holds the
    /// bootloader, kernel, and initramfs, so the default leaves room for them.
    pub esp_size_mb: u64,
    /// The boot mode the command line requests (Auto picks Home or Ghost at boot).
    pub mode: ModeChoice,
    pub os_name: String,
    pub os_id: String,
    pub os_version: String,
    /// Host binaries to install into the base's `/usr/bin`, each with its shared-library
    /// closure. Empty builds a skeleton-only base (the reproducible default the pure
    /// tests use); naming `horizon` and `horizon-init` here is what makes the base boot.
    pub userland: Vec<PathBuf>,
    /// The kernel version whose modules to install, naming the `<modules_root>/<version>`
    /// subtree to harvest. Required when `modules` is non-empty.
    pub kernel_version: Option<String>,
    /// Where to read the kernel's `/lib/modules` tree from (the host's by default; a test
    /// or a cross build points it at a kernel tree it produced).
    pub modules_root: PathBuf,
    /// Kernel modules to install by name; each is installed at its path under
    /// `/lib/modules/<version>` together with its `modules.dep` dependency closure, so a
    /// driver and everything it loads land together. Empty installs no modules.
    pub modules: Vec<String>,
    /// Where to read firmware blobs from (the host's `/lib/firmware` by default).
    pub firmware_root: PathBuf,
    /// Firmware blobs to install, each a path relative to `firmware_root`, copied to the
    /// same path under `/lib/firmware`. Empty installs no firmware.
    pub firmware: Vec<String>,
    /// The binary installed as the initramfs `/init`, the program the kernel execs as PID 1,
    /// with its shared-library closure. This is `horizon-init`. Required by
    /// [`build_initramfs`]; unused by the base build.
    pub init_bin: Option<PathBuf>,
    /// Extra binaries to install into the initramfs, each at `/usr/sbin/<name>` with its
    /// shared-library closure. This is `cryptsetup` (the one external tool `horizon-init`
    /// shells out to, for the Home LUKS open); the rest of the boot is syscalls in `init`.
    pub initramfs_bins: Vec<PathBuf>,
    /// Boot-path kernel modules to install into the initramfs (the drivers needed to reach
    /// the real root: squashfs, overlay, the block driver), with their `modules.dep`
    /// closure. Uses `kernel_version`/`modules_root` like the base modules. Empty installs
    /// none; a module-free kernel (everything built in) needs no initramfs modules.
    pub initramfs_modules: Vec<String>,
}

impl KeySpec {
    /// A spec writing into `out` with Horizon's standard labels and filesystems, the
    /// ones `init`'s defaults look for, so a Key built this way boots with no explicit
    /// command line.
    pub fn new(out: impl Into<PathBuf>) -> KeySpec {
        KeySpec {
            out: out.into(),
            base_label: BASE_LABEL.to_string(),
            data_label: DATA_LABEL.to_string(),
            basefs: "squashfs".to_string(),
            datafs: "ext4".to_string(),
            data_size_mb: 64,
            home_size_mb: 256,
            esp_size_mb: 128,
            mode: ModeChoice::Auto,
            os_name: "Horizon OS".to_string(),
            os_id: "horizon".to_string(),
            os_version: env!("CARGO_PKG_VERSION").to_string(),
            userland: Vec::new(),
            kernel_version: None,
            modules_root: PathBuf::from("/lib/modules"),
            modules: Vec::new(),
            firmware_root: PathBuf::from("/lib/firmware"),
            firmware: Vec::new(),
            init_bin: None,
            initramfs_bins: Vec::new(),
            initramfs_modules: Vec::new(),
        }
    }
}

/// The kernel command line a bootloader passes so `init` finds this Key's partitions.
/// It names the base and data by label, their filesystems, and the boot mode; the
/// `init` parser reads exactly these tokens back, so a build and a boot cannot drift.
pub fn boot_cmdline(spec: &KeySpec) -> String {
    let mode = match spec.mode {
        ModeChoice::Auto => "auto",
        ModeChoice::Home => "home",
        ModeChoice::Ghost => "ghost",
    };
    format!(
        "horizon.base=LABEL={} horizon.basefs={} horizon.data=LABEL={} horizon.datafs={} horizon.mode={}",
        spec.base_label, spec.basefs, spec.data_label, spec.datafs, mode
    )
}

/// The minimal contents of the immutable base: the standard mountpoint directories the
/// init moves the kernel filesystems onto, plus an os-release naming the system. Kept
/// pure (no filesystem touched) so it is asserted with no build tools.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skeleton {
    pub dirs: Vec<String>,
    pub os_release: String,
}

pub fn base_skeleton(spec: &KeySpec) -> Skeleton {
    let dirs = [
        "dev", "proc", "sys", "run", "tmp", "etc", "var", "usr", "usr/bin",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    Skeleton {
        dirs,
        os_release: os_release(spec),
    }
}

fn os_release(spec: &KeySpec) -> String {
    format!(
        "NAME=\"{name}\"\nID={id}\nVERSION=\"{ver}\"\nPRETTY_NAME=\"{name} {ver}\"\n",
        name = spec.os_name,
        id = spec.os_id,
        ver = spec.os_version
    )
}

/// Build the immutable base image: materialize the [`base_skeleton`] into a staging
/// tree and pack it into a reproducible squashfs at `<out>/base.squashfs`. The squashfs
/// is built root-owned, without xattrs, and with fixed timestamps, so the same skeleton
/// always yields byte-identical bytes. Returns the path to the image.
pub fn build_base(spec: &KeySpec) -> Result<PathBuf> {
    std::fs::create_dir_all(&spec.out)?;

    // A clean staging tree each time, so the input to mksquashfs is deterministic.
    let staging = spec.out.join("base.staging");
    if staging.exists() {
        std::fs::remove_dir_all(&staging)?;
    }
    materialize(&base_skeleton(spec), &staging)?;

    // Populate the real userland (the binaries plus their shared-library closure) when
    // the spec names any; an empty userland leaves the reproducible skeleton untouched.
    if !spec.userland.is_empty() {
        populate_userland(&staging, &spec.userland)?;
    }

    // Install the named kernel modules with their dependency closure and the named
    // firmware blobs, so the base drives hardware; both are empty by default, leaving
    // the skeleton-only base byte-for-byte as it was.
    if !spec.modules.is_empty() {
        let version = spec
            .kernel_version
            .as_deref()
            .ok_or(Error::NoKernelVersion)?;
        populate_modules(&staging, &spec.modules_root, version, &spec.modules)?;
    }
    if !spec.firmware.is_empty() {
        populate_firmware(&staging, &spec.firmware_root, &spec.firmware)?;
    }

    let out = spec.out.join(BASE_IMAGE);
    if out.exists() {
        std::fs::remove_file(&out)?;
    }

    let mut cmd = Command::new("mksquashfs");
    cmd.arg(&staging)
        .arg(&out)
        // -noappend overwrites; the rest pin uid/gid, xattrs, and every timestamp so the
        // bytes are reproducible.
        .args([
            "-noappend",
            "-all-root",
            "-no-xattrs",
            "-mkfs-time",
            "0",
            "-all-time",
            "0",
        ])
        .stdout(std::process::Stdio::null());
    run(cmd, "mksquashfs")?;

    let _ = std::fs::remove_dir_all(&staging);
    Ok(out)
}

/// Build the persistent data partition: a labeled ext4 image at `<out>/data.img`, sized
/// per the spec. This is the writable side of the Key: the init lays the overlay upper
/// and work directories and the identity store onto it, so unlike the base it is not
/// reproducible, it is mutable state. Shells out to `mkfs.ext4`. Returns the image path.
pub fn build_data(spec: &KeySpec) -> Result<PathBuf> {
    std::fs::create_dir_all(&spec.out)?;
    let out = spec.out.join(DATA_IMAGE);

    // A fresh file sized to the partition; mkfs.ext4 lays the filesystem into it.
    let file = std::fs::File::create(&out)?;
    file.set_len(spec.data_size_mb * 1024 * 1024)?;
    drop(file);

    let mut cmd = Command::new("mkfs.ext4");
    cmd.args(["-F", "-q", "-L"])
        .arg(&spec.data_label)
        .arg(&out)
        .stdout(std::process::Stdio::null());
    run(cmd, "mkfs.ext4")?;
    Ok(out)
}

/// Build the encrypted Home writable layer: a LUKS2 container at `<out>/home.img`, sized
/// per the spec and keyed by `master` (the identity master `boot` recovers), with an
/// empty ext4 filesystem laid inside it. This is the persistent OverlayFS upper for a
/// Home (Known) Surface, so it is encrypted at rest: a lost Key reveals nothing without
/// the identity. Returns the image path.
///
/// Shells out to `cryptsetup` (see [`mod@luks`]) and `mkfs.ext4`. Formatting writes only
/// the LUKS header, but opening the volume to lay the inner filesystem needs
/// device-mapper, so the whole call runs where that is permitted (the privileged build
/// container) and is gated in tests; the mapper is always closed, even when `mkfs` fails,
/// so a build never leaks an open mapping. The master is fed to cryptsetup on stdin, so
/// it is never written to disk.
pub fn build_home(spec: &KeySpec, master: &[u8; luks::MASTER_KEY_SIZE]) -> Result<PathBuf> {
    std::fs::create_dir_all(&spec.out)?;
    let out = spec.out.join(HOME_IMAGE);

    // A fresh file sized to the partition; cryptsetup writes the LUKS header into it and
    // the inner ext4 lives in the rest.
    let file = std::fs::File::create(&out)?;
    file.set_len(spec.home_size_mb * 1024 * 1024)?;
    drop(file);

    luks::format(&out, master)?;

    // Open the volume, lay an empty ext4 inside, then close, closing even if mkfs fails so
    // the device-mapper node is never left behind. The mapper name is unique to this build
    // so concurrent builds do not collide on one global name.
    let mapper = format!("horizon-home-build-{}", std::process::id());
    let dev = luks::open(&out, master, &mapper)?;
    let mkfs = {
        let mut cmd = Command::new("mkfs.ext4");
        cmd.args(["-F", "-q", "-L", HOME_LABEL])
            .arg(&dev)
            .stdout(std::process::Stdio::null());
        run(cmd, "mkfs.ext4")
    };
    luks::close(&mapper)?;
    mkfs?;
    Ok(out)
}

/// What a verity build produced: the hash device image and the root hash that anchors it.
/// The root is the trust anchor a bootloader carries (signed or measured) and hands the
/// kernel's `dm-verity` target, which then catches any tampering of the immutable base.
#[derive(Debug, Clone)]
pub struct VerityArtifact {
    /// The hash device image written next to the base.
    pub image: PathBuf,
    pub root_hash: [u8; verity::DIGEST_SIZE],
    pub data_blocks: u64,
    pub levels: usize,
}

impl VerityArtifact {
    /// The root hash as lowercase hex, the form a boot command line carries.
    pub fn root_hex(&self) -> String {
        verity::to_hex(&self.root_hash)
    }
}

/// Build the dm-verity hash device over the immutable base: read `<out>/base.squashfs`,
/// compute its [`verity::format`] Merkle tree with the reproducible defaults, and write the
/// hash device to `<out>/base.verity`. Returns the image path and the root hash. The base
/// must already be built ([`build_base`]). The hash tree and root are a pure function of the
/// base bytes, so a reproducible base yields a reproducible hash device and root; the
/// kernel's `dm-verity` opens this image unchanged (eye-verified by booting), and a gated
/// test proves the bytes match `veritysetup format` exactly.
pub fn build_verity(spec: &KeySpec) -> Result<VerityArtifact> {
    let base = spec.out.join(BASE_IMAGE);
    // The base is a modest image; read it whole. (Streaming the data blocks is a later
    // refinement if base images ever grow large enough to matter.)
    let data = std::fs::read(&base)?;
    let v = verity::format(&data, &VerityParams::default());

    let out = spec.out.join(VERITY_IMAGE);
    std::fs::write(&out, &v.hash_device)?;
    Ok(VerityArtifact {
        image: out,
        root_hash: v.root_hash,
        data_blocks: v.data_blocks,
        levels: v.levels,
    })
}

/// Build the FAT EFI System Partition image at `<out>/esp.img`, sized per the spec
/// ([`KeySpec::esp_size_mb`]) and holding `tree`, the bootloader/kernel/initramfs to lay into
/// it. The FAT format is owned in pure Rust ([`mod@fat`]), so this writes the image directly
/// with no `mkfs.fat`, and the result is reproducible. Returns the image path. The kernel and
/// initramfs files are added by later steps; [`build_esp`] lays a default skeleton.
pub fn build_esp_with(spec: &KeySpec, tree: &fat::Dir) -> Result<PathBuf> {
    std::fs::create_dir_all(&spec.out)?;
    let out = spec.out.join(ESP_IMAGE);
    let bytes = fat::format(
        spec.esp_size_mb * 1024 * 1024,
        tree,
        &fat::Params::for_label(ESP_LABEL),
    )?;
    std::fs::write(&out, &bytes)?;
    Ok(out)
}

/// Build the ESP with the default skeleton: the `/EFI/BOOT` directory the removable-media
/// bootloader path lives in, so the partition is a valid, mountable FAT volume with the
/// directory structure a bootloader is later written into. Once the bootloader, kernel, and
/// initramfs exist, the step that builds them passes a populated tree to [`build_esp_with`].
pub fn build_esp(spec: &KeySpec) -> Result<PathBuf> {
    let mut tree = fat::Dir::new();
    tree.mkdir("EFI/BOOT")?;
    build_esp_with(spec, &tree)
}

/// Build the initramfs: the root filesystem the kernel unpacks before any disk is mounted, a
/// gzip-compressed newc cpio archive at `<out>/initramfs.img`. It holds `/init` (the
/// `init_bin`, `horizon-init`) with its shared-library closure, each extra `initramfs_bins`
/// binary (`cryptsetup`) under `/usr/sbin` with its closure, the boot-path `initramfs_modules`
/// with their `modules.dep` closure, and the `/dev/console` and `/dev/null` device nodes the
/// init needs for console output before it mounts devtmpfs.
///
/// No `busybox` or coreutils are vendored: `horizon-init` does its mounting, overlay
/// assembly, bind, move, and `switch_root` with syscalls and recovers the identity master
/// in-process, shelling out only to `cryptsetup` to open the encrypted Home layer, so the
/// boot path is one real program plus that one tool, not a shell driving applets. The
/// archive is assembled with the same binary-and-closure machinery as the base
/// ([`ldd_closure`], [`build_ld_so_cache`], [`populate_modules`]) into a staging tree, which
/// [`cpio::read_dir_tree`] imports; the device nodes (which a staging directory cannot hold
/// without privilege) are added to the tree directly, and the result is gzip-compressed.
///
/// Needs `ldd`/`ldconfig`/`gzip`, so it runs on a Linux build host like [`build_base`]'s
/// userland path; errors with [`Error::NoInitBin`] if no `init_bin` is set.
pub fn build_initramfs(spec: &KeySpec) -> Result<PathBuf> {
    let init_bin = spec.init_bin.as_ref().ok_or(Error::NoInitBin)?;
    std::fs::create_dir_all(&spec.out)?;

    // A clean staging tree each time, so the input to the cpio packer is deterministic.
    let staging = spec.out.join("initramfs.staging");
    if staging.exists() {
        std::fs::remove_dir_all(&staging)?;
    }
    // The mountpoints early_mounts needs (/dev, /proc, /sys must exist before they are
    // mounted onto) plus the standard homes for the tools and the loader cache. The closure
    // copy creates /lib/... as it goes; these are the directories that must exist regardless.
    for d in [
        "dev", "proc", "sys", "run", "tmp", "root", "etc", "usr", "usr/bin", "usr/sbin",
    ] {
        std::fs::create_dir_all(staging.join(d))?;
    }

    // /init is the program the kernel execs as PID 1 (horizon-init), at the root with its
    // shared-library closure; each extra binary (cryptsetup) goes under /usr/sbin with its
    // own closure. The closures are collected across every binary and deduplicated, so a
    // library init and cryptsetup share is copied once, exactly as the base userland does.
    copy_file(init_bin, &staging.join("init"))?;
    let mut libs: Vec<PathBuf> = ldd_closure(init_bin)?;
    for bin in &spec.initramfs_bins {
        copy_file(bin, &staging.join(bin_sbin_path(bin)?))?;
        for lib in ldd_closure(bin)? {
            if !libs.contains(&lib) {
                libs.push(lib);
            }
        }
    }
    for lib in &libs {
        // Strip the leading slash so /lib/.../libc.so.6 lands under the initramfs root.
        let rel = lib.strip_prefix("/").unwrap_or(lib);
        copy_file(lib, &staging.join(rel))?;
    }
    build_ld_so_cache(&staging)?;

    // The boot-path kernel modules and their dependency closure, if the kernel needs any
    // loaded to reach the root (squashfs, overlay, the block driver). A kernel with those
    // built in needs none, leaving no modules directory.
    if !spec.initramfs_modules.is_empty() {
        let version = spec
            .kernel_version
            .as_deref()
            .ok_or(Error::NoKernelVersion)?;
        populate_modules(
            &staging,
            &spec.modules_root,
            version,
            &spec.initramfs_modules,
        )?;
    }

    // Import the staging tree into a cpio archive, then add the device nodes a staging
    // directory on disk cannot hold without privilege: /dev/console so the init's console
    // output is visible before it mounts devtmpfs, and /dev/null. The kernel creates the
    // nodes on unpack.
    let mut tree = cpio::read_dir_tree(&staging)?;
    tree.device("dev/console", 0o600, cpio::NodeKind::Char, 5, 1)?;
    tree.device("dev/null", 0o666, cpio::NodeKind::Char, 1, 3)?;
    let archive = cpio::write(&tree);

    // gzip the archive into the final image, the form a bootloader loads and the kernel
    // detects and decompresses.
    let out = spec.out.join(INITRAMFS_IMAGE);
    gzip_to(&archive, &out)?;

    let _ = std::fs::remove_dir_all(&staging);
    Ok(out)
}

/// A partition to place on the assembled disk: the image file that fills it, its GPT type
/// GUID, and its partition name (the PARTLABEL). [`write_disk`] reads each image's size,
/// lays the partitions out under a GPT, and copies the images into place.
#[derive(Debug, Clone)]
pub struct DiskPart {
    pub image: PathBuf,
    pub type_guid: gpt::Guid,
    pub name: String,
}

/// Where a partition landed on the assembled disk: its name and the byte offset and length
/// of its region. [`write_disk`] returns one per partition, in order, so a later step (such
/// as writing a bootloader into the ESP) knows where each partition begins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Placement {
    pub name: String,
    pub offset: u64,
    pub size: u64,
}

/// Assemble `parts` into a GPT disk image at `out`. Reads each partition image's size,
/// computes the table with [`gpt::build`] (the disk and partition GUIDs derived from the
/// names, so the table is reproducible), creates the disk file sized to hold everything,
/// streams each image into its partition offset, and writes the primary and backup GPT
/// structures. Returns each partition's [`Placement`] on the disk. Tool-free, plain file IO
/// over images already built, so it runs and is testable on any host; a gated test
/// cross-checks the result against `sgdisk` and a container test attaches each partition by
/// its returned offset to confirm the right filesystem landed there.
pub fn write_disk(out: &Path, parts: &[DiskPart]) -> Result<Vec<Placement>> {
    use std::io::{Seek, SeekFrom, Write};

    // Size every partition from its image, failing if one has not been built yet.
    let mut specs = Vec::with_capacity(parts.len());
    for p in parts {
        let size = match std::fs::metadata(&p.image) {
            Ok(m) => m.len(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(Error::NoImage(p.image.clone()));
            }
            Err(e) => return Err(e.into()),
        };
        specs.push(gpt::PartSpec {
            type_guid: p.type_guid,
            unique_guid: gpt::Guid::derive(&p.name),
            name: p.name.clone(),
            size,
        });
    }

    let disk = gpt::build(gpt::Guid::derive("horizon-key-disk"), &specs);

    // A fresh file sized to the whole disk; the gaps between partitions stay sparse zeros.
    if out.exists() {
        std::fs::remove_file(out)?;
    }
    let mut f = std::fs::File::create(out)?;
    f.set_len(disk.total_bytes)?;

    // The GPT structures (front at offset 0, backup at the tail), then each partition image
    // streamed to its offset so a large image is never read whole into memory.
    f.write_all(&disk.front)?;
    f.seek(SeekFrom::Start(disk.back_offset))?;
    f.write_all(&disk.back)?;
    let mut placements = Vec::with_capacity(parts.len());
    for (p, placed) in parts.iter().zip(&disk.parts) {
        let mut src = std::fs::File::open(&p.image)?;
        f.seek(SeekFrom::Start(placed.offset))?;
        std::io::copy(&mut src, &mut f)?;
        placements.push(Placement {
            name: p.name.clone(),
            offset: placed.offset,
            size: placed.size,
        });
    }
    f.flush()?;
    Ok(placements)
}

/// Assemble a Key's filesystems into a bootable GPT disk at `<out>/key.img`: the FAT ESP, the
/// immutable base, the plain data store, and the encrypted Home layer, written as the
/// HORIZON-ESP, HORIZON-BASE, HORIZON-DATA, and HORIZON-HOME partitions. The ESP is partition
/// one (the conventional place firmware looks) and carries the EFI System Partition type GUID
/// so firmware recognizes it; the other three carry the generic Linux filesystem type GUID
/// and are told apart by their labels, which is how `init` resolves them. Each image must
/// already be built ([`build_esp`], [`build_base`], [`build_data`], [`build_home`]); a missing
/// one is an error.
pub fn build_disk(spec: &KeySpec) -> Result<PathBuf> {
    let linux = gpt::Guid::parse(gpt::LINUX_FS_TYPE).expect("static type guid parses");
    let esp = gpt::Guid::parse(gpt::ESP_TYPE).expect("static type guid parses");
    let parts = [
        DiskPart {
            image: spec.out.join(ESP_IMAGE),
            type_guid: esp,
            name: ESP_LABEL.to_string(),
        },
        DiskPart {
            image: spec.out.join(BASE_IMAGE),
            type_guid: linux,
            name: spec.base_label.clone(),
        },
        DiskPart {
            image: spec.out.join(DATA_IMAGE),
            type_guid: linux,
            name: spec.data_label.clone(),
        },
        DiskPart {
            image: spec.out.join(HOME_IMAGE),
            type_guid: linux,
            name: HOME_LABEL.to_string(),
        },
    ];
    let out = spec.out.join(DISK_IMAGE);
    write_disk(&out, &parts)?;
    Ok(out)
}

fn materialize(skeleton: &Skeleton, staging: &Path) -> Result<()> {
    for d in &skeleton.dirs {
        std::fs::create_dir_all(staging.join(d))?;
    }
    std::fs::write(staging.join("etc/os-release"), &skeleton.os_release)?;
    Ok(())
}

/// Parse `ldd` stdout into the absolute paths of the shared objects a binary loads:
/// every `soname => /path` resolution and the bare `/path` interpreter line, dropping
/// the kernel's virtual DSO (linux-vdso / linux-gate) and any unresolved entry. The
/// trailing ` (0x...)` load address ldd prints is stripped, and duplicates are folded.
/// Pure text handling, so it is unit-tested with sample output on every host while the
/// [`ldd_closure`] call that produces the text is Linux-only.
pub fn parse_ldd(output: &str) -> Vec<PathBuf> {
    let mut libs: Vec<PathBuf> = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        if line.starts_with("linux-vdso") || line.starts_with("linux-gate") {
            continue;
        }
        let path = if let Some((_, rhs)) = line.split_once("=>") {
            // "libc.so.6 => /lib/.../libc.so.6 (0x...)"; "=> not found" has no path.
            let rhs = strip_load_address(rhs.trim());
            if rhs.is_empty() || rhs == "not found" {
                continue;
            }
            rhs
        } else if line.starts_with('/') {
            // The interpreter line: "/lib/ld-linux-aarch64.so.1 (0x...)".
            strip_load_address(line)
        } else {
            // "statically linked", a soname header, a blank line: nothing to copy.
            continue;
        };
        let p = PathBuf::from(path);
        if !libs.contains(&p) {
            libs.push(p);
        }
    }
    libs
}

// Drop the trailing " (0x...)" load address ldd prints after a resolved path.
fn strip_load_address(s: &str) -> &str {
    match s.rfind(" (0x") {
        Some(i) => s[..i].trim_end(),
        None => s.trim(),
    }
}

/// The shared-library closure of a dynamically linked binary: every shared object it
/// transitively needs plus the ELF interpreter, as resolved absolute paths. Shells out
/// to `ldd`, whose output [`parse_ldd`] reads; a statically linked or non-ELF input has
/// an empty closure rather than an error. There is no `ldd` on a non-Linux host, so the
/// populate path that calls this runs in the build container.
pub fn ldd_closure(bin: &Path) -> Result<Vec<PathBuf>> {
    let mut cmd = Command::new("ldd");
    cmd.arg(bin);
    let out = match cmd.output() {
        Ok(o) => o,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(Error::Missing("ldd")),
        Err(e) => return Err(Error::Io(e)),
    };
    if !out.status.success() {
        // ldd exits nonzero for a static or non-dynamic ELF; that is an empty closure.
        let text = String::from_utf8_lossy(&out.stdout);
        let err = String::from_utf8_lossy(&out.stderr);
        if text.contains("not a dynamic executable") || err.contains("not a dynamic executable") {
            return Ok(Vec::new());
        }
        return Err(Error::Tool {
            name: "ldd",
            code: out.status.code(),
            stderr: err.trim().to_string(),
        });
    }
    Ok(parse_ldd(&String::from_utf8_lossy(&out.stdout)))
}

/// Parse a `modules.dep` file into a map from each module's path (relative to the
/// `/lib/modules/<version>` directory) to the paths of the modules it depends on. Each
/// line is `<module>: <dep> <dep> ...` with paths relative to the modules directory;
/// blank and colon-less lines are skipped. A module with no dependencies still appears,
/// with an empty list, so the map is the full set of modules the kernel ships. Pure text
/// handling, so it is unit-tested with sample output on every host while the
/// [`populate_modules`] call that reads a real `modules.dep` runs on a build host.
pub fn parse_modules_dep(text: &str) -> BTreeMap<PathBuf, Vec<PathBuf>> {
    let mut deps = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        let Some((target, rest)) = line.split_once(':') else {
            continue;
        };
        let target = target.trim();
        if target.is_empty() {
            continue;
        }
        let needs = rest.split_whitespace().map(PathBuf::from).collect();
        deps.insert(PathBuf::from(target), needs);
    }
    deps
}

// The canonical name of a module file: its base name with the `.ko` (and any compression)
// suffix stripped and `-` normalized to `_`, the equivalence the kernel's module tools
// use, so a request for `virtio_net` matches a file named `virtio-net.ko.xz`.
fn module_name(relpath: &Path) -> String {
    let file = relpath
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or_default();
    let base = file
        .strip_suffix(".ko.xz")
        .or_else(|| file.strip_suffix(".ko.zst"))
        .or_else(|| file.strip_suffix(".ko.gz"))
        .or_else(|| file.strip_suffix(".ko"))
        .unwrap_or(file);
    base.replace('-', "_")
}

/// The dependency closure of a set of requested module names: each named module's file
/// plus every module it transitively depends on, as paths relative to the modules
/// directory, sorted. A name resolves against each module file's canonical name
/// ([`module_name`]), so `ext4` finds `kernel/fs/ext4/ext4.ko` and dashes and underscores
/// are interchangeable. `modules.dep` already lists a module's full transitive
/// dependencies, but the walk is correct either way and folds duplicates. A name that no
/// module matches is an error, not a silent omission: a base must carry every driver it
/// was told to.
pub fn module_closure(
    deps: &BTreeMap<PathBuf, Vec<PathBuf>>,
    requested: &[String],
) -> Result<Vec<PathBuf>> {
    // Index every module file by its canonical name so a requested name resolves to a path.
    let mut by_name: BTreeMap<String, &PathBuf> = BTreeMap::new();
    for path in deps.keys() {
        by_name.entry(module_name(path)).or_insert(path);
    }

    let mut stack: Vec<PathBuf> = Vec::new();
    let mut unknown: Vec<String> = Vec::new();
    for name in requested {
        match by_name.get(&name.replace('-', "_")) {
            Some(p) => stack.push((*p).clone()),
            None => unknown.push(name.clone()),
        }
    }
    if !unknown.is_empty() {
        return Err(Error::UnknownModules(unknown));
    }

    let mut closure: BTreeSet<PathBuf> = BTreeSet::new();
    while let Some(m) = stack.pop() {
        if !closure.insert(m.clone()) {
            continue;
        }
        if let Some(needs) = deps.get(&m) {
            for d in needs {
                if !closure.contains(d) {
                    stack.push(d.clone());
                }
            }
        }
    }
    Ok(closure.into_iter().collect())
}

/// Emit a `modules.dep` describing exactly `closure`: each module's line with the subset
/// of its dependencies that are themselves in the closure (all of them, since the closure
/// is dependency-complete), modules in sorted order. Deterministic, so a base populated
/// with modules stays reproducible, and it round-trips through [`parse_modules_dep`].
fn emit_modules_dep(closure: &[PathBuf], deps: &BTreeMap<PathBuf, Vec<PathBuf>>) -> String {
    let present: BTreeSet<&PathBuf> = closure.iter().collect();
    let mut out = String::new();
    for m in closure {
        out.push_str(&m.to_string_lossy());
        out.push(':');
        if let Some(needs) = deps.get(m) {
            for d in needs {
                if present.contains(d) {
                    out.push(' ');
                    out.push_str(&d.to_string_lossy());
                }
            }
        }
        out.push('\n');
    }
    out
}

// Where a userland binary is installed inside the base: /usr/bin/<name> (relative to
// the base root), which is exactly where init's DEFAULT_INIT points, so installing the
// `horizon` binary here is what makes the pivot's exec target exist.
fn bin_install_path(bin: &Path) -> Result<PathBuf> {
    let name = bin
        .file_name()
        .ok_or_else(|| Error::NotAFile(bin.to_path_buf()))?;
    Ok(Path::new("usr/bin").join(name))
}

// Where an extra initramfs binary is installed: /usr/sbin/<name>, where cryptsetup
// conventionally lives, so its closure and any compiled-in paths line up.
fn bin_sbin_path(bin: &Path) -> Result<PathBuf> {
    let name = bin
        .file_name()
        .ok_or_else(|| Error::NotAFile(bin.to_path_buf()))?;
    Ok(Path::new("usr/sbin").join(name))
}

// gzip `data` into `out` with `gzip -n -9`, the compression the kernel reads an initramfs
// back from. Shelling out (gzip is present, like mksquashfs and cryptsetup) rather than
// owning the format: gzip is neither absent nor fiddly-and-security-irrelevant the way the
// owned formats are, and the reproducible artifact is the cpio archive, which is owned. `-n`
// drops the filename and timestamp from the gzip header so the wrapper is reproducible given
// the same archive. The archive is staged to a temp file and gzip's stdin/stdout are
// redirected to files (not piped through this process) so a large initramfs never deadlocks.
fn gzip_to(data: &[u8], out: &Path) -> Result<()> {
    let tmp = out.with_file_name("initramfs.cpio");
    std::fs::write(&tmp, data)?;
    let infile = std::fs::File::open(&tmp)?;
    let outfile = std::fs::File::create(out)?;
    // status() (not output()) so the configured stdout File is respected rather than
    // overridden by a capture pipe; gzip with no file operand reads stdin and writes stdout.
    let status = Command::new("gzip")
        .args(["-n", "-9"])
        .stdin(infile)
        .stdout(outfile)
        .status();
    let _ = std::fs::remove_file(&tmp);
    match status {
        Ok(s) if s.success() => Ok(()),
        Ok(s) => Err(Error::Tool {
            name: "gzip",
            code: s.code(),
            stderr: String::new(),
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(Error::Missing("gzip")),
        Err(e) => Err(Error::Io(e)),
    }
}

/// Install the userland into the staging tree: each binary at /usr/bin/<name>, the
/// transitive shared-library closure of all of them each at its own absolute path, and
/// an ld.so.cache so the loader resolves them. The closure is collected across every
/// binary and deduplicated, so a library shared by two binaries is copied once.
fn populate_userland(staging: &Path, bins: &[PathBuf]) -> Result<()> {
    let mut libs: Vec<PathBuf> = Vec::new();
    for bin in bins {
        copy_file(bin, &staging.join(bin_install_path(bin)?))?;
        for lib in ldd_closure(bin)? {
            if !libs.contains(&lib) {
                libs.push(lib);
            }
        }
    }
    for lib in &libs {
        // Strip the leading slash so /lib/.../libc.so.6 lands under the base root.
        let rel = lib.strip_prefix("/").unwrap_or(lib);
        copy_file(lib, &staging.join(rel))?;
    }
    build_ld_so_cache(staging)
}

/// Install the requested kernel modules into the staging tree: read the source kernel's
/// `modules.dep`, compute the dependency [`module_closure`] of the requested names, copy
/// each module in the closure to its own path under `/lib/modules/<version>`, and write a
/// `modules.dep` describing exactly that closure. The closure guarantees every module
/// present has all of its dependencies present too, so the modules are self-consistent on
/// the base; the emitted `modules.dep` is deterministic, so the populated base stays
/// reproducible. Plain filesystem work (no kernel tool), so it runs and is tested on any
/// host. The binary index (`modules.dep.bin`) the kernel's autoloader prefers is a
/// `depmod` pass for the build host that has the kernel toolchain; this text `modules.dep`
/// is what that pass consumes.
fn populate_modules(
    staging: &Path,
    modules_root: &Path,
    version: &str,
    requested: &[String],
) -> Result<()> {
    let src = modules_root.join(version);
    let dep_text = std::fs::read_to_string(src.join("modules.dep"))?;
    let deps = parse_modules_dep(&dep_text);
    let closure = module_closure(&deps, requested)?;

    let dst = staging.join("lib/modules").join(version);
    for rel in &closure {
        copy_file(&src.join(rel), &dst.join(rel))?;
    }
    std::fs::create_dir_all(&dst)?;
    std::fs::write(dst.join("modules.dep"), emit_modules_dep(&closure, &deps))?;
    Ok(())
}

/// Install the named firmware blobs into the staging tree: each blob, a path relative to
/// `firmware_root`, is copied to the same path under `/lib/firmware`, where a driver finds
/// the firmware it loads by name. Firmware blobs are standalone (no dependency graph), so
/// this is a straight copy; a named blob the source lacks fails the build rather than
/// shipping a base with a silent gap. `fs::copy` follows symlinks, so a linux-firmware
/// blob behind a compatibility symlink resolves to its bytes.
fn populate_firmware(staging: &Path, firmware_root: &Path, requested: &[String]) -> Result<()> {
    let dst = staging.join("lib/firmware");
    for blob in requested {
        let rel = Path::new(blob);
        copy_file(&firmware_root.join(rel), &dst.join(rel))?;
    }
    Ok(())
}

// Copy one file into the base, creating parent directories as needed. fs::copy follows
// symlinks (a versioned .so behind its soname) and preserves the mode bits, so an
// executable or the loader stays executable; squashfs then pins ownership and
// timestamps, keeping the base reproducible.
fn copy_file(src: &Path, dst: &Path) -> Result<()> {
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::copy(src, dst)?;
    Ok(())
}

/// Build `/etc/ld.so.cache` inside the staging tree with `ldconfig -r`, so the dynamic
/// loader finds the copied libraries by soname the way it does on a normal system
/// rather than leaning on its compiled-in defaults. The cache is a deterministic
/// function of the libraries present, so the populated base stays reproducible.
fn build_ld_so_cache(staging: &Path) -> Result<()> {
    std::fs::create_dir_all(staging.join("etc"))?;
    let mut cmd = Command::new("ldconfig");
    cmd.arg("-r")
        .arg(staging)
        .stdout(std::process::Stdio::null());
    run(cmd, "ldconfig")
}

fn run(mut cmd: Command, name: &'static str) -> Result<()> {
    match cmd.output() {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => Err(Error::Tool {
            name,
            code: o.status.code(),
            stderr: String::from_utf8_lossy(&o.stderr).trim().to_string(),
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(Error::Missing(name)),
        Err(e) => Err(Error::Io(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use init::{parse_cmdline, Spec};

    #[test]
    fn cmdline_round_trips_through_the_init_parser() {
        for mode in [ModeChoice::Auto, ModeChoice::Home, ModeChoice::Ghost] {
            let mut spec = KeySpec::new("/tmp/key");
            spec.mode = mode;
            let parsed = parse_cmdline(&boot_cmdline(&spec));
            assert_eq!(parsed.base, Spec::Label(spec.base_label.clone()));
            assert_eq!(parsed.data, Spec::Label(spec.data_label.clone()));
            assert_eq!(parsed.basefs, spec.basefs);
            assert_eq!(parsed.datafs, spec.datafs);
            assert_eq!(parsed.mode, mode);
        }
    }

    #[test]
    fn default_labels_are_the_ones_init_looks_for() {
        // keybuild's defaults write the labels init's own defaults search for, so a Key
        // built with no explicit command line still boots.
        let spec = KeySpec::new("/tmp/key");
        let init_default = parse_cmdline("");
        assert_eq!(init_default.base, Spec::Label(spec.base_label));
        assert_eq!(init_default.data, Spec::Label(spec.data_label));
    }

    #[test]
    fn skeleton_has_the_mount_dirs_and_names_the_system() {
        let spec = KeySpec::new("/tmp/key");
        let sk = base_skeleton(&spec);
        for d in ["dev", "proc", "sys", "run", "etc", "usr/bin"] {
            assert!(sk.dirs.iter().any(|x| x == d), "missing base dir {d}");
        }
        assert!(sk.os_release.contains("Horizon OS"));
        assert!(sk.os_release.contains("ID=horizon"));
    }

    #[test]
    fn parse_ldd_reads_resolved_libraries_and_the_interpreter() {
        // Real aarch64 ldd output: the kernel vdso, a resolved library, the interpreter.
        let out = "\tlinux-vdso.so.1 (0x0000ffff82c4f000)\n\
                   \tlibc.so.6 => /lib/aarch64-linux-gnu/libc.so.6 (0x0000ffff82a20000)\n\
                   \t/lib/ld-linux-aarch64.so.1 (0x0000ffff82c00000)\n";
        let libs = parse_ldd(out);
        assert_eq!(
            libs,
            vec![
                PathBuf::from("/lib/aarch64-linux-gnu/libc.so.6"),
                PathBuf::from("/lib/ld-linux-aarch64.so.1"),
            ]
        );
        // The kernel's virtual DSO is never a real file, so it is dropped.
        assert!(!libs.iter().any(|p| p.to_string_lossy().contains("vdso")));
    }

    #[test]
    fn parse_ldd_skips_unresolved_and_folds_duplicates() {
        // An x86-64 shape, a missing library, and the same soname listed twice.
        let out = "\tlibfoo.so.1 => not found\n\
                   \tlibm.so.6 => /lib/x86_64-linux-gnu/libm.so.6 (0x00007f00)\n\
                   \tlibc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f10)\n\
                   \tlibm.so.6 => /lib/x86_64-linux-gnu/libm.so.6 (0x00007f20)\n\
                   \t/lib64/ld-linux-x86-64.so.2 (0x00007f30)\n";
        assert_eq!(
            parse_ldd(out),
            vec![
                PathBuf::from("/lib/x86_64-linux-gnu/libm.so.6"),
                PathBuf::from("/lib/x86_64-linux-gnu/libc.so.6"),
                PathBuf::from("/lib64/ld-linux-x86-64.so.2"),
            ]
        );
    }

    #[test]
    fn parse_ldd_of_a_static_binary_is_empty() {
        assert!(parse_ldd("\tstatically linked\n").is_empty());
        assert!(parse_ldd("").is_empty());
    }

    #[test]
    fn a_binary_installs_where_init_execs_it() {
        // The horizon binary must land at exactly init's DEFAULT_INIT, so the pivot's
        // exec target exists in the base no matter what host path it was built at.
        let rel = bin_install_path(Path::new("target/release/horizon")).unwrap();
        assert_eq!(rel, PathBuf::from("usr/bin/horizon"));
        assert_eq!(Path::new("/").join(&rel), Path::new(init::DEFAULT_INIT));
        // A path with no filename is rejected rather than silently misplaced.
        assert!(bin_install_path(Path::new("/")).is_err());
    }

    // A small but realistic modules.dep: ext4 needs crc16 and mbcache, virtio_net needs
    // virtio (the file spelled with a dash), and an unrelated sound module sits alone.
    const SAMPLE_DEP: &str = "kernel/fs/ext4/ext4.ko: kernel/lib/crc16.ko kernel/fs/mbcache.ko\n\
         kernel/lib/crc16.ko:\n\
         kernel/fs/mbcache.ko:\n\
         kernel/net/virtio-net.ko: kernel/drivers/virtio/virtio.ko\n\
         kernel/drivers/virtio/virtio.ko:\n\
         kernel/sound/foo.ko:\n";

    #[test]
    fn parse_modules_dep_reads_targets_and_deps() {
        let deps = parse_modules_dep(SAMPLE_DEP);
        assert_eq!(
            deps.get(Path::new("kernel/fs/ext4/ext4.ko")).unwrap(),
            &vec![
                PathBuf::from("kernel/lib/crc16.ko"),
                PathBuf::from("kernel/fs/mbcache.ko"),
            ]
        );
        // A module with no dependencies still appears, with an empty list.
        assert!(deps
            .get(Path::new("kernel/lib/crc16.ko"))
            .unwrap()
            .is_empty());
        // A blank or colon-less line contributes no module.
        let messy = parse_modules_dep("\nnot a dep line\nkernel/x.ko:\n");
        assert_eq!(messy.len(), 1);
        assert!(messy.contains_key(Path::new("kernel/x.ko")));
    }

    #[test]
    fn module_closure_pulls_transitive_deps_and_excludes_the_rest() {
        let deps = parse_modules_dep(SAMPLE_DEP);
        let c = module_closure(&deps, &["ext4".to_string()]).unwrap();
        assert!(c.contains(&PathBuf::from("kernel/fs/ext4/ext4.ko")));
        assert!(c.contains(&PathBuf::from("kernel/lib/crc16.ko")));
        assert!(c.contains(&PathBuf::from("kernel/fs/mbcache.ko")));
        // Unrelated modules are not dragged in.
        assert!(!c.iter().any(|p| p.to_string_lossy().contains("virtio")));
        assert!(!c.iter().any(|p| p.to_string_lossy().contains("foo")));
    }

    #[test]
    fn module_closure_normalizes_dashes_and_strips_suffixes() {
        let deps = parse_modules_dep(SAMPLE_DEP);
        // "virtio_net" (underscore) resolves the file named virtio-net.ko (dash).
        let c = module_closure(&deps, &["virtio_net".to_string()]).unwrap();
        assert!(c.contains(&PathBuf::from("kernel/net/virtio-net.ko")));
        assert!(c.contains(&PathBuf::from("kernel/drivers/virtio/virtio.ko")));
        // A compression suffix on the file is stripped for name matching.
        let xz = parse_modules_dep("kernel/crypto/aes.ko.xz:\n");
        assert_eq!(
            module_closure(&xz, &["aes".to_string()]).unwrap(),
            vec![PathBuf::from("kernel/crypto/aes.ko.xz")]
        );
    }

    #[test]
    fn module_closure_errors_on_an_unknown_module() {
        let deps = parse_modules_dep(SAMPLE_DEP);
        let err = module_closure(&deps, &["nosuchmod".to_string()]).unwrap_err();
        assert!(matches!(err, Error::UnknownModules(m) if m == vec!["nosuchmod".to_string()]));
    }

    #[test]
    fn emitted_modules_dep_round_trips_and_is_deterministic() {
        let deps = parse_modules_dep(SAMPLE_DEP);
        let closure = module_closure(&deps, &["ext4".to_string()]).unwrap();
        let emitted = emit_modules_dep(&closure, &deps);
        // Re-parsing yields exactly the closure, ext4 still carrying its deps.
        let reparsed = parse_modules_dep(&emitted);
        assert_eq!(reparsed.len(), 3);
        assert_eq!(
            reparsed.get(Path::new("kernel/fs/ext4/ext4.ko")).unwrap(),
            &vec![
                PathBuf::from("kernel/lib/crc16.ko"),
                PathBuf::from("kernel/fs/mbcache.ko"),
            ]
        );
        assert!(!reparsed.contains_key(Path::new("kernel/sound/foo.ko")));
        // Emitting again is byte-identical, so the populated base is reproducible.
        assert_eq!(emit_modules_dep(&closure, &deps), emitted);
    }

    // Build a synthesized kernel module tree under `root`/`ver` whose dependency graph is
    // SAMPLE_DEP, with each `.ko` holding its own name as a marker. No real modules or
    // kernel tools are needed: populate_modules is plain filesystem work.
    #[cfg(test)]
    fn synth_modules(root: &Path, ver: &str) {
        let moddir = root.join(ver);
        for rel in [
            "kernel/fs/ext4/ext4.ko",
            "kernel/lib/crc16.ko",
            "kernel/fs/mbcache.ko",
            "kernel/net/virtio-net.ko",
            "kernel/drivers/virtio/virtio.ko",
            "kernel/sound/foo.ko",
        ] {
            let p = moddir.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            // The marker is the module's base name, so a copied file is identifiable.
            std::fs::write(&p, module_name(Path::new(rel))).unwrap();
        }
        std::fs::write(moddir.join("modules.dep"), SAMPLE_DEP).unwrap();
    }

    #[test]
    fn populate_modules_copies_the_closure_and_writes_a_consistent_dep() {
        let src = tempfile::tempdir().unwrap();
        let ver = "6.12.0-horizon";
        synth_modules(src.path(), ver);

        let staging = tempfile::tempdir().unwrap();
        populate_modules(staging.path(), src.path(), ver, &["ext4".to_string()]).unwrap();

        let installed = staging.path().join("lib/modules").join(ver);
        assert_eq!(
            std::fs::read_to_string(installed.join("kernel/fs/ext4/ext4.ko")).unwrap(),
            "ext4"
        );
        assert!(installed.join("kernel/lib/crc16.ko").exists());
        assert!(installed.join("kernel/fs/mbcache.ko").exists());
        // The unrelated module is left out of the base entirely.
        assert!(!installed.join("kernel/sound/foo.ko").exists());
        assert!(!installed.join("kernel/net/virtio-net.ko").exists());
        // The emitted modules.dep describes exactly the installed closure.
        let dep =
            parse_modules_dep(&std::fs::read_to_string(installed.join("modules.dep")).unwrap());
        assert_eq!(dep.len(), 3);
        assert!(dep.contains_key(Path::new("kernel/fs/ext4/ext4.ko")));
        assert!(!dep.contains_key(Path::new("kernel/sound/foo.ko")));

        // Reproducible: a second populate yields the same modules.dep bytes.
        let staging2 = tempfile::tempdir().unwrap();
        populate_modules(staging2.path(), src.path(), ver, &["ext4".to_string()]).unwrap();
        assert_eq!(
            std::fs::read(installed.join("modules.dep")).unwrap(),
            std::fs::read(
                staging2
                    .path()
                    .join("lib/modules")
                    .join(ver)
                    .join("modules.dep")
            )
            .unwrap()
        );
    }

    #[test]
    fn populate_firmware_copies_named_blobs_and_fails_on_a_gap() {
        let src = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(src.path().join("rtl_nic")).unwrap();
        std::fs::write(src.path().join("rtl_nic/rtl8168.fw"), b"blob").unwrap();

        let staging = tempfile::tempdir().unwrap();
        populate_firmware(
            staging.path(),
            src.path(),
            &["rtl_nic/rtl8168.fw".to_string()],
        )
        .unwrap();
        assert_eq!(
            std::fs::read(staging.path().join("lib/firmware/rtl_nic/rtl8168.fw")).unwrap(),
            b"blob"
        );
        // A named blob the source lacks fails the build rather than shipping a gap.
        assert!(
            populate_firmware(staging.path(), src.path(), &["missing.bin".to_string()]).is_err()
        );
    }

    // A stand-in partition image of `mib` megabytes (zeros), enough for `write_disk` to size
    // and place a partition without a real filesystem or any build tool.
    fn stub(dir: &Path, name: &str, mib: u64) -> DiskPart {
        let img = dir.join(format!("{name}.img"));
        let f = std::fs::File::create(&img).unwrap();
        f.set_len(mib * 1024 * 1024).unwrap();
        let type_guid = if name == "HORIZON-ESP" {
            gpt::Guid::parse(gpt::ESP_TYPE).unwrap()
        } else {
            gpt::Guid::parse(gpt::LINUX_FS_TYPE).unwrap()
        };
        DiskPart {
            image: img,
            type_guid,
            name: name.to_string(),
        }
    }

    #[test]
    fn assembled_disk_round_trips_through_sgdisk() {
        // Assemble a disk from tiny stand-in images (no build tools, no device-mapper) and
        // have a reference GPT tool read the table back: it must verify clean and report the
        // partitions with the right names, type codes, and 1 MiB alignment. This is the
        // byte-exact proof of the table, the way the verity tests cross-check veritysetup.
        // Skips where sgdisk is absent (a bare host, darwin) and runs in CI and the
        // container.
        use std::process::Command;
        let dir = tempfile::tempdir().unwrap();
        let parts = [
            stub(dir.path(), "HORIZON-ESP", 3),
            stub(dir.path(), "HORIZON-BASE", 5),
            stub(dir.path(), "HORIZON-DATA", 4),
            stub(dir.path(), "HORIZON-HOME", 7),
        ];
        let disk = dir.path().join("key.img");
        let placed = write_disk(&disk, &parts).unwrap();
        // The first partition sits at 1 MiB; the placements are returned in order.
        assert_eq!(placed[0].offset, gpt::ALIGN_SECTORS * gpt::SECTOR);
        assert_eq!(placed.iter().map(|p| &p.name).collect::<Vec<_>>().len(), 4);

        let verify = match Command::new("sgdisk").arg("-v").arg(&disk).output() {
            Ok(o) => o,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("skipping: sgdisk not installed");
                return;
            }
            Err(e) => panic!("sgdisk: {e}"),
        };
        let vout = String::from_utf8_lossy(&verify.stdout);
        assert!(verify.status.success(), "sgdisk -v failed: {vout}");
        assert!(
            vout.contains("No problems found"),
            "sgdisk found problems: {vout}"
        );

        let print = Command::new("sgdisk")
            .arg("-p")
            .arg(&disk)
            .output()
            .unwrap();
        let pout = String::from_utf8_lossy(&print.stdout);
        for name in [
            "HORIZON-ESP",
            "HORIZON-BASE",
            "HORIZON-DATA",
            "HORIZON-HOME",
        ] {
            assert!(pout.contains(name), "sgdisk -p missing {name}:\n{pout}");
        }
        // EF00 is the ESP type code, 8300 the Linux filesystem one, derived from our GUIDs.
        assert!(pout.contains("EF00"), "missing ESP type code:\n{pout}");
        assert!(pout.contains("8300"), "missing Linux fs type code:\n{pout}");
        // The first partition is reported starting at the 1 MiB-aligned sector 2048.
        assert!(
            pout.contains("2048"),
            "first partition not 1 MiB-aligned:\n{pout}"
        );
    }
}

// Mounting the built base back, as the init's overlay lower, needs a Linux kernel, so
// it is proven for real where there is one: a privileged container packs a squashfs and
// stacks a writable overlay on it, the immutable-base + writable-overlay model the
// design turns on, now on the real image format the Key uses.
#[cfg(all(test, target_os = "linux"))]
mod linux_tests {
    use super::*;
    use init::{execute, is_unprivileged_error, Layout, MountFlags, Plan, Source, Step};
    use std::process::Command;

    // Attach `file` to a free loop device (read-only for the immutable base, writable
    // for the data partition) and return its path, or None if losetup is not permitted.
    fn losetup(file: &Path, ro: bool) -> Option<String> {
        let mut cmd = Command::new("losetup");
        cmd.args(["--find", "--show"]);
        if ro {
            cmd.arg("-r");
        }
        let out = cmd.arg(file).output().ok()?;
        if !out.status.success() {
            return None;
        }
        let dev = String::from_utf8_lossy(&out.stdout).trim().to_string();
        (!dev.is_empty()).then_some(dev)
    }

    fn losetup_d(dev: &str) {
        let _ = Command::new("losetup").arg("-d").arg(dev).output();
    }

    fn umount(p: &Path) {
        let _ = Command::new("umount").arg("-l").arg(p).output();
    }

    // Attach one GPT partition (a sub-region of the whole disk image) to a read-only loop
    // device by its byte offset and length. This is how a partition is read without udev
    // creating the per-partition nodes a `losetup -P` partition scan would need (this
    // container has no udev, the same gap a minimal initramfs has), and it doubles as proof
    // that the right filesystem really landed at the offset the GPT points to.
    fn losetup_off(file: &Path, offset: u64, size: u64) -> Option<String> {
        let out = Command::new("losetup")
            .args([
                "-r",
                "-o",
                &offset.to_string(),
                "--sizelimit",
                &size.to_string(),
                "--find",
                "--show",
            ])
            .arg(file)
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let dev = String::from_utf8_lossy(&out.stdout).trim().to_string();
        (!dev.is_empty()).then_some(dev)
    }

    // `-c /dev/null` probes the device fresh instead of trusting blkid's on-disk cache,
    // which keys on the device name: losetup reuses the same loop node across partitions, so
    // a cached probe would report the previous partition's filesystem.
    fn blkid(dev: &str) -> String {
        Command::new("blkid")
            .args(["-c", "/dev/null"])
            .arg(dev)
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default()
    }

    // Build a base, skipping if mksquashfs is not installed (CI) rather than failing.
    fn build_or_skip(out: &Path) -> Option<PathBuf> {
        match build_base(&KeySpec::new(out)) {
            Ok(p) => Some(p),
            Err(Error::Missing(_)) => {
                eprintln!("skipping: mksquashfs not installed");
                None
            }
            Err(e) => panic!("build base: {e}"),
        }
    }

    #[test]
    fn base_image_is_reproducible() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let Some(pa) = build_or_skip(a.path()) else {
            return;
        };
        let pb = build_or_skip(b.path()).unwrap();
        let bytes_a = std::fs::read(&pa).unwrap();
        let bytes_b = std::fs::read(&pb).unwrap();
        assert!(!bytes_a.is_empty());
        assert_eq!(
            bytes_a, bytes_b,
            "the immutable base must build byte-for-byte reproducibly"
        );
    }

    #[test]
    fn base_squashfs_mounts_read_only_as_the_overlay_lower() {
        let dir = tempfile::tempdir().unwrap();
        let Some(base) = build_or_skip(dir.path()) else {
            return;
        };

        // A read-only loop device over the squashfs file, the immutable base as the init
        // would see the Key's base partition.
        let Some(loopdev) = losetup(&base, true) else {
            eprintln!("skipping: losetup not permitted here");
            return;
        };

        // Assemble on a private tmpfs so nothing escapes and the lower is isolated.
        let scratch = dir.path().join("run");
        std::fs::create_dir_all(&scratch).unwrap();
        if let Err(e) = execute(&Plan {
            steps: vec![Step::Mount {
                source: Source::tmpfs(),
                target: scratch.clone(),
            }],
        }) {
            losetup_d(&loopdev);
            if is_unprivileged_error(&e) {
                eprintln!("skipping: mounting not permitted here ({e})");
                return;
            }
            panic!("mount tmpfs: {e}");
        }

        let l = Layout::new(&scratch);
        let steps = vec![
            Step::Mkdir(l.lower.clone()),
            Step::Mount {
                source: Source::new(loopdev.as_str(), "squashfs", MountFlags::default())
                    .read_only(),
                target: l.lower.clone(),
            },
            Step::Mkdir(l.over.clone()),
            Step::Mount {
                source: Source::tmpfs(),
                target: l.over.clone(),
            },
            Step::Mkdir(l.upper.clone()),
            Step::Mkdir(l.work.clone()),
            Step::Mkdir(l.root.clone()),
            Step::Overlay {
                lower: l.lower.clone(),
                upper: l.upper.clone(),
                work: l.work.clone(),
                target: l.root.clone(),
            },
        ];
        if let Err(e) = execute(&Plan { steps }) {
            umount(&scratch);
            losetup_d(&loopdev);
            if is_unprivileged_error(&e) {
                eprintln!("skipping: assembling not permitted here ({e})");
                return;
            }
            panic!("assemble: {e}");
        }

        // The immutable base shows through the overlay root.
        let osr = std::fs::read_to_string(l.root.join("etc/os-release")).unwrap();
        assert!(osr.contains("Horizon OS"));
        // A write to the root lands in the writable tmpfs upper.
        std::fs::write(l.root.join("state"), b"session").unwrap();
        assert!(l.upper.join("state").exists());
        // The squashfs lower is genuinely read-only: it cannot be written.
        assert!(
            std::fs::write(l.lower.join("nope"), b"x").is_err(),
            "the immutable base must be read-only"
        );

        umount(&l.root);
        umount(&l.over);
        umount(&l.lower);
        umount(&scratch);
        losetup_d(&loopdev);
    }

    // A base populated with a real userland actually runs it: build a base holding a
    // dynamic host binary and its ldd closure, mount the squashfs, and exec the binary
    // inside a chroot of the base. If any library or the loader were missing or
    // misplaced, the dynamic loader would fail, so this proves the closure is complete
    // and correctly placed on the real image, the part parse_ldd's unit tests cannot.
    #[test]
    fn a_populated_base_runs_its_userland_under_chroot() {
        let dir = tempfile::tempdir().unwrap();
        // A small, ubiquitous dynamic binary whose closure is just libc and the loader.
        let probe = Path::new("/bin/cat");
        if !probe.exists() {
            eprintln!("skipping: no /bin/cat to populate");
            return;
        }
        let mut spec = KeySpec::new(dir.path());
        spec.userland = vec![probe.to_path_buf()];
        let base = match build_base(&spec) {
            Ok(p) => p,
            Err(Error::Missing(t)) => {
                eprintln!("skipping: {t} not installed");
                return;
            }
            Err(e) => panic!("build populated base: {e}"),
        };

        let Some(loopdev) = losetup(&base, true) else {
            eprintln!("skipping: losetup not permitted here");
            return;
        };
        let mnt = dir.path().join("mnt");
        std::fs::create_dir_all(&mnt).unwrap();
        if let Err(e) = execute(&Plan {
            steps: vec![Step::Mount {
                source: Source::new(loopdev.as_str(), "squashfs", MountFlags::default())
                    .read_only(),
                target: mnt.clone(),
            }],
        }) {
            losetup_d(&loopdev);
            if is_unprivileged_error(&e) {
                eprintln!("skipping: mounting not permitted here ({e})");
                return;
            }
            panic!("mount base: {e}");
        }

        // The populated cat reads the skeleton's os-release from inside the chrooted
        // base: the binary, its libc, the loader, and the cache all have to resolve.
        let out = Command::new("chroot")
            .arg(&mnt)
            .args(["/usr/bin/cat", "/etc/os-release"])
            .output();
        umount(&mnt);
        losetup_d(&loopdev);
        let out = out.expect("spawn chroot");
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        if !out.status.success() {
            // chroot needs CAP_SYS_CHROOT; skip where it is not permitted (CI).
            if stderr.contains("Operation not permitted") || stderr.contains("superuser") {
                eprintln!("skipping: chroot not permitted here ({stderr})");
                return;
            }
            panic!("chroot run failed (code {:?}): {stderr}", out.status.code());
        }
        assert!(
            stdout.contains("Horizon OS"),
            "the populated cat must read the base os-release, got: {stdout:?}"
        );
    }

    // The keystone: a complete Key (a real squashfs base, a real ext4 data partition,
    // and an initialized identity store) assembles through the init's plan and horizon
    // boot opens the identity on it, all on the real filesystems keybuild produced. This
    // ties keybuild, init, and boot together end to end, short of the switch_root and
    // the on-screen session that need an actual boot.
    #[test]
    fn a_built_key_assembles_and_boot_opens_its_identity() {
        use boot::{boot as boot_device, derive, Method};
        use identity::{enroll, Keyslots, SoftwareAuthenticator};
        use lifestream::Lifestream;

        const PASS: &str = "correct horse battery staple";
        const SALT: &[u8] = b"horizon-keybuild-keystone-salt!!";
        const SEED: [u8; 32] = [7u8; 32];

        let dir = tempfile::tempdir().unwrap();
        let spec = KeySpec::new(dir.path());

        // Build both filesystems of the Key, skipping if a build tool is absent.
        let Some(base) = build_or_skip(dir.path()) else {
            return;
        };
        let data = match build_data(&spec) {
            Ok(p) => p,
            Err(Error::Missing(_)) => {
                eprintln!("skipping: mkfs.ext4 not installed");
                return;
            }
            Err(e) => panic!("build data: {e}"),
        };

        // The base read-only and the data writable, as the init sees the Key's two
        // partitions.
        let Some(base_loop) = losetup(&base, true) else {
            eprintln!("skipping: losetup not permitted here");
            return;
        };
        let Some(data_loop) = losetup(&data, false) else {
            losetup_d(&base_loop);
            eprintln!("skipping: losetup not permitted here");
            return;
        };

        let scratch = dir.path().join("run");
        std::fs::create_dir_all(&scratch).unwrap();
        let l = Layout::new(&scratch);
        let store = l.over.join("store");
        let booted_store = l.root.join("run/horizon/store");

        let cleanup = || {
            umount(&booted_store);
            umount(&l.root);
            umount(&l.over);
            umount(&l.lower);
            umount(&scratch);
            losetup_d(&data_loop);
            losetup_d(&base_loop);
        };

        // Assemble the writable layer over the immutable base, init's Home-mode plan: a
        // private tmpfs scratch, the squashfs base as the read-only lower, the ext4 data
        // as the writable backing for the overlay upper and work.
        let setup = Plan {
            steps: vec![
                Step::Mount {
                    source: Source::tmpfs(),
                    target: scratch.clone(),
                },
                Step::Mkdir(l.lower.clone()),
                Step::Mount {
                    source: Source::new(base_loop.as_str(), "squashfs", MountFlags::default())
                        .read_only(),
                    target: l.lower.clone(),
                },
                Step::Mkdir(l.over.clone()),
                Step::Mount {
                    source: Source::new(data_loop.as_str(), "ext4", MountFlags::default()),
                    target: l.over.clone(),
                },
            ],
        };
        if let Err(e) = execute(&setup) {
            cleanup();
            if is_unprivileged_error(&e) {
                eprintln!("skipping: mounting not permitted here ({e})");
                return;
            }
            panic!("mount Key: {e}");
        }

        // Initialize the identity store on the data partition, the way the boot crate's
        // own tests build one: a master derived from a passphrase and salt, a HEAD
        // generation to prove, and an enrolled software token (the touch-to-boot path).
        std::fs::create_dir_all(&store).unwrap();
        let master = derive(PASS, SALT);
        let ls = Lifestream::init(&store, &master).unwrap();
        std::fs::write(store.join("keysalt"), SALT).unwrap();
        let seed = dir.path().join("seed");
        std::fs::create_dir_all(&seed).unwrap();
        std::fs::write(seed.join("hello"), b"horizon").unwrap();
        let tree = ls.snapshot_dir(&seed).unwrap();
        ls.commit(tree, vec![], "first").unwrap();
        let mut auth = SoftwareAuthenticator::new(SEED);
        let mut slots = Keyslots::new();
        slots.add(enroll(&mut auth, &master).unwrap());
        std::fs::write(store.join("keyslots"), slots.encode()).unwrap();
        drop(ls);

        // Overlay the root and carry the store into it, exactly as init's Home-mode plan.
        let assemble = Plan {
            steps: vec![
                Step::Mkdir(l.upper.clone()),
                Step::Mkdir(l.work.clone()),
                Step::Mkdir(l.root.clone()),
                Step::Overlay {
                    lower: l.lower.clone(),
                    upper: l.upper.clone(),
                    work: l.work.clone(),
                    target: l.root.clone(),
                },
                Step::Mkdir(booted_store.clone()),
                Step::Bind {
                    from: store.clone(),
                    to: booted_store.clone(),
                },
            ],
        };
        if let Err(e) = execute(&assemble) {
            cleanup();
            panic!("assemble Key: {e}");
        }

        // The whole Key boots: boot finds the carried store, unlocks the master with the
        // enrolled token and no passphrase, and proves HEAD, on the real squashfs + ext4
        // filesystems keybuild produced.
        let mut token = SoftwareAuthenticator::new(SEED);
        let booted = boot_device(&booted_store, Some(&mut token), || {
            panic!("the passphrase must not be requested when the token unlocks")
        });
        let booted = match booted {
            Ok(b) => b,
            Err(e) => {
                cleanup();
                panic!("boot: {e}");
            }
        };
        assert_eq!(booted.method, Method::Keyslot);
        assert_eq!(booted.master, master);
        assert!(booted.head.is_some());
        // The immutable base is also visible through the assembled root.
        assert!(std::fs::read_to_string(l.root.join("etc/os-release"))
            .unwrap()
            .contains("Horizon OS"));

        cleanup();
    }

    // The encrypted keystone: a complete Home Surface boots into its identity on the real
    // formats, with the writable layer encrypted. Build a squashfs base, a plain ext4 data
    // partition for the identity store, and a LUKS2 Home layer keyed by the master; init the
    // store on the data partition; then assemble exactly as a Home boot does, mount the base
    // read-only as the overlay lower, mount the data partition, recover the master from the
    // store with an enrolled token (boot::unlock), open the Home layer with that master
    // (init::luks_open), and overlay the decrypted layer over the base. This proves the
    // master the store yields unlocks the encrypted writable layer and a write lands in that
    // encrypted upper, not the immutable base, all on the real squashfs + ext4 + LUKS2
    // formats keybuild produced, short of the switch_root that needs an actual boot. Skips
    // where a build tool or device-mapper is unavailable, and tears every mount, loop device,
    // and mapping down on each path.
    #[test]
    fn an_encrypted_home_assembles_and_boot_opens_its_identity() {
        use boot::{boot as boot_device, derive, unlock, Method};
        use identity::{enroll, Keyslots, SoftwareAuthenticator};
        use init::{
            execute, is_unprivileged_error, luks_close, luks_open, Layout, MountFlags, Plan,
            Source, Step, HOME_MAPPER,
        };
        use lifestream::Lifestream;

        const PASS: &str = "correct horse battery staple";
        const SALT: &[u8] = b"horizon-encrypted-keystone-salt!";
        const SEED: [u8; 32] = [11u8; 32];

        let dir = tempfile::tempdir().unwrap();
        let mut spec = KeySpec::new(dir.path());
        spec.home_size_mb = 48;
        let master = derive(PASS, SALT);

        // The three filesystems of an encrypted Key, skipping if a build tool is absent.
        let Some(base) = build_or_skip(dir.path()) else {
            return;
        };
        let data = match build_data(&spec) {
            Ok(p) => p,
            Err(Error::Missing(_)) => {
                eprintln!("skipping: mkfs.ext4 not installed");
                return;
            }
            Err(e) => panic!("build data: {e}"),
        };
        let home = match build_home(&spec, &master) {
            Ok(p) => p,
            Err(Error::Missing(t)) => {
                eprintln!("skipping: {t} not installed");
                return;
            }
            Err(e) if is_dm_unavailable(&e) => {
                eprintln!("skipping: device-mapper not permitted here ({e})");
                return;
            }
            Err(e) => panic!("build home: {e}"),
        };

        // The base read-only and the store partition writable, as a Home boot sees the Key;
        // the Home layer is opened from its file directly (cryptsetup makes its own loop).
        let Some(base_loop) = losetup(&base, true) else {
            eprintln!("skipping: losetup not permitted here");
            return;
        };
        let Some(data_loop) = losetup(&data, false) else {
            losetup_d(&base_loop);
            eprintln!("skipping: losetup not permitted here");
            return;
        };

        let scratch = dir.path().join("run");
        std::fs::create_dir_all(&scratch).unwrap();
        let l = Layout::new(&scratch);
        let data_mnt = scratch.join("data");
        let store = data_mnt.join("store");
        let booted_store = l.root.join("run/horizon/store");

        let cleanup = || {
            umount(&booted_store);
            umount(&l.root);
            umount(&l.over);
            let _ = luks_close(HOME_MAPPER);
            umount(&data_mnt);
            umount(&l.lower);
            umount(&scratch);
            losetup_d(&data_loop);
            losetup_d(&base_loop);
        };

        // A private tmpfs scratch, the base as the read-only lower, the data partition
        // mounted so the identity store can be read before the encrypted layer is opened.
        let setup = Plan {
            steps: vec![
                Step::Mount {
                    source: Source::tmpfs(),
                    target: scratch.clone(),
                },
                Step::Mkdir(l.lower.clone()),
                Step::Mount {
                    source: Source::new(base_loop.as_str(), "squashfs", MountFlags::default())
                        .read_only(),
                    target: l.lower.clone(),
                },
                Step::Mkdir(data_mnt.clone()),
                Step::Mount {
                    source: Source::new(data_loop.as_str(), "ext4", MountFlags::default()),
                    target: data_mnt.clone(),
                },
            ],
        };
        if let Err(e) = execute(&setup) {
            cleanup();
            if is_unprivileged_error(&e) {
                eprintln!("skipping: mounting not permitted here ({e})");
                return;
            }
            panic!("mount Key: {e}");
        }

        // Initialize the identity store on the data partition: the master derived from the
        // passphrase and salt (the same master the Home layer is keyed by), a HEAD to prove,
        // and an enrolled token (the touch-to-boot path).
        std::fs::create_dir_all(&store).unwrap();
        let ls = Lifestream::init(&store, &master).unwrap();
        std::fs::write(store.join("keysalt"), SALT).unwrap();
        let seed = dir.path().join("seed");
        std::fs::create_dir_all(&seed).unwrap();
        std::fs::write(seed.join("hello"), b"horizon").unwrap();
        let tree = ls.snapshot_dir(&seed).unwrap();
        ls.commit(tree, vec![], "first").unwrap();
        let mut auth = SoftwareAuthenticator::new(SEED);
        let mut slots = Keyslots::new();
        slots.add(enroll(&mut auth, &master).unwrap());
        std::fs::write(store.join("keyslots"), slots.encode()).unwrap();
        drop(ls);

        // Recover the master from the store with the token, exactly as the init does in the
        // initramfs, and open the encrypted Home layer with it.
        let mut token = SoftwareAuthenticator::new(SEED);
        let (recovered, method) = unlock(&store, Some(&mut token), || {
            panic!("the token must unlock the master without a passphrase")
        })
        .unwrap();
        assert_eq!(method, Method::Keyslot);
        assert_eq!(recovered, master);
        let mapper = match luks_open(&home, HOME_MAPPER, &recovered) {
            Ok(d) => d,
            Err(e) => {
                cleanup();
                panic!("the recovered master must open the Home layer: {e}");
            }
        };

        // Overlay the decrypted Home layer over the immutable base and carry the store in.
        let assemble = Plan {
            steps: vec![
                Step::Mkdir(l.over.clone()),
                Step::Mount {
                    source: Source::new(mapper.clone(), "ext4", MountFlags::default()),
                    target: l.over.clone(),
                },
                Step::Mkdir(l.upper.clone()),
                Step::Mkdir(l.work.clone()),
                Step::Mkdir(l.root.clone()),
                Step::Overlay {
                    lower: l.lower.clone(),
                    upper: l.upper.clone(),
                    work: l.work.clone(),
                    target: l.root.clone(),
                },
                Step::Mkdir(booted_store.clone()),
                Step::Bind {
                    from: store.clone(),
                    to: booted_store.clone(),
                },
            ],
        };
        if let Err(e) = execute(&assemble) {
            cleanup();
            panic!("assemble encrypted root: {e}");
        }

        // A write to the root lands in the encrypted upper (on the LUKS layer), never in the
        // immutable base: persistent state is encrypted at rest.
        std::fs::write(l.root.join("session-state"), b"remembered").unwrap();
        assert!(
            l.upper.join("session-state").exists(),
            "the write must land in the encrypted upper"
        );
        assert!(std::fs::read_to_string(l.root.join("etc/os-release"))
            .unwrap()
            .contains("Horizon OS"));

        // boot opens the carried identity on the recovered master, the same proof the plain
        // keystone makes, now over the encrypted writable layer.
        let mut token2 = SoftwareAuthenticator::new(SEED);
        let booted = match boot_device(&booted_store, Some(&mut token2), || {
            panic!("the passphrase must not be requested when the token unlocks")
        }) {
            Ok(b) => b,
            Err(e) => {
                cleanup();
                panic!("boot opens the identity: {e}");
            }
        };
        assert_eq!(booted.master, master);
        assert_eq!(booted.method, Method::Keyslot);
        assert!(booted.head.is_some());

        cleanup();
    }

    // A base built with modules and firmware carries them on the real image: build from a
    // synthesized kernel module tree and a firmware blob (so no real /lib/modules is
    // needed), mount the squashfs read-only, and read the closure and the blob back
    // through it. This proves the dependency closure is placed right and survives the
    // squashfs round-trip on the format the Key uses, the part the pure populate tests do
    // not exercise. The modules are not executed (they load into a kernel, not a chroot),
    // so unlike the userland test this only needs the image to mount.
    #[test]
    fn a_base_carries_its_modules_and_firmware_through_the_squashfs() {
        let dir = tempfile::tempdir().unwrap();
        let ver = "6.12.0-horizon";

        // ext4 needs crc16 and mbcache; an unrelated sound module must stay off the base.
        let modsrc = dir.path().join("modsrc");
        let moddir = modsrc.join(ver);
        for (rel, body) in [
            ("kernel/fs/ext4/ext4.ko", "ext4"),
            ("kernel/lib/crc16.ko", "crc16"),
            ("kernel/fs/mbcache.ko", "mbcache"),
            ("kernel/sound/foo.ko", "foo"),
        ] {
            let p = moddir.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, body).unwrap();
        }
        std::fs::write(
            moddir.join("modules.dep"),
            "kernel/fs/ext4/ext4.ko: kernel/lib/crc16.ko kernel/fs/mbcache.ko\n\
             kernel/lib/crc16.ko:\n\
             kernel/fs/mbcache.ko:\n\
             kernel/sound/foo.ko:\n",
        )
        .unwrap();

        let fwsrc = dir.path().join("fwsrc");
        std::fs::create_dir_all(fwsrc.join("rtl_nic")).unwrap();
        std::fs::write(fwsrc.join("rtl_nic/rtl8168.fw"), b"firmware-blob").unwrap();

        let mut spec = KeySpec::new(dir.path());
        spec.kernel_version = Some(ver.to_string());
        spec.modules_root = modsrc.clone();
        spec.modules = vec!["ext4".to_string()];
        spec.firmware_root = fwsrc.clone();
        spec.firmware = vec!["rtl_nic/rtl8168.fw".to_string()];
        let base = match build_base(&spec) {
            Ok(p) => p,
            Err(Error::Missing(t)) => {
                eprintln!("skipping: {t} not installed");
                return;
            }
            Err(e) => panic!("build base with modules: {e}"),
        };

        let Some(loopdev) = losetup(&base, true) else {
            eprintln!("skipping: losetup not permitted here");
            return;
        };
        let mnt = dir.path().join("mnt");
        std::fs::create_dir_all(&mnt).unwrap();
        if let Err(e) = execute(&Plan {
            steps: vec![Step::Mount {
                source: Source::new(loopdev.as_str(), "squashfs", MountFlags::default())
                    .read_only(),
                target: mnt.clone(),
            }],
        }) {
            losetup_d(&loopdev);
            if is_unprivileged_error(&e) {
                eprintln!("skipping: mounting not permitted here ({e})");
                return;
            }
            panic!("mount base: {e}");
        }

        // Read the modules, the dependency closure, the emitted dep file, and the firmware
        // back through the read-only mount before tearing it down.
        let modroot = mnt.join("lib/modules").join(ver);
        let ext4 = std::fs::read_to_string(modroot.join("kernel/fs/ext4/ext4.ko"));
        let crc16 = modroot.join("kernel/lib/crc16.ko").exists();
        let mbcache = modroot.join("kernel/fs/mbcache.ko").exists();
        let foo = modroot.join("kernel/sound/foo.ko").exists();
        let dep = std::fs::read_to_string(modroot.join("modules.dep"));
        let fw = std::fs::read(mnt.join("lib/firmware/rtl_nic/rtl8168.fw"));
        umount(&mnt);
        losetup_d(&loopdev);

        assert_eq!(ext4.unwrap(), "ext4");
        assert!(
            crc16 && mbcache,
            "the dependency closure must be on the image"
        );
        assert!(!foo, "an unrelated module must not be on the image");
        assert!(dep.unwrap().contains("kernel/fs/ext4/ext4.ko"));
        assert_eq!(fw.unwrap(), b"firmware-blob");
    }

    // Cross-check the verity hash device byte-for-byte against `veritysetup format`, the
    // reference implementation. This is the proof the owned SHA-256 Merkle tree is exactly
    // the on-disk format the kernel's dm-verity target reads: the same superblock, level
    // layout, salted digests, and root. It needs only the veritysetup binary (no loop
    // devices, no root), so it runs in CI as well as the container, and skips where
    // veritysetup is absent.

    // Run `veritysetup format` over `data` with the given params and return the bytes it
    // wrote to the hash device and the root hash it printed, or None if veritysetup is not
    // installed (so the caller skips rather than fails).
    fn veritysetup_format(dir: &Path, data: &[u8], p: &VerityParams) -> Option<(Vec<u8>, String)> {
        let data_path = dir.join("data.img");
        let hash_path = dir.join("hash.img");
        std::fs::write(&data_path, data).unwrap();
        std::fs::write(&hash_path, b"").unwrap(); // veritysetup writes into an existing file

        let data_blocks = (data.len() / p.data_block_size as usize).max(1);
        let out = match Command::new("veritysetup")
            .arg("format")
            .arg("--hash=sha256")
            .arg(format!("--data-block-size={}", p.data_block_size))
            .arg(format!("--hash-block-size={}", p.hash_block_size))
            .arg(format!("--data-blocks={data_blocks}"))
            .arg(format!("--salt={}", verity::to_hex(&p.salt)))
            .arg(format!("--uuid={}", verity::format_uuid(&p.uuid)))
            .arg(&data_path)
            .arg(&hash_path)
            .output()
        {
            Ok(o) => o,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("skipping: veritysetup not installed");
                return None;
            }
            Err(e) => panic!("spawn veritysetup: {e}"),
        };
        assert!(
            out.status.success(),
            "veritysetup format failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        // The "Root hash:" line carries the value as its last whitespace token.
        let stdout = String::from_utf8_lossy(&out.stdout);
        let root = stdout
            .lines()
            .find(|l| l.contains("Root hash"))
            .and_then(|l| l.split_whitespace().last())
            .expect("veritysetup printed a root hash")
            .to_string();
        Some((std::fs::read(&hash_path).unwrap(), root))
    }

    // Compare two hash devices, reporting the first differing offset and a window around it
    // so a format mismatch is quick to locate rather than an opaque "vectors differ".
    fn assert_bytes_eq(ours: &[u8], theirs: &[u8]) {
        if ours == theirs {
            return;
        }
        let at = ours
            .iter()
            .zip(theirs.iter())
            .position(|(a, b)| a != b)
            .unwrap_or(ours.len().min(theirs.len()));
        let lo = at.saturating_sub(8);
        let hi = (at + 24).min(ours.len()).min(theirs.len()).max(lo);
        panic!(
            "hash device differs at offset {at} (ours {} bytes, veritysetup {} bytes)\n ours:   {:02x?}\n vsetup: {:02x?}",
            ours.len(),
            theirs.len(),
            &ours[lo..hi],
            &theirs[lo..hi],
        );
    }

    // Deterministic, non-zero, block-varying data so adjacent block hashes differ.
    fn aligned(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8 + 1).collect()
    }

    #[test]
    fn verity_matches_veritysetup_byte_for_byte() {
        // A 32-byte salt, and cases of (data_blocks, data_block_size, hash_block_size): a
        // single level, a two-level tree, and a three-level tree forced cheaply with small
        // hash blocks (hashes per block = 1024/32 = 32, so 1025 data blocks needs three
        // levels) on differing data and hash block sizes.
        let salt = b"horizon cross-check salt 32 byte".to_vec();
        let cases: &[(usize, u32, u32)] = &[
            (1, 4096, 4096),
            (5, 4096, 4096),
            (200, 4096, 4096),
            (1025, 512, 1024),
        ];
        let mut ran = false;
        for &(blocks, dbs, hbs) in cases {
            let dir = tempfile::tempdir().unwrap();
            let params = VerityParams {
                data_block_size: dbs,
                hash_block_size: hbs,
                salt: salt.clone(),
                uuid: verity::DEFAULT_UUID,
            };
            let data = aligned(blocks * dbs as usize);
            let ours = verity::format(&data, &params);
            let Some((theirs_bytes, theirs_root)) = veritysetup_format(dir.path(), &data, &params)
            else {
                return; // veritysetup absent: skip the whole test
            };
            ran = true;
            assert_eq!(
                ours.root_hex(),
                theirs_root,
                "root hash mismatch for {blocks} blocks ({dbs}/{hbs})"
            );
            assert_bytes_eq(&ours.hash_device, &theirs_bytes);
        }
        assert!(ran, "at least one case must have run");
    }

    // A cryptsetup error from device-mapper being unavailable (no privilege, no dm_mod),
    // so the encrypted-layer test skips on an unprivileged runner the way the mount tests
    // do, rather than failing. luksFormat writes only a header and needs none of this; it
    // is luksOpen that needs device-mapper.
    fn is_dm_unavailable(e: &Error) -> bool {
        matches!(e, Error::Tool { stderr, .. } if {
            let s = stderr.to_lowercase();
            s.contains("device-mapper")
                || s.contains("permission denied")
                || s.contains("operation not permitted")
                || s.contains("dm_mod")
        })
    }

    // The encrypted Home writable layer round-trips on the real format: build_home formats
    // a LUKS2 container keyed by a master and lays an ext4 inside, and the same master
    // opens it to a mountable, writable filesystem while a wrong master is refused. This is
    // the proof the producer keys the layer with the master (so boot's recovered master
    // unlocks it) on the real cryptsetup format, the part the pure arg tests cannot show.
    // CONFIG_DM_CRYPT=y here, so the open runs for real; it skips where device-mapper is
    // not permitted (CI) and tears the mapping and mount down on every path.
    #[test]
    fn build_home_makes_a_luks2_layer_the_master_unlocks() {
        const MASTER: [u8; luks::MASTER_KEY_SIZE] = [7u8; luks::MASTER_KEY_SIZE];
        const WRONG: [u8; luks::MASTER_KEY_SIZE] = [9u8; luks::MASTER_KEY_SIZE];

        let dir = tempfile::tempdir().unwrap();
        let mut spec = KeySpec::new(dir.path());
        // Small but past the ~16 MiB LUKS2 header, so the inner ext4 has room.
        spec.home_size_mb = 48;

        let home = match build_home(&spec, &MASTER) {
            Ok(p) => p,
            Err(Error::Missing(t)) => {
                eprintln!("skipping: {t} not installed");
                return;
            }
            Err(e) if is_dm_unavailable(&e) => {
                eprintln!("skipping: device-mapper not permitted here ({e})");
                return;
            }
            Err(e) => panic!("build home: {e}"),
        };

        // A real LUKS header was written.
        assert!(luks::is_luks(&home), "home.img must be a LUKS volume");

        // The master opens it; the inner ext4 is a real, writable filesystem.
        let mapper = "horizon-home-test";
        let dev = match luks::open(&home, &MASTER, mapper) {
            Ok(d) => d,
            Err(e) if is_dm_unavailable(&e) => {
                eprintln!("skipping: device-mapper not permitted here ({e})");
                return;
            }
            Err(e) => panic!("open with the master must succeed: {e}"),
        };
        let mnt = dir.path().join("mnt");
        std::fs::create_dir_all(&mnt).unwrap();
        let mounted = Command::new("mount").arg(&dev).arg(&mnt).output();
        let mounted = mounted.expect("spawn mount");
        if !mounted.status.success() {
            let _ = luks::close(mapper);
            let err = String::from_utf8_lossy(&mounted.stderr);
            if err.contains("Permission denied") || err.contains("not permitted") {
                eprintln!("skipping: mounting not permitted here ({err})");
                return;
            }
            panic!("mount decrypted home: {err}");
        }
        std::fs::write(mnt.join("proof"), b"encrypted persistence").unwrap();
        let read_back = std::fs::read(mnt.join("proof")).unwrap();
        umount(&mnt);
        luks::close(mapper).unwrap();
        assert_eq!(read_back, b"encrypted persistence");

        // A wrong master is refused: the key genuinely gates the layer.
        match luks::open(&home, &WRONG, "horizon-home-wrong") {
            Err(Error::Tool { .. }) => {}
            Err(e) if is_dm_unavailable(&e) => {}
            Ok(_) => {
                let _ = luks::close("horizon-home-wrong");
                panic!("a wrong master must not open the encrypted layer");
            }
            Err(e) => panic!("unexpected error opening with a wrong master: {e}"),
        }
    }

    #[test]
    fn build_verity_over_a_real_base_matches_veritysetup() {
        // The whole producer path on the real image: build a squashfs base, run build_verity
        // to emit base.verity with the default reproducible params, and cross-check that file
        // and its root against veritysetup over the same base.squashfs. Proves the defaults
        // (salt, uuid, block size) are exactly what veritysetup writes and that build_verity
        // places the hash device correctly.
        let dir = tempfile::tempdir().unwrap();
        let Some(base) = build_or_skip(dir.path()) else {
            return;
        };
        let artifact = build_verity(&KeySpec::new(dir.path())).unwrap();
        let our_bytes = std::fs::read(&artifact.image).unwrap();

        let data = std::fs::read(&base).unwrap();
        // mksquashfs pads to a 4K boundary, so the base is hash-block aligned; assert it,
        // since an unaligned base would make veritysetup and our reader disagree on the tail.
        assert_eq!(data.len() % verity::DEFAULT_BLOCK_SIZE as usize, 0);

        let xdir = tempfile::tempdir().unwrap();
        let Some((theirs_bytes, theirs_root)) =
            veritysetup_format(xdir.path(), &data, &VerityParams::default())
        else {
            return;
        };
        assert_eq!(artifact.root_hex(), theirs_root);
        assert_bytes_eq(&our_bytes, &theirs_bytes);
    }

    #[test]
    fn build_disk_places_each_filesystem_at_its_gpt_offset() {
        // Assemble a real Key (FAT ESP, squashfs base, ext4 data store, LUKS2 Home layer) into
        // a GPT disk, then attach each partition at the offset write_disk reported and read it
        // back: the kernel must find the right filesystem there. This proves the table's
        // offsets point at the images write_disk copied in, on the real formats the Key
        // uses. The GPT table's own validity is cross-checked against sgdisk in the
        // cross-platform test; together they show a valid table whose offsets hold the right
        // filesystems. Skips where a build tool, device-mapper, or losetup is unavailable.
        let dir = tempfile::tempdir().unwrap();
        let mut spec = KeySpec::new(dir.path());
        spec.data_size_mb = 16;
        spec.home_size_mb = 32;
        spec.esp_size_mb = 16;

        if build_or_skip(dir.path()).is_none() {
            return;
        }
        // The ESP is owned pure Rust (no mkfs.fat), so it never skips for a missing tool.
        build_esp(&spec).expect("build esp");
        match build_data(&spec) {
            Ok(_) => {}
            Err(Error::Missing(t)) => {
                eprintln!("skipping: {t} not installed");
                return;
            }
            Err(e) => panic!("build data: {e}"),
        }
        const MASTER: [u8; luks::MASTER_KEY_SIZE] = [0x5a; luks::MASTER_KEY_SIZE];
        match build_home(&spec, &MASTER) {
            Ok(_) => {}
            Err(Error::Missing(t)) => {
                eprintln!("skipping: {t} not installed");
                return;
            }
            Err(e) if is_dm_unavailable(&e) => {
                eprintln!("skipping: device-mapper not permitted here ({e})");
                return;
            }
            Err(e) => panic!("build home: {e}"),
        }

        // write_disk is what build_disk calls; using it directly returns the placements. The
        // ESP is partition one with the EFI System Partition type, the rest carry the generic
        // Linux type, the same order build_disk lays them.
        let linux = gpt::Guid::parse(gpt::LINUX_FS_TYPE).unwrap();
        let esp = gpt::Guid::parse(gpt::ESP_TYPE).unwrap();
        let parts = [
            DiskPart {
                image: spec.out.join(ESP_IMAGE),
                type_guid: esp,
                name: ESP_LABEL.to_string(),
            },
            DiskPart {
                image: spec.out.join(BASE_IMAGE),
                type_guid: linux,
                name: spec.base_label.clone(),
            },
            DiskPart {
                image: spec.out.join(DATA_IMAGE),
                type_guid: linux,
                name: spec.data_label.clone(),
            },
            DiskPart {
                image: spec.out.join(HOME_IMAGE),
                type_guid: linux,
                name: HOME_LABEL.to_string(),
            },
        ];
        let disk = spec.out.join(DISK_IMAGE);
        let placed = write_disk(&disk, &parts).expect("assemble the GPT disk");
        assert_eq!(placed.len(), 4);

        // blkid each partition at its GPT offset: the ESP is a vfat filesystem, the base a
        // squashfs, the data store a labeled ext4, the Home layer a LUKS2 container.
        let mut found = Vec::new();
        for p in &placed {
            let Some(dev) = losetup_off(&disk, p.offset, p.size) else {
                eprintln!("skipping: losetup not permitted here");
                return;
            };
            found.push((p.name.clone(), blkid(&dev)));
            losetup_d(&dev);
        }

        assert!(
            found[0].1.contains("vfat"),
            "esp not at its offset: {}",
            found[0].1
        );
        assert!(
            found[1].1.contains("squashfs"),
            "base not at its offset: {}",
            found[1].1
        );
        assert!(
            found[2].1.contains("ext4") && found[2].1.contains("HORIZON-DATA"),
            "data store not at its offset: {}",
            found[2].1
        );
        assert!(
            found[3].1.contains("crypto_LUKS"),
            "Home layer not at its offset: {}",
            found[3].1
        );
    }

    // Mount one of our FAT images read-only as vfat, returning false (with the reason printed)
    // where mounting is not permitted, so the test skips rather than fails on a restricted host.
    fn mount_vfat(dev: &str, mnt: &Path) -> bool {
        let out = Command::new("mount")
            .args(["-t", "vfat", "-o", "ro"])
            .arg(dev)
            .arg(mnt)
            .output()
            .expect("spawn mount");
        if out.status.success() {
            return true;
        }
        let err = String::from_utf8_lossy(&out.stderr);
        if err.contains("Permission denied") || err.contains("not permitted") {
            eprintln!("skipping: mounting vfat not permitted here ({err})");
            false
        } else {
            panic!("mount esp: {err}");
        }
    }

    #[test]
    fn esp_mounts_as_vfat_and_files_read_back() {
        // The kernel's own FAT driver is the cross-check on the pure-Rust writer (the analog of
        // the GPT sgdisk check and verity's veritysetup check): build an ESP with a known tree,
        // loop-mount it as vfat, and read the files back byte-for-byte. Both sizes are
        // exercised, a small one (FAT16, the fixed-root-region path) and a large one (FAT32,
        // the root-cluster-chain path), so both code paths are proven against the kernel. Skips
        // where losetup or mounting is not permitted.
        for size_mb in [16u64, 96u64] {
            let dir = tempfile::tempdir().unwrap();
            let mut spec = KeySpec::new(dir.path());
            spec.esp_size_mb = size_mb;

            // A tree that spans subdirectories and multi-cluster files, the shape a real ESP
            // (bootloader under /EFI/BOOT, a kernel and initramfs at the root) has.
            let boot = b"this stands in for the bootloader".to_vec();
            let vmlinuz = vec![0xABu8; 4096 * 5 + 123];
            let initrd = vec![0xCDu8; 300_000];
            let mut tree = fat::Dir::new();
            tree.insert_file("EFI/BOOT/BOOTX64.EFI", boot.clone())
                .unwrap();
            tree.insert_file("VMLINUZ", vmlinuz.clone()).unwrap();
            tree.insert_file("INITRD.IMG", initrd.clone()).unwrap();
            let img = build_esp_with(&spec, &tree).expect("build esp");

            let size = std::fs::metadata(&img).unwrap().len();
            let Some(dev) = losetup_off(&img, 0, size) else {
                eprintln!("skipping: losetup not permitted here");
                return;
            };
            let mnt = dir.path().join("mnt");
            std::fs::create_dir_all(&mnt).unwrap();
            if !mount_vfat(&dev, &mnt) {
                losetup_d(&dev);
                return;
            }

            // FAT lookup is case-insensitive, so the uppercase 8.3 paths open regardless of how
            // the vfat driver displays short names.
            let read_boot = std::fs::read(mnt.join("EFI/BOOT/BOOTX64.EFI"));
            let read_vmlinuz = std::fs::read(mnt.join("VMLINUZ"));
            let read_initrd = std::fs::read(mnt.join("INITRD.IMG"));
            umount(&mnt);
            losetup_d(&dev);

            assert_eq!(read_boot.unwrap(), boot, "{size_mb} MiB ESP: bootloader");
            assert_eq!(read_vmlinuz.unwrap(), vmlinuz, "{size_mb} MiB ESP: kernel");
            assert_eq!(read_initrd.unwrap(), initrd, "{size_mb} MiB ESP: initramfs");
        }
    }

    // The initramfs cross-check: build a real initramfs, gunzip it, and parse the cpio back.
    // There is no cpio tool to compare against (the reason this crate owns the format), so the
    // proof is the reader half ([`cpio::read`]) walking the same bytes the kernel would, after
    // a real `gzip` round-trip. It asserts the assembly is complete and correctly placed: the
    // /init program at the root with its loader cache, the cryptsetup stand-in under /usr/sbin
    // with the shared closure, the boot-path module with its modules.dep closure, and the
    // /dev/console device node the build adds for the init's console output. The kernel
    // actually unpacking and exec'ing /init is eye-verified at the QEMU boot. Skips where a
    // build tool (ldd/ldconfig/gzip) is absent (a bare host, darwin runs the pure tests only).
    #[test]
    fn built_initramfs_gunzips_and_unpacks_with_init_tools_and_modules() {
        let dir = tempfile::tempdir().unwrap();

        // Two ubiquitous dynamic binaries stand in for horizon-init and cryptsetup: their
        // closures (libc and the loader) exercise the same machinery the real binaries use.
        let init_probe = Path::new("/bin/cat");
        let tool_probe = Path::new("/bin/echo");
        if !init_probe.exists() || !tool_probe.exists() {
            eprintln!("skipping: no /bin/cat or /bin/echo to assemble");
            return;
        }

        // A tiny synthesized module tree: squashfs needs a stand-in dep, the kind of boot-path
        // driver an initramfs carries; an unrelated module must stay out (the closure is exact).
        let ver = "9.9.9-horizon";
        let modsrc = dir.path().join("modsrc");
        let moddir = modsrc.join(ver);
        for (rel, body) in [
            ("kernel/fs/squashfs/squashfs.ko", "squashfs"),
            ("kernel/lib/decompress.ko", "decompress"),
            ("kernel/drivers/net/unrelated.ko", "unrelated"),
        ] {
            let p = moddir.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, body).unwrap();
        }
        std::fs::write(
            moddir.join("modules.dep"),
            "kernel/fs/squashfs/squashfs.ko: kernel/lib/decompress.ko\n\
             kernel/lib/decompress.ko:\n\
             kernel/drivers/net/unrelated.ko:\n",
        )
        .unwrap();

        let mut spec = KeySpec::new(dir.path());
        spec.init_bin = Some(init_probe.to_path_buf());
        spec.initramfs_bins = vec![tool_probe.to_path_buf()];
        spec.kernel_version = Some(ver.to_string());
        spec.modules_root = modsrc.clone();
        spec.initramfs_modules = vec!["squashfs".to_string()];

        let img = match build_initramfs(&spec) {
            Ok(p) => p,
            Err(Error::Missing(t)) => {
                eprintln!("skipping: {t} not installed");
                return;
            }
            Err(e) => panic!("build initramfs: {e}"),
        };

        // gunzip the image (the kernel reads it compressed; the test decompresses to inspect)
        // and parse the newc cpio back into entries.
        let gz = std::fs::read(&img).unwrap();
        assert_eq!(&gz[..2], &[0x1f, 0x8b], "the image must be gzip-compressed");
        let unzip = Command::new("gzip")
            .args(["-dc"])
            .arg(&img)
            .output()
            .unwrap();
        assert!(
            unzip.status.success(),
            "gunzip failed: {}",
            String::from_utf8_lossy(&unzip.stderr)
        );
        let entries = cpio::read(&unzip.stdout).expect("parse the cpio archive");

        let find = |path: &str| {
            entries.iter().find(|e| matches!(e, cpio::Entry::Dir { path: p, .. } | cpio::Entry::File { path: p, .. } | cpio::Entry::Symlink { path: p, .. } | cpio::Entry::Device { path: p, .. } if p == path))
        };

        // /init is the program the kernel execs as PID 1, executable, with the cat bytes intact.
        match find("init").expect("/init present") {
            cpio::Entry::File { mode, data, .. } => {
                assert_eq!(mode & 0o111, 0o111, "/init must be executable");
                assert_eq!(
                    *data,
                    std::fs::read(init_probe).unwrap(),
                    "/init is the init bytes"
                );
            }
            other => panic!("init should be a file, got {other:?}"),
        }
        // The cryptsetup stand-in landed under /usr/sbin with its closure.
        assert!(
            matches!(find("usr/sbin/echo"), Some(cpio::Entry::File { .. })),
            "the extra tool must be under /usr/sbin"
        );
        // The loader cache the closure copy built, so libc resolves by soname at boot.
        assert!(
            matches!(find("etc/ld.so.cache"), Some(cpio::Entry::File { .. })),
            "the ld.so.cache must be present"
        );
        // At least one shared object from the closure (the loader/libc) is on the image.
        assert!(
            entries.iter().any(|e| matches!(e, cpio::Entry::File { path, .. } if path.starts_with("lib/") && !path.starts_with("lib/modules/"))),
            "the shared-library closure must be on the initramfs"
        );
        // The boot-path module and its dependency are there; the unrelated one is not.
        let modroot = format!("lib/modules/{ver}");
        assert!(
            matches!(
                find(&format!("{modroot}/kernel/fs/squashfs/squashfs.ko")),
                Some(cpio::Entry::File { .. })
            ),
            "the boot-path module must be on the initramfs"
        );
        assert!(
            matches!(
                find(&format!("{modroot}/kernel/lib/decompress.ko")),
                Some(cpio::Entry::File { .. })
            ),
            "the module dependency closure must be on the initramfs"
        );
        assert!(
            find(&format!("{modroot}/kernel/drivers/net/unrelated.ko")).is_none(),
            "an unrelated module must not be on the initramfs"
        );
        assert!(
            matches!(
                find(&format!("{modroot}/modules.dep")),
                Some(cpio::Entry::File { .. })
            ),
            "the emitted modules.dep must be on the initramfs"
        );
        // The console device node, so horizon-init's output is visible before devtmpfs.
        match find("dev/console").expect("/dev/console present") {
            cpio::Entry::Device {
                kind, major, minor, ..
            } => {
                assert_eq!((*kind, *major, *minor), (cpio::NodeKind::Char, 5, 1));
            }
            other => panic!("/dev/console should be a char device, got {other:?}"),
        }
    }
}
