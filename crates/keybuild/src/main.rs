// horizon-keybuild: build the filesystems of a Horizon Key.
//
// A host-side tool, not part of a running Horizon. It builds the immutable base image
// into an output directory and prints the kernel command line a bootloader passes so
// the init finds the Key. Each --bin installs a host binary into the base's /usr/bin
// with its shared-library closure, so `--bin target/release/horizon --bin
// target/release/horizon-init` makes a base that boots. --module installs a kernel
// module and its modules.dep closure under /lib/modules/<kver>, and --firmware copies a
// firmware blob under /lib/firmware, so the base drives hardware. --verity builds the
// dm-verity hash tree over the base into base.verity and prints the root hash that anchors
// it. --home builds the encrypted Home writable layer (home.img, a LUKS2 container) keyed
// by the 32-byte master in --home-keyfile, so a Home Surface persists encrypted at rest.
// --esp builds the FAT EFI System Partition (esp.img) with the /EFI/BOOT skeleton, the
// partition firmware reads the bootloader from. --disk assembles the ESP, base, data, and
// Home partitions into one bootable GPT disk (key.img), building the ESP, data, and Home
// partitions too, so it needs --home-keyfile. --initramfs builds the initramfs (initramfs.img,
// a gzip newc cpio) with /init from --init-bin (horizon-init), each --initramfs-bin
// (cryptsetup) under /usr/sbin, and each --initramfs-module under /lib/modules/<kver>, all
// with their shared-library / modules.dep closures.
// The build logic is in the keybuild library, tested there; this is the thin CLI over it.

use std::path::PathBuf;
use std::process::ExitCode;

struct Args {
    out: PathBuf,
    bins: Vec<PathBuf>,
    kver: Option<String>,
    modules: Vec<String>,
    modules_root: Option<PathBuf>,
    firmware: Vec<String>,
    firmware_root: Option<PathBuf>,
    verity: bool,
    home: bool,
    home_keyfile: Option<PathBuf>,
    esp: bool,
    disk: bool,
    initramfs: bool,
    init_bin: Option<PathBuf>,
    initramfs_bins: Vec<PathBuf>,
    initramfs_modules: Vec<String>,
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let Some(parsed) = parse_args(&args) else {
        eprintln!(
            "usage: horizon-keybuild --out <dir> [--bin <path>]... \
             [--kver <version> --module <name>...] [--modules-root <dir>] \
             [--firmware <path>]... [--firmware-root <dir>] [--verity] \
             [--home --home-keyfile <32-byte-master>] [--esp] [--disk] \
             [--initramfs --init-bin <path> [--initramfs-bin <path>]... \
             [--initramfs-module <name>]...]"
        );
        return ExitCode::FAILURE;
    };

    let mut spec = keybuild::KeySpec::new(parsed.out);
    spec.userland = parsed.bins;
    spec.kernel_version = parsed.kver;
    spec.modules = parsed.modules;
    if let Some(root) = parsed.modules_root {
        spec.modules_root = root;
    }
    spec.firmware = parsed.firmware;
    if let Some(root) = parsed.firmware_root {
        spec.firmware_root = root;
    }
    spec.init_bin = parsed.init_bin;
    spec.initramfs_bins = parsed.initramfs_bins;
    spec.initramfs_modules = parsed.initramfs_modules;
    let verity = parsed.verity;
    let disk = parsed.disk;
    let initramfs = parsed.initramfs;
    // The assembled disk carries the encrypted Home and ESP partitions, so --disk needs the
    // master too; build the Home layer and the ESP whenever either flag asks for it.
    let home = parsed.home || disk;
    let esp = parsed.esp || disk;
    let home_keyfile = parsed.home_keyfile;

    match keybuild::build_base(&spec) {
        Ok(path) => {
            println!("built {}", path.display());
            if !spec.userland.is_empty() {
                println!(
                    "userland: {} binary(ies) plus shared-library closure",
                    spec.userland.len()
                );
            }
            if !spec.modules.is_empty() {
                println!(
                    "modules: {} requested plus dependency closure",
                    spec.modules.len()
                );
            }
            if !spec.firmware.is_empty() {
                println!("firmware: {} blob(s)", spec.firmware.len());
            }
            // dm-verity over the just-built base: a tamper-evident immutable layer anchored
            // by the printed root hash, which a bootloader carries (signed or measured).
            if verity {
                match keybuild::build_verity(&spec) {
                    Ok(v) => {
                        println!(
                            "verity: built {} ({} data blocks, {} tree level(s))",
                            v.image.display(),
                            v.data_blocks,
                            v.levels
                        );
                        println!("verity root: {}", v.root_hex());
                    }
                    Err(e) => {
                        eprintln!("horizon-keybuild: verity: {e}");
                        return ExitCode::FAILURE;
                    }
                }
            }
            // The encrypted Home writable layer, keyed by the 32-byte master in the
            // keyfile so boot's recovered master unlocks it.
            if home {
                let master = match read_master(home_keyfile.as_deref()) {
                    Ok(m) => m,
                    Err(e) => {
                        eprintln!("horizon-keybuild: home: {e}");
                        return ExitCode::FAILURE;
                    }
                };
                match keybuild::build_home(&spec, &master) {
                    Ok(p) => println!(
                        "home: built {} ({} MiB LUKS2, ext4 inside, label {})",
                        p.display(),
                        spec.home_size_mb,
                        keybuild::HOME_LABEL
                    ),
                    Err(e) => {
                        eprintln!("horizon-keybuild: home: {e}");
                        return ExitCode::FAILURE;
                    }
                }
            }
            // The FAT EFI System Partition with its /EFI/BOOT skeleton, the partition firmware
            // reads the bootloader from.
            if esp {
                match keybuild::build_esp(&spec) {
                    Ok(p) => println!(
                        "esp: built {} ({} MiB FAT, label {})",
                        p.display(),
                        spec.esp_size_mb,
                        keybuild::ESP_LABEL
                    ),
                    Err(e) => {
                        eprintln!("horizon-keybuild: esp: {e}");
                        return ExitCode::FAILURE;
                    }
                }
            }
            // The initramfs: the cpio root filesystem the kernel unpacks before any disk,
            // holding /init (horizon-init) and cryptsetup with their closures and the
            // boot-path modules. Independent of the disk for now; the bootloader step writes
            // it into the ESP.
            if initramfs {
                match keybuild::build_initramfs(&spec) {
                    Ok(p) => println!(
                        "initramfs: built {} (gzip newc cpio: /init plus {} tool(s), {} module(s))",
                        p.display(),
                        spec.initramfs_bins.len(),
                        spec.initramfs_modules.len()
                    ),
                    Err(e) => {
                        eprintln!("horizon-keybuild: initramfs: {e}");
                        return ExitCode::FAILURE;
                    }
                }
            }
            // Assemble the partitions into a bootable GPT disk. The disk carries the plain
            // data store partition too, so build it here; the base, the Home layer, and the
            // ESP are already built above.
            if disk {
                if let Err(e) = keybuild::build_data(&spec) {
                    eprintln!("horizon-keybuild: data: {e}");
                    return ExitCode::FAILURE;
                }
                match keybuild::build_disk(&spec) {
                    Ok(p) => println!(
                        "disk: built {} (GPT: {} / {} / {} / {})",
                        p.display(),
                        keybuild::ESP_LABEL,
                        spec.base_label,
                        spec.data_label,
                        keybuild::HOME_LABEL
                    ),
                    Err(e) => {
                        eprintln!("horizon-keybuild: disk: {e}");
                        return ExitCode::FAILURE;
                    }
                }
            }
            println!("boot cmdline: {}", keybuild::boot_cmdline(&spec));
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("horizon-keybuild: {e}");
            ExitCode::FAILURE
        }
    }
}

fn parse_args(args: &[String]) -> Option<Args> {
    let mut out = None;
    let mut bins = Vec::new();
    let mut kver = None;
    let mut modules = Vec::new();
    let mut modules_root = None;
    let mut firmware = Vec::new();
    let mut firmware_root = None;
    let mut verity = false;
    let mut home = false;
    let mut home_keyfile = None;
    let mut esp = false;
    let mut disk = false;
    let mut initramfs = false;
    let mut init_bin = None;
    let mut initramfs_bins = Vec::new();
    let mut initramfs_modules = Vec::new();
    let mut it = args.iter().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--out" => out = Some(PathBuf::from(it.next()?)),
            "--bin" => bins.push(PathBuf::from(it.next()?)),
            "--kver" => kver = Some(it.next()?.clone()),
            "--module" => modules.push(it.next()?.clone()),
            "--modules-root" => modules_root = Some(PathBuf::from(it.next()?)),
            "--firmware" => firmware.push(it.next()?.clone()),
            "--firmware-root" => firmware_root = Some(PathBuf::from(it.next()?)),
            "--verity" => verity = true,
            "--home" => home = true,
            "--home-keyfile" => home_keyfile = Some(PathBuf::from(it.next()?)),
            "--esp" => esp = true,
            "--disk" => disk = true,
            "--initramfs" => initramfs = true,
            "--init-bin" => init_bin = Some(PathBuf::from(it.next()?)),
            "--initramfs-bin" => initramfs_bins.push(PathBuf::from(it.next()?)),
            "--initramfs-module" => initramfs_modules.push(it.next()?.clone()),
            _ => return None,
        }
    }
    Some(Args {
        out: out?,
        bins,
        kver,
        modules,
        modules_root,
        firmware,
        firmware_root,
        verity,
        home,
        home_keyfile,
        esp,
        disk,
        initramfs,
        init_bin,
        initramfs_bins,
        initramfs_modules,
    })
}

// Read the 32-byte identity master from the keyfile --home is keyed by. Exactly 32 bytes:
// it is the raw master, the same one boot recovers and luksOpen unlocks the layer with.
fn read_master(keyfile: Option<&std::path::Path>) -> Result<[u8; 32], String> {
    let path = keyfile.ok_or("--home needs --home-keyfile <path> (the 32-byte master)")?;
    let bytes = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    bytes.as_slice().try_into().map_err(|_| {
        format!(
            "{} must be exactly 32 bytes, got {}",
            path.display(),
            bytes.len()
        )
    })
}
