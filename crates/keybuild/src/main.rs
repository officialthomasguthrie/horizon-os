// horizon-keybuild: build the filesystems of a Horizon Key.
//
// A host-side tool, not part of a running Horizon. It builds the immutable base image
// into an output directory and prints the kernel command line a bootloader passes so
// the init finds the Key. Each --bin installs a host binary into the base's /usr/bin
// with its shared-library closure, so `--bin target/release/horizon --bin
// target/release/horizon-init` makes a base that boots. --module installs a kernel
// module and its modules.dep closure under /lib/modules/<kver>, and --firmware copies a
// firmware blob under /lib/firmware, so the base drives hardware. --stage <src[:dst]> copies
// a host data tree verbatim into the base (the xkb keymap data /usr/share/X11/xkb a keyboard
// needs, libinput's /usr/share/libinput quirks), to dst or, with no dst, the same path.
// --verity builds the
// dm-verity hash tree over the base into base.verity and prints the root hash that anchors
// it. --home builds the encrypted Home writable layer (home.img, a LUKS2 container) keyed
// by the 32-byte master in --home-keyfile, so a Home Surface persists encrypted at rest.
// --esp builds the FAT EFI System Partition (esp.img). With --kernel and --bootloader it is a
// loadable ESP: the bootloader (systemd-boot, or shim) at the removable path /EFI/BOOT/BOOT<arch>.EFI
// (BOOTAA64.EFI / BOOTX64.EFI, read from the bootloader's machine type), the kernel and the built
// initramfs at the root, any --esp-efi binaries under /EFI/BOOT, and the systemd-boot loader config
// carrying the boot command line plus the dm-verity root hash from --verity and any --cmdline tokens
// (with --loader-timeout setting the menu wait); with neither it lays the /EFI/BOOT skeleton. --disk
// assembles the ESP, base, the verity hash device (when --verity), data, and Home partitions
// into one bootable GPT disk (key.img), building the ESP, data, and Home partitions too, so it
// needs --home-keyfile. --initramfs builds the initramfs (initramfs.img, a gzip newc cpio) with
// /init from --init-bin (horizon-init), each --initramfs-bin (cryptsetup) under /usr/sbin, and
// each --initramfs-module under /lib/modules/<kver>, all with their shared-library / modules.dep
// closures; it is built before the ESP so a bootable ESP can write it in.
// --mode <auto|home|ghost> sets the default boot mode baked into the loader's kernel command
// line (default auto: Home if a data device is present, else Ghost), so a Ghost-only Key boots
// without a horizon.mode= override.
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
    staged: Vec<keybuild::Stage>,
    verity: bool,
    home: bool,
    home_keyfile: Option<PathBuf>,
    esp: bool,
    disk: bool,
    initramfs: bool,
    init_bin: Option<PathBuf>,
    initramfs_bins: Vec<PathBuf>,
    initramfs_modules: Vec<String>,
    kernel: Option<PathBuf>,
    bootloader: Option<PathBuf>,
    esp_efi: Vec<PathBuf>,
    loader_timeout: Option<u32>,
    cmdline_extra: Vec<String>,
    mode: Option<keybuild::ModeChoice>,
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let Some(parsed) = parse_args(&args) else {
        eprintln!(
            "usage: horizon-keybuild --out <dir> [--bin <path>]... \
             [--kver <version> --module <name>...] [--modules-root <dir>] \
             [--firmware <path>]... [--firmware-root <dir>] \
             [--stage <src[:dst]>]... [--verity] \
             [--home --home-keyfile <32-byte-master>] [--esp] [--disk] \
             [--initramfs --init-bin <path> [--initramfs-bin <path>]... \
             [--initramfs-module <name>]...] \
             [--kernel <path> --bootloader <path> [--esp-efi <path>]... \
             [--loader-timeout <secs>] [--cmdline <token>]...] \
             [--mode <auto|home|ghost>]"
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
    spec.staged = parsed.staged;
    spec.init_bin = parsed.init_bin;
    spec.initramfs_bins = parsed.initramfs_bins;
    spec.initramfs_modules = parsed.initramfs_modules;
    spec.kernel = parsed.kernel;
    spec.bootloader = parsed.bootloader;
    spec.esp_efi = parsed.esp_efi;
    if let Some(t) = parsed.loader_timeout {
        spec.loader_timeout = t;
    }
    spec.cmdline_extra = parsed.cmdline_extra;
    if let Some(m) = parsed.mode {
        spec.mode = m;
    }
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
            if !spec.staged.is_empty() {
                println!("staged: {} data tree(s)", spec.staged.len());
            }
            // dm-verity over the just-built base: a tamper-evident immutable layer anchored by
            // the printed root hash, which the loader config carries into the kernel command
            // line (horizon.verity=) so the init verifies the base. Threading the root onto the
            // spec is what lets the ESP step below write it into the loader config.
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
                        spec.verity_root = Some(v.root_hex());
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
            // The initramfs: the cpio root filesystem the kernel unpacks before any disk,
            // holding /init (horizon-init) and cryptsetup with their closures and the boot-path
            // modules. Built before the ESP, since a bootable ESP writes it in as INITRD.IMG.
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
            // The FAT EFI System Partition. With a kernel and bootloader it is a loadable ESP
            // (bootloader at /EFI/BOOT/BOOTX64.EFI, the kernel and initramfs at the root, the
            // systemd-boot loader config carrying the boot command line and the verity root);
            // with neither it is the /EFI/BOOT skeleton, the partition firmware reads from.
            if esp {
                let bootable = spec.kernel.is_some() && spec.bootloader.is_some();
                match keybuild::build_esp(&spec) {
                    Ok(p) => println!(
                        "esp: built {} ({} MiB FAT, label {}, {})",
                        p.display(),
                        spec.esp_size_mb,
                        keybuild::ESP_LABEL,
                        if bootable {
                            "bootloader + kernel + initramfs + loader config"
                        } else {
                            "/EFI/BOOT skeleton"
                        }
                    ),
                    Err(e) => {
                        eprintln!("horizon-keybuild: esp: {e}");
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
                    Ok(p) => {
                        // The verity hash partition is laid only when --verity built base.verity.
                        let mut labels = vec![keybuild::ESP_LABEL, spec.base_label.as_str()];
                        if verity {
                            labels.push(keybuild::VERITY_LABEL);
                        }
                        labels.push(spec.data_label.as_str());
                        labels.push(keybuild::HOME_LABEL);
                        println!("disk: built {} (GPT: {})", p.display(), labels.join(" / "));
                    }
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
    let mut staged = Vec::new();
    let mut verity = false;
    let mut home = false;
    let mut home_keyfile = None;
    let mut esp = false;
    let mut disk = false;
    let mut initramfs = false;
    let mut init_bin = None;
    let mut initramfs_bins = Vec::new();
    let mut initramfs_modules = Vec::new();
    let mut kernel = None;
    let mut bootloader = None;
    let mut esp_efi = Vec::new();
    let mut loader_timeout = None;
    let mut cmdline_extra = Vec::new();
    let mut mode = None;
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
            "--stage" => staged.push(parse_stage(it.next()?)?),
            "--verity" => verity = true,
            "--home" => home = true,
            "--home-keyfile" => home_keyfile = Some(PathBuf::from(it.next()?)),
            "--esp" => esp = true,
            "--disk" => disk = true,
            "--initramfs" => initramfs = true,
            "--init-bin" => init_bin = Some(PathBuf::from(it.next()?)),
            "--initramfs-bin" => initramfs_bins.push(PathBuf::from(it.next()?)),
            "--initramfs-module" => initramfs_modules.push(it.next()?.clone()),
            "--kernel" => kernel = Some(PathBuf::from(it.next()?)),
            "--bootloader" => bootloader = Some(PathBuf::from(it.next()?)),
            "--esp-efi" => esp_efi.push(PathBuf::from(it.next()?)),
            "--loader-timeout" => loader_timeout = Some(it.next()?.parse().ok()?),
            "--cmdline" => cmdline_extra.push(it.next()?.clone()),
            "--mode" => {
                mode = Some(match it.next()?.as_str() {
                    "auto" => keybuild::ModeChoice::Auto,
                    "home" => keybuild::ModeChoice::Home,
                    "ghost" => keybuild::ModeChoice::Ghost,
                    _ => return None,
                })
            }
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
        staged,
        verity,
        home,
        home_keyfile,
        esp,
        disk,
        initramfs,
        init_bin,
        initramfs_bins,
        initramfs_modules,
        kernel,
        bootloader,
        esp_efi,
        loader_timeout,
        cmdline_extra,
        mode,
    })
}

// Parse a --stage argument: SRC[:DST], the host path to stage and the absolute path it
// lands at in the base. With no ":DST" the destination defaults to the source path, so
// `--stage /usr/share/X11/xkb` ships that tree at the same path (where libxkbcommon looks);
// an explicit DST is for a cross build whose source tree sits elsewhere. Empty either side
// is rejected so a malformed argument fails the parse rather than staging a root.
fn parse_stage(arg: &str) -> Option<keybuild::Stage> {
    let (src, dst) = match arg.split_once(':') {
        Some((s, d)) => (s, d),
        None => (arg, arg),
    };
    if src.is_empty() || dst.is_empty() {
        return None;
    }
    Some(keybuild::Stage {
        src: PathBuf::from(src),
        dst: PathBuf::from(dst),
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
