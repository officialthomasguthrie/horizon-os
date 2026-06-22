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
// it. The build logic is in the keybuild library, tested there; this is the thin CLI over it.

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
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let Some(parsed) = parse_args(&args) else {
        eprintln!(
            "usage: horizon-keybuild --out <dir> [--bin <path>]... \
             [--kver <version> --module <name>...] [--modules-root <dir>] \
             [--firmware <path>]... [--firmware-root <dir>] [--verity]"
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
    let verity = parsed.verity;

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
    })
}
