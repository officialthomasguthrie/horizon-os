// horizon-keybuild: build the filesystems of a Horizon Key.
//
// A host-side tool, not part of a running Horizon. It builds the immutable base image
// into an output directory and prints the kernel command line a bootloader passes so
// the init finds the Key. The build logic is in the keybuild library, tested there;
// this is the thin CLI over it.

use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let Some(out) = parse_out(&args) else {
        eprintln!("usage: horizon-keybuild --out <dir>");
        return ExitCode::FAILURE;
    };

    let spec = keybuild::KeySpec::new(out);
    match keybuild::build_base(&spec) {
        Ok(path) => {
            println!("built {}", path.display());
            println!("boot cmdline: {}", keybuild::boot_cmdline(&spec));
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("horizon-keybuild: {e}");
            ExitCode::FAILURE
        }
    }
}

fn parse_out(args: &[String]) -> Option<PathBuf> {
    let mut it = args.iter().skip(1);
    while let Some(a) = it.next() {
        if a == "--out" {
            return it.next().map(PathBuf::from);
        }
    }
    None
}
