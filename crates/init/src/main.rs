// horizon-init: PID 1 in Horizon's initramfs.
//
// The kernel execs this as the first userspace process. It reads the boot parameters
// off the kernel command line, finds the Key, assembles the immutable-base +
// writable-overlay root, and switch_roots into `horizon boot`. All the logic is in the
// init library, tested with no devices; this binary is the thin glue that builds a
// plan from the real machine and runs it, proven by actually booting.
//
// Linux only: the executor is kernel work. On other hosts the binary still builds (so
// the workspace builds on darwin) but only prints that it is an initramfs init.

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    match run() {
        // run() returns only if switch_root did not happen, which is a failed boot.
        Ok(()) => {
            eprintln!("horizon-init: switch_root did not take over; halting");
            std::process::ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("horizon-init: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(target_os = "linux")]
fn run() -> init::Result<()> {
    use init::*;
    use std::path::PathBuf;

    // Mount proc first so the kernel command line is readable, then plan from it.
    mount_proc()?;
    let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
    let params = parse_cmdline(&cmdline);
    eprintln!("horizon-init: cmdline {cmdline:?}");

    // The base must resolve; without the immutable OS there is nothing to boot. The
    // data device is optional: its absence simply means Ghost mode.
    let base = resolve(&params.base, &params.basefs)?.read_only();
    let data = resolve(&params.data, &params.datafs).ok();
    let mode = choose_mode(params.mode, data);

    let scratch = PathBuf::from(SCRATCH);
    let layout = Layout::new(&scratch);

    // In Home mode the identity store lives on the persistent data device, which the
    // plan mounts as the overlay backing; carry it into the new root and point
    // horizon boot at it. Ghost mode leaves the Key untouched, so no store is carried
    // and horizon boot reports an empty session (a Foreign-Surface boot with no
    // persistent identity is refined when the Key's partition layout is built).
    let (carry, init_args) = match &mode {
        Mode::Home(_) => (
            vec![Carry {
                from: layout.over.join("store"),
                to: PathBuf::from(STORE_MOUNT),
            }],
            vec!["boot".into(), "--root".into(), STORE_MOUNT.into()],
        ),
        Mode::Ghost => (Vec::new(), params.init_args.clone()),
    };

    eprintln!(
        "horizon-init: {} mode, base {}",
        match mode {
            Mode::Home(_) => "home",
            Mode::Ghost => "ghost",
        },
        base.dev.display()
    );

    let recipe = Recipe {
        scratch,
        base,
        mode,
        carry,
        init: params.init,
        init_args,
    };
    execute(&plan(&recipe))
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("horizon-init runs as PID 1 in a Linux initramfs; it has nothing to do on this host");
    std::process::exit(1);
}
