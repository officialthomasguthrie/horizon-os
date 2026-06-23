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

    // The kernel gives PID 1 no environment, so set a PATH before anything shells out: cryptsetup
    // and veritysetup live under /usr/sbin in the initramfs, and a bare Command::new finds them by
    // PATH. Without this the LUKS and dm-verity opens fail with "No such file or directory".
    std::env::set_var("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");

    // Mount proc first so the kernel command line is readable, then plan from it.
    mount_proc()?;
    let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
    let params = parse_cmdline(&cmdline);
    eprintln!("horizon-init: cmdline {cmdline:?}");

    // Bring up the kernel filesystems first, so the Key's partitions appear under /dev
    // before anything is resolved or mounted. early_mounts is idempotent (the executor
    // ignores EBUSY on the pseudo filesystems), so the plan running them again is fine.
    execute(&Plan {
        steps: early_mounts(),
    })?;

    // Load the boot-path kernel modules the initramfs carries (the Debian-class kernel ships
    // squashfs, overlay, ext4, the dm-verity/dm-crypt targets, and the virtio block drivers as
    // modules, and a minimal initramfs has no udev or modprobe to load them on demand), in
    // dependency order, so the partitions appear under /dev and the verity/LUKS layers can be
    // opened. A kernel with these built in carries no modules directory, so this is a no-op.
    if let Some(dir) = modules_dir() {
        match load_modules(&dir) {
            Ok(n) => eprintln!(
                "horizon-init: loaded {n} boot-path module(s) from {}",
                dir.display()
            ),
            Err(e) => eprintln!("horizon-init: module load: {e}"),
        }
    }

    // The base must resolve; without the immutable OS there is nothing to boot. The store
    // (data) partition and the encrypted Home layer are optional: their absence, or an
    // explicit Ghost request, means a stateless boot.
    //
    // Block-device probing is asynchronous: virtio_blk creates the disk and its partition nodes a
    // moment after it loads, so poll for the required base to resolve before mounting it (the
    // other partitions on the same disk are ready once the base is). Give up after a few seconds,
    // so a genuinely absent base still fails the boot rather than hanging forever.
    let base = {
        use std::time::{Duration, Instant};
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            match resolve(&params.base, &params.basefs) {
                Ok(s) => break s.read_only(),
                Err(e) if Instant::now() >= deadline => return Err(e),
                Err(_) => std::thread::sleep(Duration::from_millis(50)),
            }
        }
    };
    eprintln!("horizon-init: base resolved to {}", base.dev.display());

    // If the loader supplied a dm-verity root hash, verify the base before mounting it: open
    // a verity device over the raw partition against the hash tree, anchored by that hash,
    // and use the verified mapper as the read-only overlay lower in its place. A tampered
    // base fails to open here rather than booting. Absent the token the base is mounted
    // unverified, the same "boots anywhere" degradation a missing partition gets.
    let base = match &params.verity {
        Some(root_hash) => {
            let hash = resolve(&params.verity_dev, "")?; // a raw hash device, no filesystem
            let verified = verity_open(&base.dev, &hash.dev, BASE_MAPPER, root_hash)?;
            eprintln!(
                "horizon-init: opened dm-verity over the base {} (hash {})",
                base.dev.display(),
                hash.dev.display()
            );
            Source::new(verified, &params.basefs, MountFlags::default()).read_only()
        }
        None => base,
    };

    let store_part = resolve(&params.data, &params.datafs).ok();
    let home_dev = resolve(&params.home, &params.homefs).ok();

    let scratch = PathBuf::from(SCRATCH);
    let layout = Layout::new(&scratch);

    // A Home (Known Surface) boot persists into the encrypted Home layer; it needs both
    // the store (to recover the master) and the Home layer (to unlock with it). Anything
    // else, or an explicit Ghost, runs stateless on tmpfs.
    let want_home = home_wanted(params.mode, store_part.is_some(), home_dev.is_some());

    let mut carry = Vec::new();
    let mut init_args = params.init_args.clone();
    let mut mode = Mode::Ghost;

    // Mount the store partition so the identity can be read before the encrypted layer is
    // opened: read-write for a Home boot (the store accumulates generations), read-only
    // for Ghost, so a Foreign Surface gets no writes (the Ghost read-only store handoff).
    if let Some(part) = &store_part {
        let src = if want_home {
            part.clone()
        } else {
            part.clone().read_only()
        };
        execute(&Plan {
            steps: vec![
                Step::Mkdir(layout.data.clone()),
                Step::Mount {
                    source: src,
                    target: layout.data.clone(),
                },
            ],
        })?;

        // Find the one identity store on the partition, carry it into the new root, and
        // point horizon boot at it.
        match boot::discover(&layout.data) {
            Ok(store) => {
                carry.push(Carry {
                    from: store.clone(),
                    to: PathBuf::from(STORE_MOUNT),
                });
                init_args = vec!["boot".into(), "--root".into(), STORE_MOUNT.into()];

                // Home: recover the master from the store and open the encrypted Home
                // layer with it. If the store cannot unlock, the boot fails here rather
                // than assembling a root over a layer it could not decrypt.
                if want_home {
                    let master = recover_master(&store)?;
                    let dev = home_dev
                        .as_ref()
                        .expect("home_wanted implies a Home device");
                    let mapper = luks_open(&dev.dev, HOME_MAPPER, &master)?;
                    mode = Mode::Home(Source::new(mapper, &params.homefs, MountFlags::default()));
                }
            }
            Err(e) => eprintln!("horizon-init: no identity store on the data partition ({e})"),
        }
    }

    eprintln!(
        "horizon-init: {} mode, base {}",
        if matches!(mode, Mode::Home(_)) {
            "home (encrypted)"
        } else {
            "ghost"
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

// Recover the 32-byte identity master from the store, the same key that opens the
// encrypted Home layer. No authenticator is wired into the initramfs yet, so the master
// is recovered from the console passphrase; a FIDO2 key at the initramfs (identity's
// HardwareKey behind the fido2 feature, the touch-to-boot path) is a later refinement, as
// is handing the recovered master to horizon boot so the session does not unlock a second
// time after the pivot.
#[cfg(target_os = "linux")]
fn recover_master(store: &std::path::Path) -> init::Result<[u8; 32]> {
    let (master, method) =
        boot::unlock(store, None, read_passphrase).map_err(|e| init::Error::Boot(e.to_string()))?;
    eprintln!(
        "horizon-init: unlocked the Home layer via {}",
        method.label()
    );
    Ok(master)
}

// Read the store passphrase from the console. Echo suppression is a later refinement; for
// now the line is read plainly, which the eye-verify at boot will surface.
#[cfg(target_os = "linux")]
fn read_passphrase() -> boot::Result<String> {
    use std::io::Write;
    eprint!("horizon passphrase: ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| boot::Error::Passphrase(e.to_string()))?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("horizon-init runs as PID 1 in a Linux initramfs; it has nothing to do on this host");
    std::process::exit(1);
}
