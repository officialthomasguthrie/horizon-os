use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use constellation::{
    LocalTransport, NetworkTransport, Relay, Rendezvous, RendezvousClient, Server, SyncReport,
};
use lifestream::{Lifestream, Object, ObjectId};
use reconstitution::Share;
use weave::{Broker, Event, GrantId, Limits, Resource, Rights};

#[derive(Parser)]
#[command(name = "horizon", version, about = "Horizon system tools")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Content-addressed state store
    Lifestream {
        #[command(subcommand)]
        op: LsOp,
    },
    /// Object-capability broker and audit log
    Weave {
        #[command(subcommand)]
        op: WeaveOp,
    },
    /// Live transparency surface over the audit log: who reached what, and a kill switch
    Glass {
        #[command(subcommand)]
        op: GlassOp,
    },
    /// Replicate Lifestream objects to another store of the same identity
    Sync {
        /// Source store
        from: PathBuf,
        /// Destination store (created as a replica if it does not exist)
        to: PathBuf,
        /// Also pull the destination back, so both stores end up matching
        #[arg(long)]
        both: bool,
    },
    /// Split or recover a store's master key with k-of-n shares
    Reconstitute {
        #[command(subcommand)]
        op: ReconOp,
    },
    /// Unlock a store with a FIDO2 security key (or software token) instead of the passphrase
    Identity {
        #[command(subcommand)]
        op: IdentityOp,
    },
    /// Replicate over the network to another device of the same identity
    Constellation {
        #[command(subcommand)]
        op: ConstellationOp,
    },
    /// Confine a principal in a Cell and watch it reach a resource only through the broker
    Cell {
        #[command(subcommand)]
        op: CellOp,
    },
    /// Run the Wayland compositor (the experience layer)
    Compositor {
        #[command(subcommand)]
        op: CompositorOp,
    },
    /// Bring this device up into its identity: unlock the store once (a security
    /// key, a token, or the passphrase) and launch the desktop on that master
    Boot {
        /// The identity store to boot. If omitted, discover one under --root
        #[arg(long)]
        store: Option<PathBuf>,
        /// Where to look for the store when none is named: the store itself, or a
        /// mount holding exactly one (a plugged-in Key)
        #[arg(long, default_value = ".")]
        root: PathBuf,
        /// Unlock with a software token file instead of the passphrase
        #[arg(long)]
        token: Option<PathBuf>,
        /// Unlock with a connected USB FIDO2 security key (a touch)
        #[arg(long)]
        fido2: bool,
        /// Days of audit history the Glass desktop summarizes
        #[arg(long, default_value_t = 7)]
        days: u64,
        /// Launch the nested (winit) session instead of the bare-metal (DRM) one,
        /// for development inside an existing desktop
        #[arg(long)]
        nested: bool,
        /// Unlock and prove the store but do not launch the desktop (the boot check)
        #[arg(long)]
        no_session: bool,
    },
}

#[derive(Subcommand)]
enum ConstellationOp {
    /// Serve this store to other devices over QUIC + Noise until stopped
    Serve {
        store: PathBuf,
        /// Address to listen on (host:port)
        #[arg(long, default_value = "0.0.0.0:7777")]
        listen: String,
        /// Do not announce this server to peers on the LAN over mDNS
        #[arg(long)]
        no_announce: bool,
        /// Also use this rendezvous (host:port) so peers beyond the LAN can find this server and hole-punch to it
        #[arg(long)]
        rendezvous: Option<String>,
        /// Also serve through this relay (host:port) so peers can reach this server when no direct path can be opened
        #[arg(long)]
        relay: Option<String>,
    },
    /// Sync with a peer that is serving the same identity
    Sync {
        store: PathBuf,
        /// Peer address (host:port); omit and use --discover or --rendezvous to find one
        peer: Option<String>,
        /// Find a peer of this identity on the LAN over mDNS instead of an address
        #[arg(long)]
        discover: bool,
        /// Find or hole-punch a peer of this identity through a rendezvous (host:port) instead of an address
        #[arg(long)]
        rendezvous: Option<String>,
        /// Tunnel to the peer through this relay (host:port) if no direct path works
        #[arg(long)]
        relay: Option<String>,
        /// Push local -> peer instead of the default pull
        #[arg(long)]
        push: bool,
        /// Sync both directions so the two stores converge
        #[arg(long)]
        both: bool,
    },
    /// Run a rendezvous server: a meeting point that maps identity fingerprints
    /// to addresses so peers find each other beyond the LAN. Holds no identity.
    Rendezvous {
        /// Address to listen on (host:port)
        #[arg(long, default_value = "0.0.0.0:7778")]
        listen: String,
    },
    /// Run a relay server: forwards bytes between two peers that cannot reach
    /// each other directly. Holds no identity and sees only ciphertext.
    Relay {
        /// Address to listen on (host:port)
        #[arg(long, default_value = "0.0.0.0:7779")]
        listen: String,
    },
}

#[derive(Subcommand)]
enum CellOp {
    /// Scripted demo: a confined principal with no authority reaches a file only through the broker, audited
    Demo,
    /// Run a command confined in a Cell: read-only host system, private /proc and /dev, no network, no host data
    Run {
        /// Extra read-only bind, SRC or SRC:DST (repeatable)
        #[arg(long = "ro", value_name = "SRC[:DST]")]
        ro: Vec<String>,
        /// Extra read-write bind, SRC or SRC:DST (repeatable)
        #[arg(long = "rw", value_name = "SRC[:DST]")]
        rw: Vec<String>,
        /// The command and its arguments, after --
        #[arg(last = true, required = true)]
        cmd: Vec<String>,
    },
}

#[derive(Subcommand)]
enum CompositorOp {
    /// Start the headless Wayland server and log windows as they map and unmap
    Run,
    /// Composite client windows once and write the result to a PPM image (no
    /// display needed: the software renderer turns buffers into pixels you can
    /// open anywhere). Waits briefly for a client to connect.
    #[cfg(feature = "compositor-render")]
    Screenshot {
        /// File to write the PPM (P6) image to
        #[arg(long, default_value = "horizon-compositor.ppm")]
        out: PathBuf,
        /// Seconds to wait for a client window before rendering
        #[arg(long, default_value_t = 10)]
        seconds: u64,
        /// Draw the Glass surface of this store as the shell background (the L5
        /// home screen), then composite any client windows over it
        #[arg(long)]
        background: Option<PathBuf>,
        /// Window to summarize for the background Glass surface, in days
        #[arg(long, default_value_t = 7)]
        days: u64,
    },
    /// Open a nested window and show client windows on screen, optionally over a
    /// clickable Glass shell background. Needs a Wayland or X session to nest in
    /// and a GPU; verified by eye, not in CI.
    #[cfg(feature = "compositor-winit")]
    Show {
        /// Draw the Glass surface of this store as the shell background (the L5
        /// home screen); clicking a `sever` button revokes that capability live
        #[arg(long)]
        background: Option<PathBuf>,
        /// Window to summarize for the background Glass surface, in days
        #[arg(long, default_value_t = 7)]
        days: u64,
    },
    /// Drive a real display directly off the GPU (DRM/KMS) with libinput input.
    /// This is the bare-metal path: run it from a console, not nested. Needs a
    /// GPU and a seat; verified by eye on hardware, not in CI.
    #[cfg(feature = "compositor-udev")]
    Drm {
        /// Draw the Glass surface of this store as the shell background (the L5
        /// home screen); clicking a `sever` button revokes that capability live
        #[arg(long)]
        background: Option<PathBuf>,
        /// Window to summarize for the background Glass surface, in days
        #[arg(long, default_value_t = 7)]
        days: u64,
    },
    /// Drive a real display through KMS with no GPU: composite in software (pixman)
    /// into a DRM dumb buffer and page-flip it. Runs where the GPU path cannot,
    /// including plain virtio-gpu (no virgl) and hardware with no usable GLES, so it
    /// is the QEMU boot target and the no-GPU fallback. Run it from a console.
    #[cfg(feature = "compositor-softdrm")]
    Softdrm {
        /// Draw the Glass surface of this store as the shell background (the L5
        /// home screen); clicking a `sever` button revokes that capability live
        #[arg(long)]
        background: Option<PathBuf>,
        /// Window to summarize for the background Glass surface, in days
        #[arg(long, default_value_t = 7)]
        days: u64,
    },
}

#[derive(Subcommand)]
enum ReconOp {
    /// Split this store's master key into n shares, any k of which recover it
    Split {
        store: PathBuf,
        #[arg(long)]
        k: u8,
        #[arg(long)]
        n: u8,
    },
    /// Recover access to a store from k shares, without the passphrase
    Open {
        store: PathBuf,
        /// A recovery share in hex; pass --share once per share
        #[arg(long = "share", required = true)]
        shares: Vec<String>,
    },
}

#[derive(Subcommand)]
enum IdentityOp {
    /// Enroll a security key (or software token) that can unlock this store
    Enroll {
        store: PathBuf,
        /// Path to a 32-byte software token file (created if absent). The token is
        /// "something you have"; keep it safe, it unlocks the store.
        #[arg(long)]
        token: Option<PathBuf>,
        /// Use a connected USB FIDO2 security key instead of a software token
        #[arg(long)]
        fido2: bool,
    },
    /// Unlock this store with an enrolled key, falling back to the passphrase
    Unlock {
        store: PathBuf,
        #[arg(long)]
        token: Option<PathBuf>,
        #[arg(long)]
        fido2: bool,
    },
    /// Recover from k recovery shares and enroll a fresh key, for a lost device
    Reenroll {
        store: PathBuf,
        /// A recovery share in hex; pass --share once per share
        #[arg(long = "share", required = true)]
        shares: Vec<String>,
        #[arg(long)]
        token: Option<PathBuf>,
        #[arg(long)]
        fido2: bool,
    },
    /// List the keyslots enrolled for this store
    List { store: PathBuf },
}

#[derive(Subcommand)]
enum LsOp {
    /// Create a new store
    Init { store: PathBuf },
    /// Snapshot a directory into a new generation (parent is current HEAD)
    Snapshot {
        store: PathBuf,
        dir: PathBuf,
        #[arg(long, default_value = "snapshot")]
        label: String,
    },
    /// Show generation history from HEAD
    Log { store: PathBuf },
    /// Restore a generation (or HEAD) into a directory
    Restore {
        store: PathBuf,
        generation: String,
        dest: PathBuf,
    },
    /// Delete objects not reachable from any ref
    Gc { store: PathBuf },
    /// List refs
    Refs { store: PathBuf },
    /// Show store stats
    Stat { store: PathBuf },
}

// Resources are written file:/path, net:host:port, dev:name, or svc:name/action.
// Rights are a subset of the letters r, w, x.
#[derive(Subcommand)]
enum WeaveOp {
    /// Grant a capability to a principal
    Grant {
        store: PathBuf,
        #[arg(long)]
        principal: String,
        #[arg(long)]
        resource: String,
        #[arg(long, default_value = "r")]
        rights: String,
        /// Expire the grant this many seconds from now
        #[arg(long)]
        ttl: Option<u64>,
        /// Allow at most this many uses
        #[arg(long)]
        uses: Option<u32>,
    },
    /// Revoke a grant by id
    Revoke {
        store: PathBuf,
        #[arg(long)]
        grant: String,
    },
    /// Exercise a grant: reissue a handle, then access a resource through it
    Use {
        store: PathBuf,
        #[arg(long)]
        grant: String,
        #[arg(long)]
        resource: String,
        #[arg(long, default_value = "r")]
        rights: String,
    },
    /// List grants and their status
    Grants { store: PathBuf },
    /// Print the audit log, oldest first
    Audit { store: PathBuf },
    /// Verify the audit chain is intact
    Verify { store: PathBuf },
    /// Run a scripted end-to-end audit demo against a store
    Demo { store: PathBuf },
}

#[derive(Subcommand)]
enum GlassOp {
    /// Render the live transparency view: per-principal channels and a timeline
    Show {
        store: PathBuf,
        /// Length of the window to summarize, in days
        #[arg(long, default_value_t = 7)]
        days: u64,
    },
    /// Pull the kill switch: sever a live capability by its grant id
    Sever {
        store: PathBuf,
        #[arg(long)]
        grant: String,
    },
    /// Draw the transparency view to an image (PPM): the same model the text view
    /// shows, rasterized to pixels with no display needed, so it opens anywhere
    Render {
        store: PathBuf,
        /// Length of the window to summarize, in days
        #[arg(long, default_value_t = 7)]
        days: u64,
        /// File to write the PPM (P6) image to
        #[arg(long, default_value = "horizon-glass.ppm")]
        out: PathBuf,
        /// Surface width in pixels
        #[arg(long, default_value_t = 1280)]
        width: u32,
        /// Surface height in pixels
        #[arg(long, default_value_t = 800)]
        height: u32,
        /// Integer text scale (1 = 8px glyphs, 2 = 16px, ...)
        #[arg(long, default_value_t = 2)]
        scale: u32,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Lifestream { op } => lifestream_cmd(op),
        Cmd::Weave { op } => weave_cmd(op),
        Cmd::Glass { op } => glass_cmd(op),
        Cmd::Sync { from, to, both } => sync_cmd(from, to, both),
        Cmd::Reconstitute { op } => recon_cmd(op),
        Cmd::Identity { op } => identity_cmd(op),
        Cmd::Constellation { op } => constellation_cmd(op),
        Cmd::Cell { op } => cell_cmd(op),
        Cmd::Compositor { op } => compositor_cmd(op),
        Cmd::Boot {
            store,
            root,
            token,
            fido2,
            days,
            nested,
            no_session,
        } => boot_cmd(store, root, token, fido2, days, nested, no_session),
    }
}

fn lifestream_cmd(op: LsOp) -> Result<()> {
    match op {
        LsOp::Init { store } => {
            let pass = passphrase()?;
            let salt = random_salt();
            Lifestream::init(&store, &derive(&pass, &salt))?;
            std::fs::write(store.join("keysalt"), salt).context("write keysalt")?;
            println!("initialized store at {}", store.display());
        }
        LsOp::Snapshot { store, dir, label } => {
            let ls = open(&store)?;
            let parents = ls.head()?.map(|h| vec![h]).unwrap_or_default();
            let tree = ls.snapshot_dir(&dir)?;
            let g = ls.commit(tree, parents, &label)?;
            println!("{g}");
        }
        LsOp::Log { store } => {
            let ls = open(&store)?;
            match ls.head()? {
                None => println!("no commits"),
                Some(h) => {
                    for (id, g) in ls.history(&h)? {
                        println!("{}  {:>12}  {}", &id.to_hex()[..12], g.time_unix, g.label);
                    }
                }
            }
        }
        LsOp::Restore {
            store,
            generation,
            dest,
        } => {
            let ls = open(&store)?;
            let gid = resolve(&ls, &generation)?;
            let root = match ls.get(&gid)? {
                Object::Generation(g) => g.root,
                _ => return Err(anyhow!("{generation} is not a generation")),
            };
            ls.restore_tree(&root, &dest)?;
            println!("restored {} into {}", &gid.to_hex()[..12], dest.display());
        }
        LsOp::Gc { store } => {
            let ls = open(&store)?;
            let mut roots = Vec::new();
            for name in ls.list_refs()? {
                if let Some(id) = ls.get_ref(&name)? {
                    roots.push(id);
                }
            }
            println!("removed {} objects", ls.gc(&roots)?);
        }
        LsOp::Refs { store } => {
            let ls = open(&store)?;
            for name in ls.list_refs()? {
                if let Some(id) = ls.get_ref(&name)? {
                    println!("{name}\t{id}");
                }
            }
        }
        LsOp::Stat { store } => {
            let ls = open(&store)?;
            println!("objects: {}", ls.object_count()?);
            match ls.head()? {
                Some(h) => println!("head:    {h}"),
                None => println!("head:    none"),
            }
        }
    }
    Ok(())
}

fn weave_cmd(op: WeaveOp) -> Result<()> {
    match op {
        WeaveOp::Grant {
            store,
            principal,
            resource,
            rights,
            ttl,
            uses,
        } => {
            let mut b = open_broker(&store)?;
            let mut limits = Limits::none();
            if let Some(secs) = ttl {
                limits = limits.with_expiry(now_unix() + secs);
            }
            if let Some(n) = uses {
                limits = limits.with_uses(n);
            }
            let cap = b.grant(
                principal.as_str().into(),
                parse_resource(&resource)?,
                parse_rights(&rights)?,
                limits,
            )?;
            println!("{}", cap.grant_id());
        }
        WeaveOp::Revoke { store, grant } => {
            let mut b = open_broker(&store)?;
            b.revoke(parse_grant(&grant)?)?;
            println!("revoked {grant}");
        }
        WeaveOp::Use {
            store,
            grant,
            resource,
            rights,
        } => {
            let mut b = open_broker(&store)?;
            let gid = parse_grant(&grant)?;
            let res = parse_resource(&resource)?;
            let rt = parse_rights(&rights)?;
            // the original session handle is gone, so reissue one for the live
            // grant, then exercise it. scope and rights are still checked.
            let outcome = match b.reissue(gid) {
                Ok(cap) => b.access(&cap, &res, rt),
                Err(e) => Err(e),
            };
            match outcome {
                Ok(lease) => println!("allowed  {} {}", lease.resource, lease.rights),
                Err(e) => println!("{e}"),
            }
        }
        WeaveOp::Grants { store } => {
            let b = open_broker(&store)?;
            for g in b.grants() {
                let mut limits = vec![match g.max_uses {
                    Some(m) => format!("uses {}/{m}", g.uses),
                    None => format!("uses {}", g.uses),
                }];
                if let Some(e) = g.expires_unix {
                    limits.push(format!("exp {e}"));
                }
                println!(
                    "{}  {:<7}  {:<10}  {:<3}  {}  [{}]",
                    short(&g.id),
                    g.status,
                    g.principal,
                    g.rights,
                    g.resource,
                    limits.join(" ")
                );
            }
        }
        WeaveOp::Audit { store } => {
            print_audit(&open_broker(&store)?)?;
        }
        WeaveOp::Verify { store } => {
            let b = open_broker(&store)?;
            println!("audit log ok, {} entries", b.verify()?);
        }
        WeaveOp::Demo { store } => weave_demo(&store)?,
    }
    Ok(())
}

// Glass: the same audit log weave prints flat, folded into a live per-principal
// view. `show` renders it; `sever` is the kill switch, the same revoke weave
// does but spoken in Glass's voice. The text is the headless stand-in for the
// drawn compositor surface.
fn glass_cmd(op: GlassOp) -> Result<()> {
    match op {
        GlassOp::Show { store, days } => {
            let mut b = open_broker(&store)?;
            let g = glass::Glass::new(&mut b);
            let window = glass::Window::days(now_unix(), days);
            let model = g.model_within(window, glass::DEFAULT_BUCKETS)?;
            print!("{}", glass::report::text(&model));
        }
        GlassOp::Sever { store, grant } => {
            let mut b = open_broker(&store)?;
            let gid = parse_grant(&grant)?;
            let mut g = glass::Glass::new(&mut b);
            g.sever(gid)?;
            println!("severed {grant}");
        }
        GlassOp::Render {
            store,
            days,
            out,
            width,
            height,
            scale,
        } => {
            let mut b = open_broker(&store)?;
            let g = glass::Glass::new(&mut b);
            let window = glass::Window::days(now_unix(), days);
            let model = g.model_within(window, glass::DEFAULT_BUCKETS)?;
            let pm = glass::render(&model, width, height, scale);
            write_glass_ppm(&out, &pm).with_context(|| format!("write {}", out.display()))?;
            println!(
                "glass: rendered {}x{} surface for {} principal(s); wrote {}",
                pm.width,
                pm.height,
                model.principals.len(),
                out.display()
            );
        }
    }
    Ok(())
}

// Write a Glass Pixmap as a binary PPM (P6). The pixmap is RGBA; PPM is RGB, so
// drop the (always opaque) alpha. The surface renders with no display, so the
// image is the headless way to actually see what Glass draws.
fn write_glass_ppm(path: &Path, pm: &glass::Pixmap) -> io::Result<()> {
    let mut buf = Vec::with_capacity(20 + (pm.width as usize * pm.height as usize * 3));
    buf.extend_from_slice(format!("P6\n{} {}\n255\n", pm.width, pm.height).as_bytes());
    for px in pm.rgba.chunks_exact(4) {
        buf.push(px[0]); // R
        buf.push(px[1]); // G
        buf.push(px[2]); // B
    }
    std::fs::write(path, buf)
}

// A scripted run that shows the whole capability lifecycle landing in the log:
// a grant, an in-scope use, two policy denials, a revocation, and a use after
// revoke. Mutates the given store so you can inspect it afterward with
// `horizon weave audit`.
fn weave_demo(store: &Path) -> Result<()> {
    let mut b = open_broker(store)?;
    let docs = Resource::file("/home/user/docs");
    let cap = b.grant("aura".into(), docs.clone(), Rights::READ, Limits::uses(3))?;
    println!(
        "granted  aura  read  {docs}  (3 uses)  -> {}",
        cap.grant_id()
    );
    println!();

    let step = |b: &mut Broker, res: Resource, rights: Rights| match b.access(&cap, &res, rights) {
        Ok(_) => println!("  allow   {res} {rights}"),
        Err(e) => println!("  {e}  ({res} {rights})"),
    };
    step(
        &mut b,
        Resource::file("/home/user/docs/cattle.odp"),
        Rights::READ,
    );
    step(
        &mut b,
        Resource::file("/home/user/.ssh/id_ed25519"),
        Rights::READ,
    );
    step(
        &mut b,
        Resource::file("/home/user/docs/cattle.odp"),
        Rights::WRITE,
    );

    b.revoke(cap.grant_id())?;
    println!();
    println!("revoked  {}", cap.grant_id());
    println!();
    step(
        &mut b,
        Resource::file("/home/user/docs/cattle.odp"),
        Rights::READ,
    );

    println!();
    println!("# audit log");
    print_audit(&b)?;
    println!();
    println!("verify:  {} entries, chain intact", b.verify()?);
    Ok(())
}

fn cell_cmd(op: CellOp) -> Result<()> {
    match op {
        CellOp::Demo => cell_demo(),
        CellOp::Run { ro, rw, cmd } => cell_run(ro, rw, cmd),
    }
}

// A scripted run that shows confinement and the broker as the only path to a
// resource. A Cell with no filesystem, no network, and no devices is handed one
// socket to the broker; the principal inside fails to open a file by path, asks
// the broker, receives an open fd it could never have made itself, reads through
// it, and the access lands in the audit log (the Glass stand-in).
#[cfg(target_os = "linux")]
fn cell_demo() -> Result<()> {
    use cells::{portal, Cell, Payload};
    use std::ffi::CString;
    use std::os::unix::io::{AsRawFd, RawFd};

    if !cells::available() {
        println!(
            "this kernel will not create unprivileged user namespaces, so a Cell \
             cannot be built here"
        );
        return Ok(());
    }

    // A throwaway identity store and a secret the principal must not reach alone.
    let dir = std::env::temp_dir().join(format!("horizon-cell-demo.{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let secret = dir.join("secret.txt");
    std::fs::write(&secret, b"the-only-way-in-is-the-broker")?;

    let ls = Lifestream::init(dir.join("store"), &[0xC1u8; 32])?;
    let mut broker = Broker::open(ls, weave::Policy::DenyAll)?;
    let cap = broker.grant(
        "app".into(),
        Resource::file(secret.clone()),
        Rights::READ,
        Limits::none(),
    )?;
    println!("granted  app  read  {}", secret.display());
    println!("spawning a confined principal: no filesystem, no network, one socket to the broker");
    println!();
    io::stdout().flush().ok();

    let mut fds = [0 as RawFd; 2];
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) } != 0 {
        return Err(anyhow!("socketpair: {}", io::Error::last_os_error()));
    }
    let (sv, cl) = (fds[0], fds[1]);

    let secret_path = secret.to_string_lossy().into_owned();
    let child = Cell::new()
        .keep_fd(cl)
        .spawn(Payload::call(move || {
            let say = |s: &str| unsafe {
                libc::write(1, s.as_ptr() as *const libc::c_void, s.len());
            };
            // No filesystem: the path does not resolve inside the cell.
            if let Ok(c) = CString::new(secret_path.as_str()) {
                let d = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY) };
                if d >= 0 {
                    unsafe { libc::close(d) };
                    say("  [cell] opened the file directly; confinement is broken\n");
                    return 1;
                }
            }
            say("  [cell] cannot open the file by path: the cell has no filesystem\n");
            // The only way in is to ask the broker.
            let res = Resource::file(secret_path.clone());
            let fd = match portal::request(cl, &res, Rights::READ) {
                Ok(f) => f,
                Err(_) => {
                    say("  [cell] the broker refused\n");
                    return 2;
                }
            };
            say("  [cell] the broker passed a file descriptor; reading through it\n");
            let mut buf = [0u8; 256];
            let n = unsafe {
                libc::read(
                    fd.as_raw_fd(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                )
            };
            if n > 0 {
                say("  [cell] read: ");
                unsafe { libc::write(1, buf.as_ptr() as *const libc::c_void, n as usize) };
                say("\n");
                0
            } else {
                say("  [cell] read failed\n");
                3
            }
        }))
        .context("spawn cell")?;

    // The broker side: drop our copy of the principal's socket, serve one request
    // through weave's access check and materialize, then collect the principal.
    unsafe { libc::close(cl) };
    let served = portal::serve_once(sv, |res, rights| {
        let lease = broker
            .access(&cap, res, rights)
            .map_err(|e| cells::Error::Confine(e.to_string()))?;
        portal::materialize(&lease)
    });
    unsafe { libc::close(sv) };
    if let Err(e) = served {
        eprintln!("broker error: {e}");
    }

    let status = child.wait().context("wait for cell")?;
    println!();
    match status.code {
        Some(0) => println!("principal exited cleanly"),
        Some(c) => println!("principal exited with code {c}"),
        None => println!("principal was killed by a signal"),
    }
    println!();
    println!("# audit log (the Glass stand-in)");
    print_audit(&broker)?;

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn cell_demo() -> Result<()> {
    println!("Cells need Linux (namespaces + seccomp); this host has no confinement.");
    Ok(())
}

// Run a real command confined. bind_host_system makes the host's read-only
// system directories, /proc and /dev available so an ordinary dynamically linked
// binary can run; everything else (the home directory, host data, the network)
// stays out. The command's exit code is propagated, so the cell is transparent
// to a caller that only cares whether the command succeeded.
#[cfg(target_os = "linux")]
fn cell_run(ro: Vec<String>, rw: Vec<String>, cmd: Vec<String>) -> Result<()> {
    use cells::{Cell, Payload};
    use std::ffi::OsString;

    if !cells::available() {
        println!(
            "this kernel will not create unprivileged user namespaces, so a Cell \
             cannot be built here"
        );
        return Ok(());
    }

    let program = cmd.first().ok_or_else(|| anyhow!("no command given"))?;
    let path =
        resolve_program(program).ok_or_else(|| anyhow!("command not found on host: {program}"))?;

    let mut cell = Cell::new().bind_host_system();
    for spec in &ro {
        let (src, dst) = split_bind(spec);
        cell = cell.bind_ro(src, dst);
    }
    for spec in &rw {
        let (src, dst) = split_bind(spec);
        cell = cell.bind_rw(src, dst);
    }

    let argv: Vec<OsString> = cmd.iter().map(OsString::from).collect();
    let env = vec![
        (
            OsString::from("PATH"),
            OsString::from("/usr/bin:/bin:/usr/sbin:/sbin"),
        ),
        (OsString::from("HOME"), OsString::from("/")),
    ];

    eprintln!("cell: read-only host system, private /proc and /dev, no network, no host data");
    eprintln!("cell: exec {}", path.display());
    eprintln!();
    io::stderr().flush().ok();

    let status = cell
        .run(Payload::Exec { path, argv, env })
        .context("run cell")?;
    match status.code {
        Some(0) => Ok(()),
        Some(c) => std::process::exit(c),
        None => Err(anyhow!(
            "command was killed by signal {}",
            status.signal.unwrap_or(0)
        )),
    }
}

#[cfg(not(target_os = "linux"))]
fn cell_run(_ro: Vec<String>, _rw: Vec<String>, _cmd: Vec<String>) -> Result<()> {
    println!("Cells need Linux (namespaces + seccomp); this host has no confinement.");
    Ok(())
}

// Find a program for `cell run`: an explicit path as given, otherwise the first
// match in the standard binary directories (which bind_host_system mounts).
#[cfg(target_os = "linux")]
fn resolve_program(name: &str) -> Option<PathBuf> {
    if name.contains('/') {
        let p = PathBuf::from(name);
        return p.exists().then_some(p);
    }
    for dir in ["/usr/bin", "/bin", "/usr/sbin", "/sbin"] {
        let p = Path::new(dir).join(name);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

// A bind spec is SRC or SRC:DST; with no colon the destination matches the source.
#[cfg(target_os = "linux")]
fn split_bind(spec: &str) -> (PathBuf, PathBuf) {
    match spec.split_once(':') {
        Some((src, dst)) => (PathBuf::from(src), PathBuf::from(dst)),
        None => (PathBuf::from(spec), PathBuf::from(spec)),
    }
}

fn compositor_cmd(op: CompositorOp) -> Result<()> {
    match op {
        CompositorOp::Run => compositor_run(),
        #[cfg(feature = "compositor-render")]
        CompositorOp::Screenshot {
            out,
            seconds,
            background,
            days,
        } => compositor_screenshot(&out, seconds, background.as_deref(), days),
        #[cfg(feature = "compositor-winit")]
        CompositorOp::Show { background, days } => {
            compositor_show(background.as_deref(), days, None)
        }
        #[cfg(feature = "compositor-udev")]
        CompositorOp::Drm { background, days } => compositor_drm(background.as_deref(), days, None),
        #[cfg(feature = "compositor-softdrm")]
        CompositorOp::Softdrm { background, days } => {
            compositor_softdrm(background.as_deref(), days, None)
        }
    }
}

// The Wayland socket lives under XDG_RUNTIME_DIR. A real session always sets it;
// for a bare dev shell, fall back to a private temp dir so the commands still
// work. The library stays strict and binds wherever it points.
#[cfg(target_os = "linux")]
fn compositor_ensure_runtime_dir() -> Result<()> {
    if std::env::var_os("XDG_RUNTIME_DIR").is_none() {
        let dir = std::env::temp_dir().join(format!("horizon-compositor.{}", std::process::id()));
        std::fs::create_dir_all(&dir).context("create runtime dir")?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).ok();
        std::env::set_var("XDG_RUNTIME_DIR", &dir);
        println!(
            "compositor: XDG_RUNTIME_DIR was unset; using {}",
            dir.display()
        );
    }
    Ok(())
}

// Run the compositor's headless core: a real Wayland server clients connect to,
// with no display backend yet. It cannot paint pixels, but the scene graph is
// real, so every window a client opens is tracked; we log them as they map and
// unmap to make that visible at the command line, the way `weave demo` makes the
// audit log visible. Point a client at the printed WAYLAND_DISPLAY to watch.
#[cfg(target_os = "linux")]
fn compositor_run() -> Result<()> {
    if !compositor::available() {
        println!("the compositor needs Linux (Wayland); this host has none");
        return Ok(());
    }

    compositor_ensure_runtime_dir()?;

    let mut comp = compositor::Compositor::new().context("start compositor")?;
    let socket = comp.socket_name().to_string_lossy().into_owned();
    println!("compositor: headless Wayland server (no display backend yet)");
    println!("compositor: listening on WAYLAND_DISPLAY={socket}");
    println!("compositor: connect a client, e.g.  WAYLAND_DISPLAY={socket} <wayland-app>");
    println!("compositor: windows are logged as they map and unmap; Ctrl-C to stop");
    println!();
    io::stdout().flush().ok();

    let mut last = usize::MAX;
    loop {
        comp.dispatch(Some(Duration::from_millis(200)))
            .context("dispatch")?;
        let count = comp.window_count();
        if count != last {
            let titles = comp.window_titles();
            let labels = if titles.is_empty() {
                "(untitled or none)".to_string()
            } else {
                titles.join(", ")
            };
            println!("compositor: {count} window(s) mapped: {labels}");
            io::stdout().flush().ok();
            last = count;
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn compositor_run() -> Result<()> {
    println!("the compositor needs Linux (Wayland); this host has none");
    Ok(())
}

// Composite one frame of whatever clients have mapped and write it to a PPM
// image. This is the headless way to actually see what the compositor draws: the
// software (pixman) renderer turns client buffers into pixels with no display or
// GPU, so the image opens anywhere. Waits up to `seconds` for a window to map.
#[cfg(all(target_os = "linux", feature = "compositor-render"))]
fn compositor_screenshot(
    out: &Path,
    seconds: u64,
    background: Option<&Path>,
    days: u64,
) -> Result<()> {
    compositor_ensure_runtime_dir()?;

    let mut comp = compositor::Compositor::new().context("start compositor")?;
    let socket = comp.socket_name().to_string_lossy().into_owned();
    println!("compositor: software renderer (no display needed)");
    println!("compositor: listening on WAYLAND_DISPLAY={socket}");

    // Draw the store's Glass surface as the shell background (the L5 home screen),
    // at the output size, before compositing any client windows over it.
    if let Some(store) = background {
        let (w, h) = comp.output_size();
        let mut b = open_broker(store)?;
        let g = glass::Glass::new(&mut b);
        let window = glass::Window::days(now_unix(), days);
        let model = g.model_within(window, glass::DEFAULT_BUCKETS)?;
        let pm = glass::render(&model, w as u32, h as u32, 2);
        comp.set_shell_background(&pm.rgba, w, h);
        println!(
            "compositor: Glass shell background from {}",
            store.display()
        );
    }

    println!("compositor: waiting up to {seconds}s for a client window, then rendering");
    io::stdout().flush().ok();

    let deadline = Duration::from_secs(seconds);
    let start = std::time::Instant::now();
    while comp.window_count() == 0 && start.elapsed() < deadline {
        comp.dispatch(Some(Duration::from_millis(50)))
            .context("dispatch")?;
    }
    // A couple more batches so a just-mapped window has its buffer committed.
    for _ in 0..5 {
        comp.dispatch(Some(Duration::from_millis(20))).ok();
    }

    let count = comp.window_count();
    let frame = comp.render().context("render frame")?;
    write_ppm(out, &frame).with_context(|| format!("write {}", out.display()))?;
    println!(
        "compositor: rendered {} window(s) into {}x{}; wrote {}",
        count,
        frame.width,
        frame.height,
        out.display()
    );
    if count == 0 && background.is_none() {
        println!("compositor: (no client connected, so the image is just the clear colour)");
    }
    Ok(())
}

// Write a RenderedFrame as a binary PPM (P6). The frame is Argb8888 little-endian
// (bytes B, G, R, A); PPM is RGB, so reorder and drop alpha.
#[cfg(all(target_os = "linux", feature = "compositor-render"))]
fn write_ppm(path: &Path, frame: &compositor::RenderedFrame) -> io::Result<()> {
    let mut buf = Vec::with_capacity(15 + frame.pixels.len() / 4 * 3);
    buf.extend_from_slice(format!("P6\n{} {}\n255\n", frame.width, frame.height).as_bytes());
    for px in frame.pixels.chunks_exact(4) {
        buf.push(px[2]); // R
        buf.push(px[1]); // G
        buf.push(px[0]); // B
    }
    std::fs::write(path, buf)
}

// Run the on-screen winit backend: a real window, nested in the current Wayland
// or X session, showing the client windows the compositor manages and forwarding
// keyboard and pointer input to them. This is the part that needs a display and a
// GPU, so it is verified by eye.
//
// With --background it also draws a Glass shell behind the windows and routes a
// click on a `sever` button back through Glass to revoke that capability, then
// redraws the surface. The compositor reports a press that landed on no client
// window (`take_shell_click`); the Shell maps it through the scene's hit targets
// (Scene::action_at) to the grant and severs it, exactly as `glass sever` does.
#[cfg(all(target_os = "linux", feature = "compositor-winit"))]
fn compositor_show(background: Option<&Path>, days: u64, master: Option<[u8; 32]>) -> Result<()> {
    compositor_ensure_runtime_dir()?;

    let mut comp = compositor::Compositor::new().context("start compositor")?;
    let socket = comp.socket_name().to_string_lossy().into_owned();
    println!("compositor: on-screen (winit) backend, nested in the current session");
    println!("compositor: listening on WAYLAND_DISPLAY={socket}");
    println!("compositor: connect a client, e.g.  WAYLAND_DISPLAY={socket} <wayland-app>");
    println!("compositor: click a window to focus it; keyboard and pointer go to it");

    // Optional clickable Glass shell, rendered at the output size.
    let (ow, oh) = comp.output_size();
    let mut shell = match background {
        Some(store) => {
            let (shell, rgba) =
                Shell::open(store, days, ow as u32, oh as u32, &socket, master.as_ref())?;
            comp.set_shell_background(&rgba, ow, oh);
            println!(
                "compositor: Glass shell background from {} (click `sever` to revoke a \
                 capability; with no window focused, type a command: launch <app>, sever \
                 <name>, or any text to filter; refreshes live as the audit log changes)",
                store.display()
            );
            Some(shell)
        }
        None => None,
    };

    println!("compositor: close the window to stop");
    io::stdout().flush().ok();

    comp.show(|event| {
        let s = shell.as_mut()?;
        match event {
            compositor::ShellEvent::Click(x, y) => s.click(x, y),
            compositor::ShellEvent::Key(k) => s.key(k),
            compositor::ShellEvent::Tick => s.refresh(),
        }
    })
    .context("run winit backend")
}

// How often the live shell polls the store for changes made outside it (another
// process granting, using, or revoking a capability). Human-scale, so half a
// second reads as immediate while the per-frame cost stays a clock check; an
// actual store read happens at most this often, and re-uploads the surface only
// when the audit log actually changed.
#[cfg(all(target_os = "linux", feature = "compositor-shell"))]
const SHELL_POLL: Duration = Duration::from_millis(500);

// A launched palette client runs confined in a Cell, so it starts with no ambient
// authority: no host files, no network, no devices. Its one channel is the Wayland
// connection to this compositor, which is the display capability you grant by
// launching it; the compositor mediates everything over that socket. Further
// authority (a file, the network) is a Weave grant brokered later, not something
// the app holds by virtue of running as you.
//
// Reaching the display from inside the empty world takes two things: the host's
// read-only system directories (bind_host_system) so a dynamically linked client
// finds its interpreter and libraries, and the compositor's Wayland socket bound
// in at the one path the client looks for it. The net namespace stays empty: a
// Wayland socket is a pathname Unix socket, a filesystem rendezvous rather than a
// network one, so connecting to it crosses an empty network namespace (only an
// abstract socket or real networking would not). No host data is bound: no home,
// no other contents of the host runtime dir. A GPU client would also need a render
// node (/dev/dri), deliberately not granted, so it cannot reach the GPU; an shm
// client composites fine, which is what the compositor imports.

// Inside the cell the socket is bound here and the client is pointed at it. A
// fixed name decouples the in-cell path from the host's wayland-N, and a private
// runtime dir keeps the client from seeing anything else under the host's.
#[cfg(all(target_os = "linux", feature = "compositor-shell"))]
const CELL_RUNTIME_DIR: &str = "/run/horizon";
#[cfg(all(target_os = "linux", feature = "compositor-shell"))]
const CELL_WAYLAND_NAME: &str = "wayland-0";

// Where the Wayland socket is bound inside the cell: the runtime dir joined with
// the display name, so XDG_RUNTIME_DIR + WAYLAND_DISPLAY resolve to exactly it.
// This equality is the invariant a confined client relies on to connect.
#[cfg(all(target_os = "linux", feature = "compositor-shell"))]
fn cell_wayland_socket() -> PathBuf {
    Path::new(CELL_RUNTIME_DIR).join(CELL_WAYLAND_NAME)
}

// The host path of the compositor's listening socket: WAYLAND_DISPLAY under
// XDG_RUNTIME_DIR, or the display itself when it is already an absolute path.
#[cfg(all(target_os = "linux", feature = "compositor-shell"))]
fn host_wayland_socket(runtime: &Path, display: &str) -> PathBuf {
    let p = Path::new(display);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        runtime.join(display)
    }
}

// The environment a confined client sees: a private writable runtime dir holding
// only the brokered Wayland socket, the matching display name, a minimal PATH into
// the bound system dirs, and a HOME. Nothing from the host's runtime dir leaks in.
#[cfg(all(target_os = "linux", feature = "compositor-shell"))]
fn client_env() -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
    use std::ffi::OsString;
    vec![
        (
            OsString::from("WAYLAND_DISPLAY"),
            OsString::from(CELL_WAYLAND_NAME),
        ),
        (
            OsString::from("XDG_RUNTIME_DIR"),
            OsString::from(CELL_RUNTIME_DIR),
        ),
        (
            OsString::from("PATH"),
            OsString::from("/usr/bin:/bin:/usr/sbin:/sbin"),
        ),
        (OsString::from("HOME"), OsString::from("/")),
    ]
}

// Build the cell for a launched Wayland client: the host's read-only system for
// libraries, the compositor's Wayland socket bound in writable at the one path the
// client is pointed at, and nothing else. See the note above on why the empty net
// namespace still reaches the display and what is deliberately withheld.
#[cfg(all(target_os = "linux", feature = "compositor-shell"))]
fn client_cell(host_sock: &Path) -> cells::Cell {
    cells::Cell::new()
        .bind_host_system()
        .bind_rw(host_sock, cell_wayland_socket())
}

// The interactive Glass shell behind an on-screen backend. It holds the broker,
// the window it summarizes, the cached model, the Aura command palette, and the
// last scene it drew. A pointer click resolves against the scene's hit targets and
// severs through Glass; keystrokes (which the compositor routes here when no client
// holds focus) edit the palette, and Enter runs an Aura command: launch a client,
// sever the channels matching a name, or filter the view. It also refreshes on a
// periodic tick: the broker is opened once and would not otherwise see appends
// another process makes to the store, so each poll re-reads the audit log and
// redraws when it changed. Shared by the winit (`show`) and bare-metal (`drm`)
// backends. The model is cached so a typed line resolves against it without a store
// read per keystroke; it is rebuilt whenever the broker state changes.
#[cfg(all(target_os = "linux", feature = "compositor-shell"))]
struct Shell {
    broker: Broker,
    window: glass::Window,
    model: glass::Model,
    palette: glass::Palette,
    scene: glass::Scene,
    width: u32,
    height: u32,
    // WAYLAND_DISPLAY a launched client connects back to (this compositor).
    wayland_display: String,
    // The host XDG_RUNTIME_DIR the compositor's socket lives under, used to find
    // it on disk so it can be bound into a launched client's cell.
    host_runtime: PathBuf,
    // Apps launched from the palette, each confined in its own Cell, kept so the
    // tick can reap the exited ones.
    children: Vec<cells::Child>,
    // When the store was last polled, so the render loop's per-frame Tick costs a
    // clock check until SHELL_POLL elapses.
    last_poll: std::time::Instant,
}

#[cfg(all(target_os = "linux", feature = "compositor-shell"))]
impl Shell {
    // Open a store's Glass shell at a surface size, rendering the first frame.
    // `wayland_display` is the socket a launched client connects back to. Returns
    // the shell and the RGBA to set as the background.
    fn open(
        store: &Path,
        days: u64,
        width: u32,
        height: u32,
        wayland_display: &str,
        key: Option<&[u8; 32]>,
    ) -> Result<(Shell, Vec<u8>)> {
        // The compositor sets XDG_RUNTIME_DIR before opening the shell (its own
        // socket lives under it); the launch path needs it to find that socket on
        // disk and bind it into a client cell.
        let host_runtime = std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .ok_or_else(|| anyhow!("XDG_RUNTIME_DIR is unset"))?;
        // `key` is the master `horizon boot` already unlocked; with it the shell
        // opens the store without a passphrase prompt. Standalone `compositor
        // show/drm --background` pass None and derive from the passphrase.
        let mut broker = open_broker_with(store, key)?;
        let window = glass::Window::days(now_unix(), days);
        let model = glass::Glass::new(&mut broker).model_within(window, glass::DEFAULT_BUCKETS)?;
        let palette = glass::Palette::new();
        let scene = glass::layout(&model, &palette, width, height, 2);
        let rgba = glass::raster::rasterize(&scene).rgba;
        Ok((
            Shell {
                broker,
                window,
                model,
                palette,
                scene,
                width,
                height,
                wayland_display: wayland_display.to_string(),
                host_runtime,
                children: Vec::new(),
                last_poll: std::time::Instant::now(),
            },
            rgba,
        ))
    }

    // Lay the current model and palette out, keep the scene for hit-testing, and
    // return its pixels.
    fn relayout(&mut self) -> Vec<u8> {
        self.scene = glass::layout(&self.model, &self.palette, self.width, self.height, 2);
        glass::raster::rasterize(&self.scene).rgba
    }

    // Re-summarize the broker into the cached model, after a change to it.
    fn reload_model(&mut self) -> Result<()> {
        self.model = glass::Glass::new(&mut self.broker)
            .model_within(self.window, glass::DEFAULT_BUCKETS)?;
        Ok(())
    }

    // Recompute the palette's live preview (the view filter and the hint line)
    // from the current input against the cached model, committing nothing.
    fn preview(&mut self) {
        let r = glass::resolve(&glass::parse(&self.palette.input), &self.model);
        self.palette.filter = r.filter;
        self.palette.message = r.hint;
    }

    // Resolve a click at output-logical (x, y) against the current scene. If it
    // hits a `sever` button, revoke that grant, re-summarize, relayout, and return
    // the new RGBA to redraw; otherwise return None (nothing changed). At output
    // scale 1 the click coordinates are the surface's own pixels, so they index
    // the scene directly.
    fn click(&mut self, x: i32, y: i32) -> Option<Vec<u8>> {
        let grant = match self.scene.action_at(x, y).cloned() {
            Some(glass::Action::Sever(grant)) => grant,
            None => return None,
        };
        if let Err(e) = glass::Glass::new(&mut self.broker).sever(grant) {
            eprintln!("compositor: sever failed: {e}");
            return None;
        }
        println!("compositor: severed {}", grant.to_hex());
        if let Err(e) = self.reload_model() {
            eprintln!("compositor: store reload failed: {e}");
            return None;
        }
        self.preview();
        Some(self.relayout())
    }

    // A keystroke the compositor routed here because no client holds focus. Edit
    // the palette (or, on Enter, run the command) and redraw; the caret alone
    // moving is a visible change, so every key returns a fresh frame.
    fn key(&mut self, key: compositor::ShellKey) -> Option<Vec<u8>> {
        use compositor::ShellKey;
        match key {
            ShellKey::Char(c) => {
                self.palette.insert(c);
                self.preview();
            }
            ShellKey::Backspace => {
                self.palette.backspace();
                self.preview();
            }
            ShellKey::Delete => {
                self.palette.delete();
                self.preview();
            }
            ShellKey::Escape => {
                self.palette.clear();
                self.preview();
            }
            ShellKey::Left => self.palette.left(),
            ShellKey::Right => self.palette.right(),
            ShellKey::Home => self.palette.home(),
            ShellKey::End => self.palette.end(),
            ShellKey::Enter => self.execute(),
        }
        Some(self.relayout())
    }

    // Run the command on the current line (Enter): resolve it against the cached
    // model and carry it out. Launch spawns a client; sever revokes every matching
    // channel through Glass; everything else (empty, help, a bare filter) leaves
    // the view as the preview already set it.
    fn execute(&mut self) {
        let r = glass::resolve(&glass::parse(&self.palette.input), &self.model);
        match r.action {
            glass::PaletteAction::None => {}
            glass::PaletteAction::Launch(cmd) => {
                match self.launch(&cmd) {
                    Ok(()) => {
                        println!("compositor: launching {cmd}");
                        self.palette.message = format!("launching {cmd}");
                    }
                    Err(e) => {
                        eprintln!("compositor: launch failed: {e}");
                        self.palette.message = format!("launch failed: {e}");
                    }
                }
                self.palette.clear();
                self.palette.filter = None;
            }
            glass::PaletteAction::Sever(grants) => {
                let mut severed = 0;
                for g in &grants {
                    match glass::Glass::new(&mut self.broker).sever(*g) {
                        Ok(()) => severed += 1,
                        Err(e) => eprintln!("compositor: sever {} failed: {e}", g.to_hex()),
                    }
                }
                if let Err(e) = self.reload_model() {
                    eprintln!("compositor: store reload failed: {e}");
                }
                println!("compositor: severed {severed} channel(s)");
                self.palette.message = format!("severed {severed} channel(s)");
                self.palette.clear();
                self.palette.filter = None;
            }
        }
    }

    // Launch a Wayland client confined in a Cell connected to this compositor (see
    // the note on client_cell for the confinement). The program is resolved against
    // the host's standard binary dirs, which bind_host_system mounts at the same
    // paths inside, so the resolved path execs in the cell; the compositor's socket
    // is bound in and the env points the client at it, so its window maps into this
    // scene. The child is kept so the tick can reap it.
    fn launch(&mut self, cmd: &str) -> Result<()> {
        let mut parts = cmd.split_whitespace();
        let program = parts.next().ok_or_else(|| anyhow!("no program named"))?;
        let path = resolve_program(program)
            .ok_or_else(|| anyhow!("command not found on host: {program}"))?;
        let argv: Vec<std::ffi::OsString> = std::iter::once(std::ffi::OsString::from(program))
            .chain(parts.map(std::ffi::OsString::from))
            .collect();

        let host_sock = host_wayland_socket(&self.host_runtime, &self.wayland_display);
        let child = client_cell(&host_sock)
            .spawn(cells::Payload::Exec {
                path,
                argv,
                env: client_env(),
            })
            .map_err(|e| anyhow!("confine {program}: {e}"))?;
        self.children.push(child);
        Ok(())
    }

    // Reap launched apps that have exited, so they do not linger as zombies (the
    // cell's init child is our direct child and must be collected). Keep the ones
    // still running (try_wait yields Ok(None)); drop the finished and the failed.
    fn reap(&mut self) {
        self.children
            .retain_mut(|c| matches!(c.try_wait(), Ok(None)));
    }

    // A periodic tick from the render loop. The Shell holds one broker opened once,
    // so it does not see appends another process makes to the store; this re-reads
    // the audit log and, only if it changed, rebuilds the model, refreshes the
    // palette preview, and returns the new RGBA to redraw, so the live desktop
    // reflects a grant, use, or revoke made from outside (e.g. a `horizon weave
    // grant` in another shell). Rate-limited to SHELL_POLL so a 60fps loop does not
    // stat the store every frame; cheap when nothing changed (`Broker::reload` reads
    // only the audit ref and walks no chain, so there is no relayout and no
    // re-upload). It also reaps any apps launched from the palette.
    fn refresh(&mut self) -> Option<Vec<u8>> {
        if self.last_poll.elapsed() < SHELL_POLL {
            return None;
        }
        self.last_poll = std::time::Instant::now();
        self.reap();
        match self.broker.reload() {
            Ok(false) => None,
            Ok(true) => match self.reload_model() {
                Ok(()) => {
                    self.preview();
                    Some(self.relayout())
                }
                Err(e) => {
                    eprintln!("compositor: store reload failed: {e}");
                    None
                }
            },
            Err(e) => {
                eprintln!("compositor: store reload failed: {e}");
                None
            }
        }
    }
}

// Run the bare-metal DRM/KMS backend: drive a real display directly off the GPU
// with libinput input. Unlike `show`, this nests in nothing; it takes over a seat
// and a console, so it is meant to be run from a TTY (e.g. under seatd or
// logind), which is how Horizon boots into its shell on hardware. Needs a GPU and
// a seat, so it is verified by eye on real hardware.
//
// With --background it draws the same clickable Glass shell the winit backend
// does, behind the client windows, and routes a click on a `sever` button back
// through Glass to revoke that capability and redraw, exactly as `show` does. The
// shell is laid out at the compositor's logical output size, so on a larger
// monitor it sits at the top-left, the same single-scene limitation the rest of
// the DRM backend has.
#[cfg(all(target_os = "linux", feature = "compositor-udev"))]
fn compositor_drm(background: Option<&Path>, days: u64, master: Option<[u8; 32]>) -> Result<()> {
    compositor_ensure_runtime_dir()?;

    let mut comp = compositor::Compositor::new().context("start compositor")?;
    let socket = comp.socket_name().to_string_lossy().into_owned();
    println!("compositor: bare-metal DRM/KMS backend (driving the GPU directly)");
    println!("compositor: listening on WAYLAND_DISPLAY={socket}");
    println!("compositor: connect a client, e.g.  WAYLAND_DISPLAY={socket} <wayland-app>");
    println!("compositor: click a window to focus it; keyboard and pointer go to it");

    // Optional clickable Glass shell, rendered at the output size, exactly as the
    // winit backend draws it.
    let (ow, oh) = comp.output_size();
    let mut shell = match background {
        Some(store) => {
            let (shell, rgba) =
                Shell::open(store, days, ow as u32, oh as u32, &socket, master.as_ref())?;
            comp.set_shell_background(&rgba, ow, oh);
            println!(
                "compositor: Glass shell background from {} (click `sever` to revoke a \
                 capability; with no window focused, type a command: launch <app>, sever \
                 <name>, or any text to filter; refreshes live as the audit log changes)",
                store.display()
            );
            Some(shell)
        }
        None => None,
    };

    println!("compositor: switch VT or kill the process to stop");
    io::stdout().flush().ok();

    comp.run_drm(|event| {
        let s = shell.as_mut()?;
        match event {
            compositor::ShellEvent::Click(x, y) => s.click(x, y),
            compositor::ShellEvent::Key(k) => s.key(k),
            compositor::ShellEvent::Tick => s.refresh(),
        }
    })
    .context("run drm backend")
}

// The software DRM/KMS path: drive the screen through KMS with no GPU, compositing
// in software (pixman) into a dumb buffer and page-flipping it. The shell and the
// click/key/tick wiring are identical to `compositor_drm`; only the backend differs
// (a CPU dumb buffer instead of a GBM/GLES scanout), which is what lets it run on
// plain virtio-gpu (no virgl) and on hardware with no usable GLES, the no-GPU
// fallback and the QEMU boot target.
#[cfg(all(target_os = "linux", feature = "compositor-softdrm"))]
fn compositor_softdrm(
    background: Option<&Path>,
    days: u64,
    master: Option<[u8; 32]>,
) -> Result<()> {
    compositor_ensure_runtime_dir()?;

    let mut comp = compositor::Compositor::new().context("start compositor")?;
    let socket = comp.socket_name().to_string_lossy().into_owned();
    println!("compositor: software DRM/KMS backend (pixman scanout, no GPU)");
    println!("compositor: listening on WAYLAND_DISPLAY={socket}");
    println!("compositor: connect a client, e.g.  WAYLAND_DISPLAY={socket} <wayland-app>");
    println!("compositor: click a window to focus it; keyboard and pointer go to it");

    // Optional clickable Glass shell, rendered at the output size, exactly as the
    // GPU DRM and winit backends draw it.
    let (ow, oh) = comp.output_size();
    let mut shell = match background {
        Some(store) => {
            let (shell, rgba) =
                Shell::open(store, days, ow as u32, oh as u32, &socket, master.as_ref())?;
            comp.set_shell_background(&rgba, ow, oh);
            println!(
                "compositor: Glass shell background from {} (click `sever` to revoke a \
                 capability; with no window focused, type a command: launch <app>, sever \
                 <name>, or any text to filter; refreshes live as the audit log changes)",
                store.display()
            );
            Some(shell)
        }
        None => None,
    };

    println!("compositor: switch VT or kill the process to stop");
    io::stdout().flush().ok();

    comp.run_softdrm(|event| {
        let s = shell.as_mut()?;
        match event {
            compositor::ShellEvent::Click(x, y) => s.click(x, y),
            compositor::ShellEvent::Key(k) => s.key(k),
            compositor::ShellEvent::Tick => s.refresh(),
        }
    })
    .context("run software drm backend")
}

// Constellation sync. Both stores belong to one identity, so they share the
// master key: the source's key salt is the identity's, and a fresh destination
// is created from it. Refusing a destination whose salt differs stops you from
// trying to fold two unrelated identities together (their object ids would not
// even line up).
fn sync_cmd(from: PathBuf, to: PathBuf, both: bool) -> Result<()> {
    let pass = passphrase()?;
    let from_salt =
        std::fs::read(from.join("keysalt")).context("read source keysalt (is this a store?)")?;
    let key = derive(&pass, &from_salt);
    let src = Lifestream::open(&from, &key)?;

    let dst = if to.join("keysalt").exists() {
        let to_salt = std::fs::read(to.join("keysalt")).context("read destination keysalt")?;
        if to_salt != from_salt {
            return Err(anyhow!(
                "destination is a different identity (key salt differs); \
                 the Constellation syncs replicas of one identity"
            ));
        }
        Lifestream::open(&to, &key)?
    } else {
        let d = Lifestream::init(&to, &key)?;
        std::fs::write(to.join("keysalt"), &from_salt).context("write destination keysalt")?;
        println!("created replica at {}", to.display());
        d
    };

    let a = LocalTransport::new(src);
    let b = LocalTransport::new(dst);

    print_sync(&from, &to, &constellation::sync(&a, &b)?);
    if both {
        print_sync(&to, &from, &constellation::sync(&b, &a)?);
    }
    Ok(())
}

fn print_sync(from: &Path, to: &Path, r: &SyncReport) {
    print_report(&from.display().to_string(), &to.display().to_string(), r);
}

fn print_report(from: &str, to: &str, r: &SyncReport) {
    println!(
        "{} -> {}: {} objects, {} new ({} bytes)",
        from, to, r.source_objects, r.transferred, r.bytes
    );
    for name in &r.refs_set {
        println!("  ref {name} set");
    }
    for name in &r.refs_advanced {
        println!("  ref {name} advanced");
    }
    for name in &r.refs_conflicted {
        println!("  ref {name} diverged, left unchanged");
    }
}

// Constellation over the network. `serve` opens this store and answers peers
// that prove the same identity through the Noise handshake, advertises itself on
// the LAN over mDNS (unless --no-announce), optionally uses a rendezvous
// (--rendezvous) so peers beyond the LAN can both find it and hole-punch a direct
// path to it, and optionally binds to a relay (--relay) so peers can reach it even
// when no direct path can be opened. `sync` reaches such a peer and runs the same
// diff-and-ship the in-process sync runs, only the far transport is a QUIC link.
// It escalates in cost order: a given host:port or one found with --discover or
// --rendezvous is dialed directly; failing that, --rendezvous brokers a hole
// punch (a direct path that does not relay the data); failing that, --relay
// tunnels the sync through a third host. Direction defaults to pull (bring the
// peer's objects here); --push reverses it and --both converges the two.
// `rendezvous` and `relay` run those meeting points themselves; both hold no
// identity.
fn constellation_cmd(op: ConstellationOp) -> Result<()> {
    match op {
        ConstellationOp::Serve {
            store,
            listen,
            no_announce,
            rendezvous,
            relay,
        } => {
            let key = master_key(&store)?;
            let ls = Lifestream::open(&store, &key).context("open store (wrong passphrase?)")?;
            let addr: SocketAddr = listen.parse().context("parse --listen host:port")?;
            let server = Server::start(addr, key, ls)?;
            let local = server.local_addr();
            println!("serving {} on {}", store.display(), local);
            // Hold the beacon for the life of the process so the announcement
            // stays up; it withdraws when serve exits.
            let _beacon = if no_announce {
                None
            } else {
                match constellation::Beacon::announce(&key, local.port()) {
                    Ok(b) => {
                        eprintln!(
                            "announcing on the LAN as {}",
                            constellation::fingerprint(&key)
                        );
                        Some(b)
                    }
                    Err(e) => {
                        eprintln!("mDNS announce failed, serving without it: {e}");
                        None
                    }
                }
            };
            let rz_addr = parse_opt_addr(rendezvous.as_deref(), "--rendezvous")?;
            // Hold the rendezvous registration: it heartbeats in the background
            // and withdraws when serve exits. This lists the direct address for
            // peers to dial.
            let _registration = match rz_addr {
                None => None,
                Some(rz) => {
                    let client = RendezvousClient::connect(rz).context("connect to rendezvous")?;
                    let reg = client
                        .keepalive(constellation::fingerprint(&key), local.port())
                        .context("register at rendezvous")?;
                    eprintln!(
                        "registered at rendezvous {rz}; it sees this host as {}",
                        reg.observed()
                    );
                    Some(reg)
                }
            };
            // Also wait to be hole-punched at the same rendezvous, so a peer that
            // cannot dial the direct address can still open a direct path before
            // resorting to a relay. Withdraws when serve exits.
            let _punch = match rz_addr {
                None => None,
                Some(rz) => {
                    let listener = server
                        .punch_via_rendezvous(rz)
                        .context("wait to be punched at rendezvous")?;
                    eprintln!("waiting to be hole-punched at rendezvous {rz}");
                    Some(listener)
                }
            };
            // Likewise hold the relay binding: it keeps a connection to the relay
            // open so dialers can be tunneled in, and withdraws when serve exits.
            let _binding = match relay {
                None => None,
                Some(rladdr) => {
                    let rl: SocketAddr = rladdr.parse().context("parse --relay host:port")?;
                    let binding = server.bind_relay(rl).context("bind to relay")?;
                    eprintln!("bound to relay {rl}; peers can reach this server through it");
                    Some(binding)
                }
            };
            eprintln!("peers must prove the same identity; ctrl-c to stop");
            server.wait();
        }
        ConstellationOp::Sync {
            store,
            peer,
            discover,
            rendezvous,
            relay,
            push,
            both,
        } => {
            let key = master_key(&store)?;
            let ls = Lifestream::open(&store, &key).context("open store (wrong passphrase?)")?;
            let rz_addr = parse_opt_addr(rendezvous.as_deref(), "--rendezvous")?;
            let rl_addr = parse_opt_addr(relay.as_deref(), "--relay")?;
            let candidates = resolve_peers(peer, discover, rz_addr, &key)?;
            let (peer, remote) = connect_peer(candidates, rz_addr, rl_addr, key)?;
            let local = LocalTransport::new(ls);
            let here = store.display().to_string();
            if both {
                print_report(&peer, &here, &constellation::sync(&remote, &local)?);
                print_report(&here, &peer, &constellation::sync(&local, &remote)?);
            } else if push {
                print_report(&here, &peer, &constellation::sync(&local, &remote)?);
            } else {
                print_report(&peer, &here, &constellation::sync(&remote, &local)?);
            }
            remote.close().ok();
        }
        ConstellationOp::Rendezvous { listen } => {
            let addr: SocketAddr = listen.parse().context("parse --listen host:port")?;
            let rz = Rendezvous::start(addr)?;
            println!("rendezvous serving on {}", rz.local_addr());
            eprintln!(
                "peers register and look up by identity fingerprint; this server holds no \
                 identity and sees no objects; ctrl-c to stop"
            );
            rz.wait();
        }
        ConstellationOp::Relay { listen } => {
            let addr: SocketAddr = listen.parse().context("parse --listen host:port")?;
            let relay = Relay::start(addr)?;
            println!("relay serving on {}", relay.local_addr());
            eprintln!(
                "peers bind and connect by identity fingerprint; this server only forwards \
                 ciphertext and holds no identity; ctrl-c to stop"
            );
            relay.wait();
        }
    }
    Ok(())
}

// The direct addresses to try dialing, in order. An explicit host:port is the
// sole candidate when given. Otherwise we gather what was asked for: a rendezvous
// lookup (peers beyond the LAN) and/or an mDNS browse (peers on it). One peer can
// surface as several addresses, and a rendezvous entry could even be stale or
// wrong, so the caller tries each until one completes the handshake. The list may
// be empty (nothing asked, or asked and nothing found); the caller decides what
// to do then, including falling back to a relay.
fn resolve_peers(
    peer: Option<String>,
    discover: bool,
    rendezvous: Option<SocketAddr>,
    key: &[u8; 32],
) -> Result<Vec<SocketAddr>> {
    if let Some(p) = peer {
        return Ok(vec![p.parse().context("parse peer host:port")?]);
    }

    let mut candidates: Vec<SocketAddr> = Vec::new();

    if let Some(rz) = rendezvous {
        eprintln!("asking rendezvous {rz} for a peer of this identity...");
        let client = RendezvousClient::connect(rz).context("connect to rendezvous")?;
        let found = client.lookup(&constellation::fingerprint(key))?;
        if found.is_empty() {
            eprintln!("rendezvous knows no peer of this identity");
        } else {
            eprintln!("rendezvous returned {} address(es)", found.len());
        }
        candidates.extend(found);
    }

    if discover {
        eprintln!("searching the LAN for a peer of this identity...");
        let found = constellation::discover(key, Duration::from_secs(3))?;
        if found.is_empty() {
            eprintln!("no peer of this identity found on the LAN");
        } else {
            eprintln!("LAN discovery returned {} address(es)", found.len());
        }
        candidates.extend(found);
    }

    // One peer can resolve to several addresses (loopback and LAN, say); keep
    // them distinct and ordered so the dial is deterministic.
    candidates.sort();
    candidates.dedup();
    Ok(candidates)
}

// Connect to the peer, escalating through the routes in cost order. First try
// each direct candidate; a wrong address (a stale or poisoned rendezvous entry, a
// peer of another identity) fails the Noise handshake here and we move on. If
// none works and a rendezvous was given, try a hole punch it brokers: a direct
// path that, unlike the relay, never carries the sync through a third host. Only
// if that fails too do we fall back to the relay, the path that works even when
// no direct path can be opened at all. Returns a label for the route taken.
fn connect_peer(
    addrs: Vec<SocketAddr>,
    rendezvous: Option<SocketAddr>,
    relay: Option<SocketAddr>,
    key: [u8; 32],
) -> Result<(String, NetworkTransport)> {
    let mut last: Option<String> = None;
    for addr in &addrs {
        match NetworkTransport::connect(*addr, key) {
            Ok(t) => return Ok((addr.to_string(), t)),
            Err(e) => {
                eprintln!("could not connect to {addr}: {e}");
                last = Some(e.to_string());
            }
        }
    }

    if let Some(rz) = rendezvous {
        eprintln!("no direct route; trying a hole punch brokered by rendezvous {rz}...");
        match NetworkTransport::connect_via_punch(rz, key) {
            Ok(t) => return Ok((format!("punch via {rz}"), t)),
            Err(e) => {
                eprintln!("hole punch did not open a path: {e}");
                last = Some(e.to_string());
            }
        }
    }

    if let Some(rl) = relay {
        eprintln!("tunneling through relay {rl}...");
        let t = NetworkTransport::connect_via_relay(rl, key).context("connect through relay")?;
        return Ok((format!("relay {rl}"), t));
    }

    Err(match last {
        Some(e) => anyhow!(
            "no direct route worked and no relay given (same identity/passphrase?); \
             pass --relay to tunnel through a relay. last error: {e}"
        ),
        None => {
            anyhow!("give a peer address, or pass --discover, --rendezvous, or --relay to find one")
        }
    })
}

// Parse an optional host:port flag, naming the flag in the error.
fn parse_opt_addr(s: Option<&str>, flag: &str) -> Result<Option<SocketAddr>> {
    match s {
        None => Ok(None),
        Some(s) => Ok(Some(
            s.parse()
                .with_context(|| format!("parse {flag} host:port"))?,
        )),
    }
}

// Reconstitution. split turns the store's master key into recovery shares you
// spread across people and places; open rebuilds the key from any k of them and
// opens the store with it, the path back in when the passphrase and FIDO2 are
// gone. The on-disk store is unchanged either way; only the key is split or
// rebuilt.
fn recon_cmd(op: ReconOp) -> Result<()> {
    match op {
        ReconOp::Split { store, k, n } => {
            let salt =
                std::fs::read(store.join("keysalt")).context("read keysalt (is this a store?)")?;
            let key = derive(&passphrase()?, &salt);
            // Confirm the passphrase before splitting, so shares cannot be cut
            // from a key that does not open this store.
            Lifestream::open(&store, &key).context("open store (wrong passphrase?)")?;
            let shares = reconstitution::split(&key, k, n).map_err(|e| anyhow!("{e}"))?;
            eprintln!("{n} shares, any {k} recover. keep them apart:");
            for s in shares {
                println!("{}", s.to_hex());
            }
        }
        ReconOp::Open { store, shares } => {
            let parsed = shares
                .iter()
                .map(|s| Share::from_hex(s).map_err(|e| anyhow!("bad share: {e}")))
                .collect::<Result<Vec<_>>>()?;
            let recovered = reconstitution::combine(&parsed).map_err(|e| anyhow!("{e}"))?;
            let key: [u8; 32] = recovered
                .as_slice()
                .try_into()
                .map_err(|_| anyhow!("recovered secret is not a 32-byte key"))?;
            let ls = Lifestream::open(&store, &key).context("open store with recovered key")?;
            // Decrypt HEAD to prove the rebuilt key really is this store's.
            if let Some(h) = ls.head()? {
                ls.get(&h)
                    .context("recovered key did not decrypt the store")?;
            }
            println!("recovered access to {}", store.display());
            println!("objects: {}", ls.object_count()?);
            match ls.head()? {
                Some(h) => println!("head:    {h}"),
                None => println!("head:    none"),
            }
        }
    }
    Ok(())
}

// Identity. A store's master key (Argon2id from the passphrase, the same key
// `reconstitute` splits) can also be unlocked by a FIDO2 security key or a software
// token: `enroll` seals the master in a keyslot the device can reopen, `unlock`
// reopens it (the boot path, the passphrase as fallback), and `reenroll` rebuilds
// the master from recovery shares and seals it for a fresh device, the way back in
// when a key is lost. Keyslots live in the store's `keyslots` file and are additive:
// enrolling one changes nothing else about the store.
fn identity_cmd(op: IdentityOp) -> Result<()> {
    match op {
        IdentityOp::Enroll {
            store,
            token,
            fido2,
        } => {
            // The master from the passphrase, confirmed by opening the store, so a
            // keyslot is never cut from a key that does not open it.
            let key = master_key(&store)?;
            Lifestream::open(&store, &key).context("open store (wrong passphrase?)")?;
            let mut auth = make_authenticator(token, fido2, true)?;
            let slot = identity::enroll(&mut *auth, &key).map_err(|e| anyhow!("{e}"))?;
            let mut slots = load_keyslots(&store)?;
            slots.add(slot);
            save_keyslots(&store, &slots)?;
            println!(
                "enrolled; {} keyslot(s) now unlock {}",
                slots.len(),
                store.display()
            );
        }
        IdentityOp::Unlock {
            store,
            token,
            fido2,
        } => {
            let slots = load_keyslots(&store)?;
            let key = if !slots.is_empty() && (token.is_some() || fido2) {
                let mut auth = make_authenticator(token, fido2, false)?;
                match slots.unlock_any(&mut *auth) {
                    Ok(key) => {
                        eprintln!(
                            "unlocked with {}",
                            if fido2 { "security key" } else { "token" }
                        );
                        key
                    }
                    Err(_) => {
                        eprintln!("no enrolled keyslot matched; falling back to passphrase");
                        master_key(&store)?
                    }
                }
            } else {
                if slots.is_empty() {
                    eprintln!("no keyslots enrolled; using passphrase");
                }
                master_key(&store)?
            };
            let ls = Lifestream::open(&store, &key).context("open store with unlocked key")?;
            // Decrypt HEAD to prove the key really is this store's.
            if let Some(h) = ls.head()? {
                ls.get(&h)
                    .context("unlocked key did not decrypt the store")?;
            }
            println!("unlocked {}", store.display());
            println!("objects: {}", ls.object_count()?);
            match ls.head()? {
                Some(h) => println!("head:    {h}"),
                None => println!("head:    none"),
            }
        }
        IdentityOp::Reenroll {
            store,
            shares,
            token,
            fido2,
        } => {
            let parsed = shares
                .iter()
                .map(|s| Share::from_hex(s).map_err(|e| anyhow!("bad share: {e}")))
                .collect::<Result<Vec<_>>>()?;
            let recovered = reconstitution::combine(&parsed).map_err(|e| anyhow!("{e}"))?;
            let key: [u8; 32] = recovered
                .as_slice()
                .try_into()
                .map_err(|_| anyhow!("recovered secret is not a 32-byte key"))?;
            // Prove the rebuilt key opens this store before enrolling against it.
            let ls = Lifestream::open(&store, &key).context("open store with recovered key")?;
            if let Some(h) = ls.head()? {
                ls.get(&h)
                    .context("recovered key did not decrypt the store")?;
            }
            let mut auth = make_authenticator(token, fido2, true)?;
            let slot = identity::enroll(&mut *auth, &key).map_err(|e| anyhow!("{e}"))?;
            let mut slots = load_keyslots(&store)?;
            slots.add(slot);
            save_keyslots(&store, &slots)?;
            println!(
                "recovered and enrolled a new key; {} keyslot(s) now unlock {}",
                slots.len(),
                store.display()
            );
        }
        IdentityOp::List { store } => {
            let slots = load_keyslots(&store)?;
            println!(
                "{} keyslot(s) enrolled for {}",
                slots.len(),
                store.display()
            );
            for (i, slot) in slots.slots().iter().enumerate() {
                let id = &slot.credential().0;
                let prefix: String = id.iter().take(8).map(|b| format!("{b:02x}")).collect();
                println!("  [{i}] credential {prefix} ({} bytes)", id.len());
            }
        }
    }
    Ok(())
}

// Boot. The seam that joins identity to the experience layer: unlock the store's
// master once (a FIDO2 touch, a software token, or the passphrase) and launch the
// desktop on that same master, so a device boots straight into its identity with no
// second prompt. The unlock and HEAD proof are the cross-platform `boot` crate; the
// session it hands the master to is the compositor, behind its display backends, so
// the testable part runs on every host and only the on-screen launch needs hardware.
fn boot_cmd(
    store: Option<PathBuf>,
    root: PathBuf,
    token: Option<PathBuf>,
    fido2: bool,
    days: u64,
    nested: bool,
    no_session: bool,
) -> Result<()> {
    // The store to boot: the one named, or the single one discovered under root (a
    // plugged-in Key mounted there). Discovery refuses to guess between several.
    let store = match store {
        Some(s) => {
            if !boot::is_store(&s) {
                return Err(anyhow!("{} is not a Horizon store", s.display()));
            }
            s
        }
        None => boot::discover(&root).map_err(|e| anyhow!("{e}"))?,
    };

    // The device a holder presented, if any. With neither a token nor a security
    // key, boot is passphrase-only, so we do not build an authenticator (and do not
    // require one). create=false: boot unlocks an existing token, never mints one.
    let mut auth = if token.is_some() || fido2 {
        Some(make_authenticator(token, fido2, false)?)
    } else {
        None
    };

    // If the initramfs handed us the master it already recovered to open the Home layer,
    // adopt it instead of unlocking a second time (the single-passphrase Home boot).
    // Otherwise unlock normally: a security key, a token, or the passphrase.
    let booted = match boot::take_handed_master() {
        Some(master) => {
            let master = master.map_err(|e| anyhow!("{e}"))?;
            eprintln!("boot: adopting the master handed from the initramfs");
            boot::adopt(&store, master).map_err(|e| anyhow!("{e}"))?
        }
        None => {
            eprintln!("boot: unlocking {}", store.display());
            boot::boot(&store, auth.as_deref_mut(), || {
                passphrase().map_err(|e| boot::Error::Passphrase(e.to_string()))
            })
            .map_err(|e| anyhow!("{e}"))?
        }
    };

    println!(
        "boot: unlocked {} with the {}",
        booted.store.display(),
        booted.method.label()
    );
    println!("boot: {} object(s)", booted.objects);
    match &booted.head {
        Some(h) => println!("boot: head {h}"),
        None => println!("boot: head none (store has no snapshot yet)"),
    }

    if no_session {
        println!("boot: --no-session, not launching the desktop");
        return Ok(());
    }

    launch_session(&store, days, nested, booted.master)
}

// Launch the desktop on the already-unlocked master: the bare-metal DRM backend for
// a real boot, the nested winit backend under --nested for development inside an
// existing session. The master is threaded through so the session opens the store
// without re-deriving from the passphrase. Each backend exists only in a build with
// its feature; a build without it says how to get it instead of failing silently.
fn launch_session(store: &Path, days: u64, nested: bool, master: [u8; 32]) -> Result<()> {
    // Bring up udev before the session so libinput accepts the input devices.
    udev_coldplug();
    if nested {
        launch_nested(store, days, master)
    } else {
        launch_drm(store, days, master)
    }
}

// Bring up udev so the compositor's libinput sees a usable keyboard and pointer. The
// minimal boot runs no udev daemon, so the kernel's input devices are never marked
// "initialized" in udev's database, and libinput refuses an uninitialized device
// ("udev device never initialized") whichever way it is added. So start the daemon and
// coldplug: re-emit the `add` uevent for every existing device and wait for udevd to
// process them, which writes the /run/udev/data entries that mark each device
// initialized (the gate libinput checks). systemd-udevd is the udevadm multi-call binary
// under that argv[0], so it is run by forcing arg0 rather than shipping a second name.
// Best-effort: every step logs and continues, so a base without udevadm, or a daemon
// already running, degrades input rather than breaking the boot. This is the boot path's
// job (it is the post-pivot init); the standalone `compositor` dev commands assume a
// system that already runs udev.
#[cfg(all(
    target_os = "linux",
    any(
        feature = "compositor-softdrm",
        feature = "compositor-udev",
        feature = "compositor-winit"
    )
))]
fn udev_coldplug() {
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    let udevadm = "/usr/bin/udevadm";
    if !Path::new(udevadm).exists() {
        eprintln!("boot: no {udevadm}; input devices may be unavailable");
        return;
    }
    // Start the daemon. --resolve-names=never keeps it from resolving rule user/group
    // names through nss, which a minimal base has no libraries for. --daemon forks and
    // returns, so status() just waits for that quick parent exit.
    let started = Command::new(udevadm)
        .arg0("systemd-udevd")
        .args(["--daemon", "--resolve-names=never"])
        .status();
    match started {
        Ok(s) if s.success() => {}
        Ok(s) => eprintln!("boot: udevd exited {s}; input may be unavailable"),
        Err(e) => {
            eprintln!("boot: could not start udevd ({e}); input may be unavailable");
            return;
        }
    }
    // Coldplug: replay the add events for already-present devices, then wait for the
    // queue to drain so the device db is written before the compositor opens libinput.
    let _ = Command::new(udevadm)
        .args(["trigger", "--action=add"])
        .status();
    let _ = Command::new(udevadm)
        .args(["settle", "--timeout=10"])
        .status();
}

#[cfg(not(all(
    target_os = "linux",
    any(
        feature = "compositor-softdrm",
        feature = "compositor-udev",
        feature = "compositor-winit"
    )
)))]
fn udev_coldplug() {}

// Prefer the software backend when it is built in: it drives any KMS device with
// no GPU, so it is the safe boot default for a Key that lands on unknown hardware
// (or a plain virtio-gpu, as in QEMU), where the GLES path may not start. A build
// that wants the GPU path turns on compositor-udev alone; one that wants the
// universal path turns on compositor-softdrm (probing for GLES and falling back at
// runtime is a later refinement).
#[cfg(all(target_os = "linux", feature = "compositor-softdrm"))]
fn launch_drm(store: &Path, days: u64, master: [u8; 32]) -> Result<()> {
    println!("boot: launching the desktop (software DRM/KMS, no GPU)");
    compositor_softdrm(Some(store), days, Some(master))
}

#[cfg(all(
    target_os = "linux",
    feature = "compositor-udev",
    not(feature = "compositor-softdrm")
))]
fn launch_drm(store: &Path, days: u64, master: [u8; 32]) -> Result<()> {
    println!("boot: launching the desktop (bare-metal DRM/KMS)");
    compositor_drm(Some(store), days, Some(master))
}

#[cfg(not(all(
    target_os = "linux",
    any(feature = "compositor-softdrm", feature = "compositor-udev")
)))]
fn launch_drm(_store: &Path, _days: u64, _master: [u8; 32]) -> Result<()> {
    Err(anyhow!(
        "this build has no DRM backend; rebuild with --features compositor-softdrm \
         (software scanout, drives any KMS device with no GPU) or --features \
         compositor-udev (GPU/GLES), or pass --nested in a build with --features \
         compositor-winit to nest in an existing session"
    ))
}

#[cfg(all(target_os = "linux", feature = "compositor-winit"))]
fn launch_nested(store: &Path, days: u64, master: [u8; 32]) -> Result<()> {
    println!("boot: launching the desktop (nested winit session)");
    compositor_show(Some(store), days, Some(master))
}

#[cfg(not(all(target_os = "linux", feature = "compositor-winit")))]
fn launch_nested(_store: &Path, _days: u64, _master: [u8; 32]) -> Result<()> {
    Err(anyhow!(
        "this build has no nested (winit) backend; rebuild with --features \
         compositor-winit"
    ))
}

// The store's keyslot file, empty if none has been enrolled yet.
fn load_keyslots(store: &Path) -> Result<identity::Keyslots> {
    let path = store.join("keyslots");
    match std::fs::read(&path) {
        Ok(bytes) => identity::Keyslots::decode(&bytes).map_err(|e| anyhow!("read keyslots: {e}")),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(identity::Keyslots::new()),
        Err(e) => Err(anyhow!("read keyslots: {e}")),
    }
}

fn save_keyslots(store: &Path, slots: &identity::Keyslots) -> Result<()> {
    std::fs::write(store.join("keyslots"), slots.encode()).context("write keyslots")
}

// Build the authenticator the identity commands act through: a real USB FIDO2 key
// (--fido2, only in a build with that support) or a software token from a file.
fn make_authenticator(
    token: Option<PathBuf>,
    fido2: bool,
    create: bool,
) -> Result<Box<dyn identity::Authenticator>> {
    if fido2 {
        #[cfg(feature = "identity-fido2")]
        {
            let key = identity::HardwareKey::open(fido2_pin())
                .map_err(|e| anyhow!("open security key: {e}"))?;
            return Ok(Box::new(key));
        }
        #[cfg(not(feature = "identity-fido2"))]
        {
            return Err(anyhow!(
                "this build has no FIDO2 support (rebuild with --features identity-fido2)"
            ));
        }
    }
    let path = token
        .ok_or_else(|| anyhow!("pass --token <file> (or --fido2 in a build with FIDO2 support)"))?;
    let seed = load_or_create_token(&path, create)?;
    Ok(Box::new(identity::SoftwareAuthenticator::new(seed)))
}

// Read a 32-byte software token, or, when enrolling, create one if it is absent so
// the holder ends up with a token file. The seed is the secret a software token
// holds, so it is kept out of the store.
fn load_or_create_token(path: &Path, create: bool) -> Result<[u8; 32]> {
    use rand::RngCore;
    match std::fs::read(path) {
        Ok(bytes) => bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("token file {} is not 32 bytes", path.display())),
        Err(e) if e.kind() == io::ErrorKind::NotFound && create => {
            let mut seed = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut seed);
            std::fs::write(path, seed)
                .with_context(|| format!("write token {}", path.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
            }
            eprintln!(
                "wrote a new software token to {} (keep it safe, it unlocks this store)",
                path.display()
            );
            Ok(seed)
        }
        Err(e) => Err(anyhow!("read token {}: {e}", path.display())),
    }
}

// The FIDO2 device PIN, from the environment or prompted; None if the key needs no
// user verification.
#[cfg(feature = "identity-fido2")]
fn fido2_pin() -> Option<String> {
    if let Ok(p) = std::env::var("HORIZON_FIDO2_PIN") {
        return Some(p);
    }
    eprint!("security key PIN (blank if none): ");
    io::stderr().flush().ok();
    let mut s = String::new();
    if io::stdin().read_line(&mut s).is_ok() {
        let p = s.trim_end().to_string();
        if !p.is_empty() {
            return Some(p);
        }
    }
    None
}

fn print_audit(b: &Broker) -> Result<()> {
    for e in b.audit()? {
        println!(
            "{:>4}  {:>11}  {}",
            e.seq,
            e.time_unix,
            render_event(&e.event)
        );
    }
    Ok(())
}

fn render_event(e: &Event) -> String {
    match e {
        Event::Grant {
            grant,
            principal,
            resource,
            rights,
            expires_unix,
            max_uses,
        } => {
            let mut lim = String::new();
            if let Some(u) = max_uses {
                lim.push_str(&format!(" {u}use"));
            }
            if let Some(x) = expires_unix {
                lim.push_str(&format!(" exp{x}"));
            }
            format!(
                "grant   {principal:<8} {rights:<3} {resource} [{}{lim}]",
                short(grant)
            )
        }
        Event::Use {
            grant,
            principal,
            resource,
            rights,
        } => format!(
            "use     {principal:<8} {rights:<3} {resource} [{}]",
            short(grant)
        ),
        Event::Deny {
            principal,
            resource,
            rights,
            reason,
        } => format!("deny    {principal:<8} {rights:<3} {resource} ({reason})"),
        Event::Revoke { grant } => format!("revoke  [{}]", short(grant)),
    }
}

fn short(g: &GrantId) -> String {
    g.to_hex()[..8].to_string()
}

fn open_broker(store: &Path) -> Result<Broker> {
    open_broker_with(store, None)
}

// Open the broker over the store, using an already-unlocked master when one is
// supplied and deriving it from the passphrase otherwise. `horizon boot` unlocks
// the master once (a touch, a token, or the passphrase) and hands it to the
// session it launches, so the desktop opens the same store without a second
// prompt; the standalone session commands pass None and prompt as before.
fn open_broker_with(store: &Path, key: Option<&[u8; 32]>) -> Result<Broker> {
    let ls = match key {
        Some(k) => Lifestream::open(store, k)?,
        None => open(store)?,
    };
    Ok(Broker::open(ls, weave::Policy::DenyAll)?)
}

fn parse_resource(s: &str) -> Result<Resource> {
    Resource::parse(s).ok_or_else(|| {
        anyhow!("bad resource '{s}' (file:/p, net:host:port, dev:name, svc:name/act)")
    })
}

fn parse_rights(s: &str) -> Result<Rights> {
    Rights::parse(s).ok_or_else(|| anyhow!("bad rights '{s}' (letters r, w, x)"))
}

fn parse_grant(s: &str) -> Result<GrantId> {
    GrantId::from_hex(s).ok_or_else(|| anyhow!("bad grant id '{s}'"))
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn open(store: &Path) -> Result<Lifestream> {
    Ok(Lifestream::open(store, &master_key(store)?)?)
}

// The store's master key from the passphrase and its salt. Constellation needs
// the key itself, not just an open store, to bind the Noise handshake to the
// identity.
fn master_key(store: &Path) -> Result<[u8; 32]> {
    let salt = std::fs::read(store.join("keysalt")).context("read keysalt (is this a store?)")?;
    Ok(derive(&passphrase()?, &salt))
}

fn resolve(ls: &Lifestream, name: &str) -> Result<ObjectId> {
    if name.eq_ignore_ascii_case("head") {
        ls.head()?.ok_or_else(|| anyhow!("no HEAD yet"))
    } else {
        ObjectId::from_hex(name).ok_or_else(|| anyhow!("bad id: {name}"))
    }
}

fn passphrase() -> Result<String> {
    if let Ok(p) = std::env::var("HORIZON_PASSPHRASE") {
        return Ok(p);
    }
    eprint!("passphrase: ");
    io::stderr().flush().ok();
    let mut s = String::new();
    io::stdin().read_line(&mut s)?;
    Ok(s.trim_end().to_string())
}

fn random_salt() -> [u8; 16] {
    use rand::RngCore;
    let mut s = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut s);
    s
}

// Argon2id passphrase to master key, the single canonical derivation defined in
// the boot crate so every tool (init, recon, identity, the session) derives a
// store's master identically; a divergence here would make a store openable one
// way and not another.
fn derive(pass: &str, salt: &[u8]) -> [u8; 32] {
    boot::derive(pass, salt)
}

// The cell a launched palette client runs in: the construction (binds + env) is
// pure and assertable here without a screen; only the client actually mapping a
// window needs one. The connect test proves the harder claim, that the empty net
// namespace still reaches the display, by connecting through the bound socket.
// The identity story at the store level, cross-platform so it runs in the default
// test suite on every host: enroll a token, persist and reload the keyslots file,
// unlock with it, then recover the master from k-of-n shares and enroll a fresh
// token. Mirrors the identity CLI without the passphrase prompt, and proves the
// recovered key is the original and opens the store.
#[cfg(test)]
mod identity_tests {
    use super::*;
    use identity::{enroll, Keyslots, SoftwareAuthenticator};

    #[test]
    fn enroll_unlock_and_reenroll_from_shares() {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("store");
        let master = [42u8; 32];
        Lifestream::init(&store, &master).unwrap();

        // Enroll a software token; persist and reload the keyslots from the store.
        let mut token = SoftwareAuthenticator::new([1u8; 32]);
        let mut slots = Keyslots::new();
        slots.add(enroll(&mut token, &master).unwrap());
        save_keyslots(&store, &slots).unwrap();

        let loaded = load_keyslots(&store).unwrap();
        assert_eq!(loaded.len(), 1);
        let unlocked = loaded.unlock_any(&mut token).unwrap();
        assert_eq!(unlocked, master);
        // The unlocked key really opens the store.
        Lifestream::open(&store, &unlocked).unwrap();

        // Lose the token: rebuild the master from 2 of 3 shares, enroll a new one.
        let shares = reconstitution::split(&master, 2, 3).unwrap();
        let recovered = reconstitution::combine(&shares[..2]).unwrap();
        let recovered: [u8; 32] = recovered.try_into().unwrap();
        assert_eq!(recovered, master);

        let mut new_token = SoftwareAuthenticator::new([2u8; 32]);
        let mut after_loss = load_keyslots(&store).unwrap();
        after_loss.add(enroll(&mut new_token, &recovered).unwrap());
        save_keyslots(&store, &after_loss).unwrap();

        // Both the new and the old token now unlock the store.
        let final_slots = load_keyslots(&store).unwrap();
        assert_eq!(final_slots.len(), 2);
        assert_eq!(final_slots.unlock_any(&mut new_token).unwrap(), master);
        assert_eq!(final_slots.unlock_any(&mut token).unwrap(), master);
        Lifestream::open(&store, &final_slots.unlock_any(&mut new_token).unwrap()).unwrap();

        // A token that was never enrolled cannot unlock.
        let mut stranger = SoftwareAuthenticator::new([9u8; 32]);
        assert!(final_slots.unlock_any(&mut stranger).is_err());
    }
}

// Boot ties identity to the session: a device unlocks its master once and the
// desktop opens on that same master. The unlock and proof live in the `boot` crate
// and are tested there; these tests prove the binary-level integration, that the
// master a token unlocks really opens the session's store with no passphrase, and
// that `boot_cmd` runs the whole path through the binary. Cross-platform, so they
// run in the default suite on every host (the on-screen launch is the only part
// that needs hardware, eye-verified like the rest of the backend).
#[cfg(test)]
mod boot_tests {
    use super::*;
    use identity::{enroll, Keyslots, SoftwareAuthenticator};

    // Build a store the way the CLI does: a passphrase-derived master, the salt on
    // disk, and one committed snapshot so HEAD has something the master decrypts.
    fn make_store(store: &Path, pass: &str) -> [u8; 32] {
        let salt = random_salt();
        let master = derive(pass, &salt);
        let ls = Lifestream::init(store, &master).unwrap();
        std::fs::write(store.join("keysalt"), salt).unwrap();
        let content = store.join("content");
        std::fs::create_dir_all(&content).unwrap();
        std::fs::write(content.join("note"), b"hello horizon").unwrap();
        let tree = ls.snapshot_dir(&content).unwrap();
        ls.commit(tree, vec![], "first").unwrap();
        master
    }

    #[test]
    fn boot_unlocks_with_a_token_and_the_session_opens_on_that_master() {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("store");
        let master = make_store(&store, "a passphrase nobody types at boot");

        // Enroll a software token as one of the store's keyslots.
        let mut token = SoftwareAuthenticator::new([7u8; 32]);
        let mut slots = Keyslots::new();
        slots.add(enroll(&mut token, &master).unwrap());
        save_keyslots(&store, &slots).unwrap();

        // Boot with the token, the passphrase fallback wired to panic: a touch
        // (here a token) recovers the master with no passphrase typed.
        let booted = boot::boot(&store, Some(&mut token), || {
            panic!("the passphrase must not be requested when the token unlocks")
        })
        .unwrap();
        assert_eq!(booted.master, master);
        assert_eq!(booted.method, boot::Method::Keyslot);
        assert!(booted.head.is_some());

        // The session opens the SAME store on that unlocked master, no passphrase:
        // this is the threading boot relies on, open_broker_with(Some(master)). It
        // would prompt for the passphrase if it derived the key itself.
        let _broker = open_broker_with(&store, Some(&booted.master)).unwrap();
    }

    #[test]
    fn boot_cmd_no_session_unlocks_through_the_binary() {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("store");
        let master = make_store(&store, "passphrase");

        // Enroll a token and write the matching token file the command unlocks with.
        let mut token = SoftwareAuthenticator::new([3u8; 32]);
        let mut slots = Keyslots::new();
        slots.add(enroll(&mut token, &master).unwrap());
        save_keyslots(&store, &slots).unwrap();
        let token_file = dir.path().join("token");
        std::fs::write(&token_file, [3u8; 32]).unwrap();

        // The whole boot path through the binary: named store, build the token
        // authenticator, unlock, prove HEAD, then stop before launching a desktop.
        // No passphrase env is set, so reaching Ok proves the token alone unlocked.
        boot_cmd(
            Some(store.clone()),
            PathBuf::from("."),
            Some(token_file),
            false, // fido2
            7,     // days
            false, // nested
            true,  // no_session: the boot check, no desktop
        )
        .unwrap();
    }

    #[test]
    fn the_passphrase_is_the_fallback_when_no_token_matches() {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("store");
        let pass = "the typed secret";
        let master = make_store(&store, pass);

        // A store with one enrolled token, and a stranger token that matches no slot.
        let mut owner = SoftwareAuthenticator::new([1u8; 32]);
        let mut slots = Keyslots::new();
        slots.add(enroll(&mut owner, &master).unwrap());
        save_keyslots(&store, &slots).unwrap();
        let mut stranger = SoftwareAuthenticator::new([9u8; 32]);

        // The stranger unlocks nothing, so boot falls back to the passphrase and
        // still reaches the same master.
        let booted = boot::boot(&store, Some(&mut stranger), || Ok(pass.to_string())).unwrap();
        assert_eq!(booted.master, master);
        assert_eq!(booted.method, boot::Method::Passphrase);
    }

    #[test]
    fn the_kdf_is_one_definition() {
        // main's derive delegates to boot::derive: a store made with one opens with
        // the other. A divergence would lock a store made by `lifestream init`.
        let salt = b"some-store-salt";
        assert_eq!(derive("pw", salt), boot::derive("pw", salt));
    }
}

#[cfg(all(test, target_os = "linux", feature = "compositor-shell"))]
mod client_cell_tests {
    use super::*;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::net::UnixListener;

    #[test]
    fn host_socket_path_joins_a_name_and_passes_an_absolute_through() {
        let rt = Path::new("/run/user/1000");
        // A bare WAYLAND_DISPLAY name resolves under the host runtime dir.
        assert_eq!(
            host_wayland_socket(rt, "wayland-1"),
            Path::new("/run/user/1000/wayland-1")
        );
        // An absolute one is taken as-is.
        assert_eq!(
            host_wayland_socket(rt, "/tmp/x/wayland-3"),
            Path::new("/tmp/x/wayland-3")
        );
    }

    #[test]
    fn the_client_env_points_at_the_bound_socket() {
        // The invariant that lets a confined client connect: XDG_RUNTIME_DIR plus
        // WAYLAND_DISPLAY resolve to exactly where the socket is bound.
        let env = client_env();
        let get = |k: &str| {
            env.iter()
                .find(|(n, _)| n == k)
                .map(|(_, v)| v.clone())
                .unwrap_or_else(|| panic!("{k} not set in client env"))
        };
        let resolved = Path::new(&get("XDG_RUNTIME_DIR")).join(get("WAYLAND_DISPLAY"));
        assert_eq!(resolved, cell_wayland_socket());
    }

    #[test]
    fn the_client_cell_binds_the_socket_and_the_host_system_only() {
        let host = Path::new("/run/user/1000/wayland-7");
        let binds = client_cell(host);
        let binds = binds.binds();
        // The compositor's socket is bound writable where the client looks.
        assert!(
            binds
                .iter()
                .any(|b| b.src == host && b.dst == cell_wayland_socket() && b.writable),
            "wayland socket not bound where the env points"
        );
        // bind_host_system supplied the libraries (read-only).
        assert!(
            binds
                .iter()
                .any(|b| b.dst == Path::new("/usr") && !b.writable),
            "host /usr not bound read-only"
        );
        // No home or other host data crept in.
        assert!(
            !binds.iter().any(|b| b.dst.starts_with("/home")),
            "a home directory was bound into the client cell"
        );
    }

    #[test]
    fn a_confined_client_can_reach_the_bound_socket() {
        // The hard part, proven headlessly: a client in the empty-net cell can
        // connect to the compositor's Wayland socket through the bind. Mapping a
        // window still needs a screen; reaching the display does not. Skipped
        // where unprivileged user namespaces are unavailable.
        if !cells::available() {
            eprintln!("skipping: unprivileged user namespaces unavailable");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let host_sock = dir.path().join("wayland-host");
        // Stand in for the compositor: a real listening socket at the host path.
        let _listener = UnixListener::bind(&host_sock).unwrap();

        let target = cell_wayland_socket();
        let status = client_cell(&host_sock)
            .run(cells::Payload::call(move || {
                // Connect to the in-cell socket path with raw libc (fork-safe, no
                // allocation). A pathname Unix socket crosses the empty net
                // namespace, so this must succeed even with no network.
                let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
                if fd < 0 {
                    return 1;
                }
                let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
                addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
                let bytes = target.as_os_str().as_bytes();
                if bytes.len() + 1 > addr.sun_path.len() {
                    return 2;
                }
                for (i, b) in bytes.iter().enumerate() {
                    addr.sun_path[i] = *b as libc::c_char;
                }
                let len = std::mem::size_of::<libc::sa_family_t>() + bytes.len() + 1;
                let r = unsafe {
                    libc::connect(
                        fd,
                        &addr as *const _ as *const libc::sockaddr,
                        len as libc::socklen_t,
                    )
                };
                unsafe { libc::close(fd) };
                if r == 0 {
                    0
                } else {
                    3
                }
            }))
            .expect("run client cell");
        assert!(
            status.success(),
            "confined client could not reach the socket (code {:?})",
            status.code
        );
    }
}
