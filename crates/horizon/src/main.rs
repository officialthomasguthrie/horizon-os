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

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Lifestream { op } => lifestream_cmd(op),
        Cmd::Weave { op } => weave_cmd(op),
        Cmd::Sync { from, to, both } => sync_cmd(from, to, both),
        Cmd::Reconstitute { op } => recon_cmd(op),
        Cmd::Constellation { op } => constellation_cmd(op),
        Cmd::Cell { op } => cell_cmd(op),
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
    Ok(Broker::open(open(store)?, weave::Policy::DenyAll)?)
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

// Argon2id passphrase to master key. The identity crate will extend this with
// FIDO2 and Shamir recovery; this is the standalone path for the tools.
fn derive(pass: &str, salt: &[u8]) -> [u8; 32] {
    use argon2::Argon2;
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(pass.as_bytes(), salt, &mut key)
        .expect("argon2 derive");
    key
}
