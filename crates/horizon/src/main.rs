use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use lifestream::{Lifestream, Object, ObjectId};
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
    let salt = std::fs::read(store.join("keysalt")).context("read keysalt (is this a store?)")?;
    let key = derive(&passphrase()?, &salt);
    Ok(Lifestream::open(store, &key)?)
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
