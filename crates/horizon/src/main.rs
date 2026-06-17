use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use lifestream::{Lifestream, Object, ObjectId};

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

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Lifestream { op } => lifestream_cmd(op),
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
