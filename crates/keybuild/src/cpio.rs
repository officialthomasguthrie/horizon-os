//! The newc cpio archive (the format the Linux kernel unpacks an initramfs from), owned
//! in pure Rust.
//!
//! The initramfs is the tiny root filesystem the kernel mounts before any real disk: it
//! holds `/init` (Horizon's `horizon-init`), the few tools that get a machine to its real
//! root, and the boot-path kernel modules. The kernel embeds or loads it as a cpio archive
//! in the "new ASCII" (`newc`) format, optionally gzip-compressed, and unpacks it into a
//! rootfs at boot. See `docs/03-PORTABILITY-AND-BOOT.md`.
//!
//! This module is the producer: it writes that archive. It owns the format rather than
//! shelling out for the same reasons [`mod@super::verity`], [`mod@super::gpt`], and
//! [`mod@super::fat`] own theirs, and the inverse of [`mod@super::luks`]: there is no
//! `cpio` (and no `busybox`) in the build container, the archive is a deterministic
//! function of its contents so an initramfs is reproducible (fixed uid/gid 0 and mtime 0,
//! inodes assigned by a deterministic walk), and the format is fiddly but not
//! security-critical, so the whole thing is pure logic that builds and tests on any host.
//! `luks` shelled out only because LUKS2's format is complex and security-critical and its
//! kernel consumer was present to test against; cpio is neither. There is no external cpio
//! tool to cross-check against either, so unlike the FAT volume (which the kernel mounts as
//! `vfat`) or the verity tree (which `veritysetup` reproduces), the cpio is proven by a
//! reader half written here ([`read`]) round-tripping the writer ([`write`]); the kernel
//! actually unpacking it is eye-verified at the QEMU boot, exactly the dm-verity model when
//! the kernel consumer is absent.
//!
//! The format implemented is `newc` (magic `070701`, not the `070702` CRC variant): a
//! sequence of records, each a 110-byte header of 8-digit hex ASCII fields, then the NUL-
//! terminated pathname padded to a 4-byte boundary, then the file data padded to a 4-byte
//! boundary, ending with a `TRAILER!!!` record. Directories carry no data; symlinks carry
//! their target as the data; device nodes carry the major/minor in the rdev fields and no
//! data. Each record gets a unique inode and `nlink` 1 (2 for directories), so the kernel
//! never coalesces two records into a hardlink. Scope is what an initramfs needs:
//! directories, regular files, symlinks, and character/block device nodes (for
//! `/dev/console` so the init's console output is visible before it mounts devtmpfs).

use std::collections::BTreeMap;
use std::path::Path;

use crate::error::{Error, Result};

/// The newc magic at the head of every record.
const MAGIC: &[u8; 6] = b"070701";

/// The name of the terminating record that ends a cpio archive.
const TRAILER: &str = "TRAILER!!!";

/// The fixed header size: the 6-byte magic plus thirteen 8-byte hex fields.
const HEADER_LEN: usize = 6 + 13 * 8;

// The Unix mode type bits a record's mode carries, picking the entry kind.
const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;
const S_IFLNK: u32 = 0o120000;
const S_IFCHR: u32 = 0o020000;
const S_IFBLK: u32 = 0o060000;

/// The starting inode the writer hands out, incrementing per record. The exact value is
/// arbitrary (it only needs to be unique within the archive so no two records hardlink);
/// 721 matches the kernel's own `gen_init_cpio`.
const INO_BASE: u32 = 721;

/// Whether a device node is character- or block-special.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    Char,
    Block,
}

impl NodeKind {
    fn ifmt(self) -> u32 {
        match self {
            NodeKind::Char => S_IFCHR,
            NodeKind::Block => S_IFBLK,
        }
    }
}

/// One entry read back out of an archive, with its full path. The reader ([`read`]) returns
/// these in archive order; the round-trip tests assert a [`Tree`] survives [`write`] then
/// `read` unchanged, the pure cross-check that stands in for an external cpio tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    Dir {
        path: String,
        mode: u32,
    },
    File {
        path: String,
        mode: u32,
        data: Vec<u8>,
    },
    Symlink {
        path: String,
        target: String,
    },
    Device {
        path: String,
        mode: u32,
        kind: NodeKind,
        major: u32,
        minor: u32,
    },
}

// A node in the in-memory tree the writer walks.
enum Node {
    Dir(DirNode),
    File {
        mode: u32,
        data: Vec<u8>,
    },
    Symlink(String),
    Device {
        mode: u32,
        ifmt: u32,
        major: u32,
        minor: u32,
    },
}

#[derive(Default)]
struct DirNode {
    mode: u32,
    entries: BTreeMap<String, Node>,
}

/// A directory tree to write into a cpio archive. Build one with [`Tree::new`] and
/// [`Tree::insert_file`]/[`Tree::mkdir`]/[`Tree::symlink`]/[`Tree::device`], then hand it to
/// [`write`]. Entries are kept in a sorted map so the walk order, the inode assignment, and
/// thus the archive bytes are deterministic. Paths are slash-separated and relative (no
/// leading slash); the kernel unpacks them under the rootfs root, so `init` lands at `/init`.
pub struct Tree {
    root: DirNode,
}

impl Default for Tree {
    fn default() -> Tree {
        Tree::new()
    }
}

/// The default permission bits for a directory created implicitly along an inserted path.
const DEFAULT_DIR_MODE: u32 = 0o755;

impl Tree {
    pub fn new() -> Tree {
        Tree {
            root: DirNode {
                mode: DEFAULT_DIR_MODE,
                entries: BTreeMap::new(),
            },
        }
    }

    /// Create a directory at `path` (and any parents), each with `DEFAULT_DIR_MODE`, so an
    /// empty directory exists even before anything is placed in it. A component that already
    /// exists as a directory is reused; one that exists as a file is an error.
    pub fn mkdir(&mut self, path: &str) -> Result<()> {
        self.dir_at(&components(path)?).map(|_| ())
    }

    /// Insert a regular file at `path` with permission bits `mode` (the type bits are added
    /// by the writer), creating intermediate directories. Errors on an empty path or a path
    /// that runs through an existing file.
    pub fn insert_file(&mut self, path: &str, data: Vec<u8>, mode: u32) -> Result<()> {
        self.put(
            path,
            Node::File {
                mode: mode & 0o7777,
                data,
            },
        )
    }

    /// Insert a symlink at `path` pointing at `target`, creating intermediate directories.
    pub fn symlink(&mut self, path: &str, target: &str) -> Result<()> {
        self.put(path, Node::Symlink(target.to_string()))
    }

    /// Insert a device node at `path` (a character or block special file with the given
    /// major/minor), creating intermediate directories. No real `mknod` is needed: the node
    /// is just a record in the archive, and the kernel creates it on unpack, which is how an
    /// unprivileged build can ship `/dev/console`.
    pub fn device(
        &mut self,
        path: &str,
        mode: u32,
        kind: NodeKind,
        major: u32,
        minor: u32,
    ) -> Result<()> {
        self.put(
            path,
            Node::Device {
                mode: mode & 0o7777,
                ifmt: kind.ifmt(),
                major,
                minor,
            },
        )
    }

    // Place a leaf node at `path`, creating the parent directories.
    fn put(&mut self, path: &str, node: Node) -> Result<()> {
        let parts = components(path)?;
        let (name, dirs) = parts.split_last().expect("components is non-empty");
        let dir = self.dir_at(dirs)?;
        dir.entries.insert(name.clone(), node);
        Ok(())
    }

    // Walk to (creating along the way) the directory named by `dirs`, returning it.
    fn dir_at(&mut self, dirs: &[String]) -> Result<&mut DirNode> {
        let mut cur = &mut self.root;
        for d in dirs {
            let node = cur.entries.entry(d.clone()).or_insert_with(|| {
                Node::Dir(DirNode {
                    mode: DEFAULT_DIR_MODE,
                    entries: BTreeMap::new(),
                })
            });
            match node {
                Node::Dir(sub) => cur = sub,
                _ => return Err(Error::Cpio("path runs through a non-directory")),
            }
        }
        Ok(cur)
    }
}

// Split a slash-separated path into its non-empty components, rejecting an empty path and
// any `.`/`..` component (an initramfs path is a plain relative name).
fn components(path: &str) -> Result<Vec<String>> {
    let parts: Vec<String> = path
        .split('/')
        .filter(|p| !p.is_empty())
        .map(|p| p.to_string())
        .collect();
    if parts.is_empty() || parts.iter().any(|p| p == "." || p == "..") {
        return Err(Error::Cpio("empty or non-relative path"));
    }
    Ok(parts)
}

/// Write `tree` as a newc cpio archive. Pure: the same tree always yields the same bytes
/// (sorted walk, fixed uid/gid/mtime, deterministically assigned inodes), so an initramfs
/// is reproducible and the result is asserted with no kernel and no cpio tool.
pub fn write(tree: &Tree) -> Vec<u8> {
    let mut out = Vec::new();
    let mut ino = INO_BASE;
    write_dir(&mut out, &mut ino, "", &tree.root);
    // The trailer ends the archive: a record named TRAILER!!! with no data.
    write_record(&mut out, &mut ino, TRAILER, 0, 1, 0, 0, &[]);
    out
}

// Emit a directory's own record (skipped for the unnamed root, which the kernel's rootfs
// already provides) then recurse, so every directory precedes its contents, which is what
// the kernel's unpacker needs to place a file in a directory it has already created.
fn write_dir(out: &mut Vec<u8>, ino: &mut u32, path: &str, dir: &DirNode) {
    if !path.is_empty() {
        write_record(out, ino, path, S_IFDIR | dir.mode, 2, 0, 0, &[]);
    }
    for (name, node) in &dir.entries {
        let child = if path.is_empty() {
            name.clone()
        } else {
            format!("{path}/{name}")
        };
        match node {
            Node::Dir(d) => write_dir(out, ino, &child, d),
            Node::File { mode, data } => {
                write_record(out, ino, &child, S_IFREG | mode, 1, 0, 0, data)
            }
            Node::Symlink(target) => write_record(
                out,
                ino,
                &child,
                S_IFLNK | 0o777,
                1,
                0,
                0,
                target.as_bytes(),
            ),
            Node::Device {
                mode,
                ifmt,
                major,
                minor,
            } => write_record(out, ino, &child, ifmt | mode, 1, *major, *minor, &[]),
        }
    }
}

// Write one newc record: the 110-byte header, the NUL-terminated name padded to 4 bytes,
// then the data padded to 4 bytes. Because every record before this one is already 4-byte
// aligned, padding the running length to a multiple of 4 is the same as padding the name
// and the data individually, which is what the format requires.
#[allow(clippy::too_many_arguments)]
fn write_record(
    out: &mut Vec<u8>,
    ino: &mut u32,
    name: &str,
    mode: u32,
    nlink: u32,
    rdevmajor: u32,
    rdevminor: u32,
    data: &[u8],
) {
    let namesize = name.len() as u32 + 1; // includes the trailing NUL
    out.extend_from_slice(MAGIC);
    push_hex8(out, *ino);
    push_hex8(out, mode);
    push_hex8(out, 0); // uid
    push_hex8(out, 0); // gid
    push_hex8(out, nlink);
    push_hex8(out, 0); // mtime, fixed for reproducibility
    push_hex8(out, data.len() as u32); // filesize
    push_hex8(out, 0); // devmajor
    push_hex8(out, 0); // devminor
    push_hex8(out, rdevmajor);
    push_hex8(out, rdevminor);
    push_hex8(out, namesize);
    push_hex8(out, 0); // check, always 0 for newc (only the 070702 CRC variant uses it)
    out.extend_from_slice(name.as_bytes());
    out.push(0);
    pad4(out);
    out.extend_from_slice(data);
    pad4(out);
    *ino += 1;
}

// Append `v` as eight uppercase hex digits, the newc field encoding.
fn push_hex8(out: &mut Vec<u8>, v: u32) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for shift in (0..8).rev() {
        out.push(HEX[((v >> (shift * 4)) & 0xf) as usize]);
    }
}

// Zero-pad the output up to the next 4-byte boundary.
fn pad4(out: &mut Vec<u8>) {
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}

/// Parse a newc archive back into its entries, in archive order, stopping at the
/// `TRAILER!!!` record. The reader half of owning the format: it is the cross-check the
/// round-trip tests run against the writer (there is no external cpio tool to compare with),
/// and the gated container test uses it to inspect a freshly built, gunzipped initramfs.
/// Errors on a bad magic, a non-hex field, or a header/name/data that runs off the end.
pub fn read(bytes: &[u8]) -> Result<Vec<Entry>> {
    let mut entries = Vec::new();
    let mut pos = 0usize;
    loop {
        if pos + HEADER_LEN > bytes.len() {
            return Err(Error::Cpio("truncated header"));
        }
        if &bytes[pos..pos + 6] != MAGIC {
            return Err(Error::Cpio("bad magic"));
        }
        let field = |i: usize| parse_hex8(&bytes[pos + 6 + i * 8..pos + 6 + i * 8 + 8]);
        let mode = field(1)?;
        let filesize = field(6)? as usize;
        let rdevmajor = field(9)?;
        let rdevminor = field(10)?;
        let namesize = field(11)? as usize;

        let name_start = pos + HEADER_LEN;
        let name_end = name_start
            .checked_add(namesize)
            .filter(|&e| e <= bytes.len() && namesize >= 1)
            .ok_or(Error::Cpio("truncated name"))?;
        // The name carries a trailing NUL the path does not include.
        let name = std::str::from_utf8(&bytes[name_start..name_end - 1])
            .map_err(|_| Error::Cpio("non-utf8 name"))?
            .to_string();

        let data_start = align4(name_end);
        let data_end = data_start
            .checked_add(filesize)
            .filter(|&e| e <= bytes.len())
            .ok_or(Error::Cpio("truncated data"))?;
        let data = &bytes[data_start..data_end];

        if name == TRAILER {
            break;
        }

        entries.push(match mode & S_IFMT {
            S_IFDIR => Entry::Dir {
                path: name,
                mode: mode & 0o7777,
            },
            S_IFLNK => Entry::Symlink {
                path: name,
                target: std::str::from_utf8(data)
                    .map_err(|_| Error::Cpio("non-utf8 symlink target"))?
                    .to_string(),
            },
            S_IFCHR | S_IFBLK => Entry::Device {
                path: name,
                mode: mode & 0o7777,
                kind: if mode & S_IFMT == S_IFCHR {
                    NodeKind::Char
                } else {
                    NodeKind::Block
                },
                major: rdevmajor,
                minor: rdevminor,
            },
            _ => Entry::File {
                path: name,
                mode: mode & 0o7777,
                data: data.to_vec(),
            },
        });

        pos = align4(data_end);
    }
    Ok(entries)
}

// Parse an 8-byte ASCII hex field (newc writes uppercase; the kernel and this reader accept
// either case).
fn parse_hex8(field: &[u8]) -> Result<u32> {
    let s = std::str::from_utf8(field).map_err(|_| Error::Cpio("non-ascii field"))?;
    u32::from_str_radix(s, 16).map_err(|_| Error::Cpio("non-hex field"))
}

// Round `n` up to the next multiple of 4.
fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// Import a real directory tree into a [`Tree`], reading each entry's kind and permission
/// bits so [`write`] reproduces them: a regular file with its contents and mode, a directory
/// (recursed into), or a symlink with its target. This is how [`super::build_initramfs`]
/// turns a populated staging directory (built with the same binary/closure machinery as the
/// base) into the archive, after which it adds the device nodes a staging directory cannot
/// hold. Unix only (it reads Unix mode bits and does not follow symlinks); the workspace's
/// hosts are Unix, and the build path that calls it is the Linux container.
#[cfg(unix)]
pub fn read_dir_tree(root: &Path) -> Result<Tree> {
    let mut tree = Tree::new();
    import_dir(root, "", &mut tree)?;
    Ok(tree)
}

#[cfg(not(unix))]
pub fn read_dir_tree(_root: &Path) -> Result<Tree> {
    Err(Error::Cpio("read_dir_tree needs a Unix host"))
}

#[cfg(unix)]
fn import_dir(disk: &Path, rel: &str, tree: &mut Tree) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    // A sorted read so the import, and thus the archive, is deterministic.
    let mut names: Vec<std::ffi::OsString> = std::fs::read_dir(disk)?
        .map(|e| e.map(|e| e.file_name()))
        .collect::<std::io::Result<_>>()?;
    names.sort();

    for name in names {
        let name = name.to_string_lossy().into_owned();
        let child_disk = disk.join(&name);
        let child_rel = if rel.is_empty() {
            name.clone()
        } else {
            format!("{rel}/{name}")
        };
        let meta = std::fs::symlink_metadata(&child_disk)?;
        let ty = meta.file_type();
        if ty.is_symlink() {
            let target = std::fs::read_link(&child_disk)?;
            tree.symlink(&child_rel, &target.to_string_lossy())?;
        } else if ty.is_dir() {
            tree.mkdir(&child_rel)?;
            import_dir(&child_disk, &child_rel, tree)?;
        } else {
            // A regular file (a device node in a staging tree is not expected; the build adds
            // those to the tree directly). Carry its permission bits so an executable stays
            // executable, exactly as the squashfs base preserves them.
            let data = std::fs::read(&child_disk)?;
            tree.insert_file(&child_rel, data, meta.permissions().mode())?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Round-trip a tree through write then read: the pure cross-check standing in for an
    // external cpio tool. The reader walks the same bytes the kernel would.
    fn roundtrip(tree: &Tree) -> Vec<Entry> {
        read(&write(tree)).unwrap()
    }

    fn find<'a>(entries: &'a [Entry], path: &str) -> Option<&'a Entry> {
        entries.iter().find(|e| match e {
            Entry::Dir { path: p, .. }
            | Entry::File { path: p, .. }
            | Entry::Symlink { path: p, .. }
            | Entry::Device { path: p, .. } => p == path,
        })
    }

    #[test]
    fn files_dirs_symlinks_and_devices_round_trip() {
        let mut t = Tree::new();
        t.mkdir("dev").unwrap();
        t.insert_file("init", b"#!/bin/init\n".to_vec(), 0o755)
            .unwrap();
        t.insert_file("usr/sbin/cryptsetup", b"ELF...".to_vec(), 0o755)
            .unwrap();
        t.insert_file("etc/os-release", b"ID=horizon\n".to_vec(), 0o644)
            .unwrap();
        t.symlink("sbin", "usr/sbin").unwrap();
        t.device("dev/console", 0o600, NodeKind::Char, 5, 1)
            .unwrap();

        let entries = roundtrip(&t);

        // The /init program, executable, with its bytes intact.
        match find(&entries, "init").unwrap() {
            Entry::File { mode, data, .. } => {
                assert_eq!(*mode, 0o755);
                assert_eq!(data, b"#!/bin/init\n");
            }
            other => panic!("init should be a file, got {other:?}"),
        }
        // An intermediate directory was created for the nested binary.
        assert!(matches!(
            find(&entries, "usr/sbin").unwrap(),
            Entry::Dir { .. }
        ));
        assert!(matches!(
            find(&entries, "usr/sbin/cryptsetup").unwrap(),
            Entry::File { mode: 0o755, .. }
        ));
        // The symlink keeps its target.
        match find(&entries, "sbin").unwrap() {
            Entry::Symlink { target, .. } => assert_eq!(target, "usr/sbin"),
            other => panic!("sbin should be a symlink, got {other:?}"),
        }
        // The console device keeps its major/minor, so the init has output at boot.
        match find(&entries, "dev/console").unwrap() {
            Entry::Device {
                mode,
                kind,
                major,
                minor,
                ..
            } => {
                assert_eq!(
                    (*mode, *kind, *major, *minor),
                    (0o600, NodeKind::Char, 5, 1)
                );
            }
            other => panic!("console should be a device, got {other:?}"),
        }
    }

    #[test]
    fn a_directory_precedes_its_contents() {
        // The kernel places a file only into a directory it has already made, so every
        // directory record must come before any record under it.
        let mut t = Tree::new();
        t.insert_file("usr/bin/horizon", b"x".to_vec(), 0o755)
            .unwrap();
        let entries = roundtrip(&t);
        let pos = |p: &str| {
            entries
                .iter()
                .position(|e| matches!(e, Entry::Dir{path,..} | Entry::File{path,..} if path == p))
                .unwrap()
        };
        assert!(pos("usr") < pos("usr/bin"));
        assert!(pos("usr/bin") < pos("usr/bin/horizon"));
    }

    #[test]
    fn header_fields_are_the_newc_layout() {
        // One file, so the first record is at offset 0: assert the magic, the hex mode, and
        // the 4-byte alignment the format requires, the bytes the kernel parses.
        let mut t = Tree::new();
        t.insert_file("a", b"hello".to_vec(), 0o644).unwrap();
        let bytes = write(&t);

        assert_eq!(&bytes[0..6], MAGIC);
        // mode field (index 1): S_IFREG | 0644 = 0o100644 = 0x000081A4, uppercase hex.
        assert_eq!(&bytes[6 + 8..6 + 16], b"000081A4");
        // namesize field (index 11): "a" plus NUL is 2 = 0x00000002.
        assert_eq!(&bytes[6 + 11 * 8..6 + 12 * 8], b"00000002");
        // The whole archive is 4-byte aligned.
        assert_eq!(bytes.len() % 4, 0);
        // It ends with a trailer record, so a reader (and the kernel) knows where to stop.
        let entries = read(&bytes).unwrap();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn inodes_are_unique_so_nothing_hardlinks() {
        // Unique inodes plus nlink 1 keep the kernel from coalescing two files into a
        // hardlink, which it does only for repeated (ino, nlink>=2) records.
        let mut t = Tree::new();
        t.insert_file("a", b"one".to_vec(), 0o644).unwrap();
        t.insert_file("b", b"two".to_vec(), 0o644).unwrap();
        let bytes = write(&t);
        let mut inos = Vec::new();
        let mut pos = 0;
        while &bytes[pos..pos + 6] == MAGIC {
            inos.push(parse_hex8(&bytes[pos + 6..pos + 14]).unwrap());
            let filesize = parse_hex8(&bytes[pos + 6 + 6 * 8..pos + 6 + 7 * 8]).unwrap() as usize;
            let namesize = parse_hex8(&bytes[pos + 6 + 11 * 8..pos + 6 + 12 * 8]).unwrap() as usize;
            let next = align4(align4(pos + HEADER_LEN + namesize) + filesize);
            if std::str::from_utf8(&bytes[pos + HEADER_LEN..pos + HEADER_LEN + namesize - 1])
                == Ok(TRAILER)
            {
                break;
            }
            pos = next;
        }
        let mut sorted = inos.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            inos.len(),
            "every record has a distinct inode"
        );
    }

    #[test]
    fn build_is_deterministic() {
        let build = || {
            let mut t = Tree::new();
            t.insert_file("init", b"i".to_vec(), 0o755).unwrap();
            t.insert_file("usr/sbin/cryptsetup", b"c".to_vec(), 0o755)
                .unwrap();
            t.device("dev/console", 0o600, NodeKind::Char, 5, 1)
                .unwrap();
            write(&t)
        };
        assert_eq!(build(), build());
    }

    #[test]
    fn empty_and_non_relative_paths_are_rejected() {
        let mut t = Tree::new();
        assert!(t.insert_file("", b"x".to_vec(), 0o644).is_err());
        assert!(t.insert_file("../escape", b"x".to_vec(), 0o644).is_err());
        assert!(t.mkdir("a/./b").is_err());
    }

    #[test]
    fn insert_through_a_file_is_an_error() {
        let mut t = Tree::new();
        t.insert_file("a", b"x".to_vec(), 0o644).unwrap();
        // "a" is a file, so making "a/b" underneath it must fail rather than clobber it.
        assert!(t.insert_file("a/b", b"y".to_vec(), 0o644).is_err());
    }

    #[test]
    fn read_rejects_a_corrupt_archive() {
        let mut t = Tree::new();
        t.insert_file("a", b"x".to_vec(), 0o644).unwrap();
        let mut bytes = write(&t);
        bytes[0] = b'9'; // break the magic of the first record
        assert!(read(&bytes).is_err());
        assert!(read(b"too short").is_err());
    }

    // read_dir_tree imports a real directory; Unix only, runs on darwin and in the container.
    #[cfg(unix)]
    #[test]
    fn read_dir_tree_imports_a_staging_directory() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("usr/sbin")).unwrap();
        std::fs::write(root.join("init"), b"init-bytes").unwrap();
        std::fs::set_permissions(root.join("init"), std::fs::Permissions::from_mode(0o755))
            .unwrap();
        std::fs::write(root.join("usr/sbin/cryptsetup"), b"cs").unwrap();
        std::os::unix::fs::symlink("usr/sbin", root.join("sbin")).unwrap();

        let mut tree = read_dir_tree(root).unwrap();
        tree.device("dev/console", 0o600, NodeKind::Char, 5, 1)
            .unwrap();
        let entries = read(&write(&tree)).unwrap();

        match find(&entries, "init").unwrap() {
            Entry::File { mode, data, .. } => {
                assert_eq!(*mode & 0o777, 0o755, "the executable bit is preserved");
                assert_eq!(data, b"init-bytes");
            }
            other => panic!("init should be a file, got {other:?}"),
        }
        assert!(matches!(
            find(&entries, "usr/sbin/cryptsetup").unwrap(),
            Entry::File { .. }
        ));
        assert!(matches!(
            find(&entries, "sbin").unwrap(),
            Entry::Symlink { .. }
        ));
        assert!(matches!(
            find(&entries, "dev/console").unwrap(),
            Entry::Device { .. }
        ));
    }
}
