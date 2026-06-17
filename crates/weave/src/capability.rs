use std::fmt;
use std::ops::BitOr;
use std::path::PathBuf;

use rand::RngCore;

// A principal is whoever is acting: an app, a service, or Aura. It has no
// authority by being "you"; it can only use capabilities handed to it.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct PrincipalId(pub String);

impl From<&str> for PrincipalId {
    fn from(s: &str) -> PrincipalId {
        PrincipalId(s.to_string())
    }
}

impl fmt::Display for PrincipalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// The rights carried by a capability. A small fixed set is enough to map every
// resource: read/capture, write/send, and invoke/connect.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Rights(u32);

impl Rights {
    pub const NONE: Rights = Rights(0);
    pub const READ: Rights = Rights(1);
    pub const WRITE: Rights = Rights(2);
    pub const EXEC: Rights = Rights(4);

    pub fn bits(self) -> u32 {
        self.0
    }
    pub fn from_bits(b: u32) -> Rights {
        Rights(b & 0b111)
    }
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }
    // True when self carries at least the requested rights.
    pub fn contains(self, other: Rights) -> bool {
        self.0 & other.0 == other.0
    }
    pub fn intersect(self, other: Rights) -> Rights {
        Rights(self.0 & other.0)
    }

    pub fn parse(s: &str) -> Option<Rights> {
        let mut r = Rights::NONE;
        for c in s.chars() {
            r = r | match c {
                'r' => Rights::READ,
                'w' => Rights::WRITE,
                'x' => Rights::EXEC,
                '-' => Rights::NONE,
                _ => return None,
            };
        }
        Some(r)
    }
}

impl BitOr for Rights {
    type Output = Rights;
    fn bitor(self, rhs: Rights) -> Rights {
        Rights(self.0 | rhs.0)
    }
}

impl fmt::Display for Rights {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return f.write_str("-");
        }
        if self.contains(Rights::READ) {
            f.write_str("r")?;
        }
        if self.contains(Rights::WRITE) {
            f.write_str("w")?;
        }
        if self.contains(Rights::EXEC) {
            f.write_str("x")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Rights {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Rights({self})")
    }
}

// What a capability names. Each variant carries its own scope: a file grant
// covers a path and its descendants, a net grant a single host:port, and so on.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Resource {
    File { path: PathBuf },
    Net { host: String, port: u16 },
    Device { name: String },
    Service { name: String, action: String },
}

impl Resource {
    pub fn file(path: impl Into<PathBuf>) -> Resource {
        Resource::File { path: path.into() }
    }
    pub fn net(host: impl Into<String>, port: u16) -> Resource {
        Resource::Net {
            host: host.into(),
            port,
        }
    }
    pub fn device(name: impl Into<String>) -> Resource {
        Resource::Device { name: name.into() }
    }
    pub fn service(name: impl Into<String>, action: impl Into<String>) -> Resource {
        Resource::Service {
            name: name.into(),
            action: action.into(),
        }
    }

    // Does a grant for self authorize access to `req`? A directory grant covers
    // everything beneath it; everything else must match exactly. This is what
    // keeps a "pick one file" portal from leaking the whole folder.
    pub fn covers(&self, req: &Resource) -> bool {
        match (self, req) {
            (Resource::File { path: a }, Resource::File { path: b }) => b == a || b.starts_with(a),
            (Resource::Net { host: h1, port: p1 }, Resource::Net { host: h2, port: p2 }) => {
                h1 == h2 && p1 == p2
            }
            (Resource::Device { name: a }, Resource::Device { name: b }) => a == b,
            (
                Resource::Service {
                    name: n1,
                    action: a1,
                },
                Resource::Service {
                    name: n2,
                    action: a2,
                },
            ) => n1 == n2 && a1 == a2,
            _ => false,
        }
    }

    // Parse the CLI/log forms: file:/p, net:host:port, dev:name, svc:name/action.
    pub fn parse(s: &str) -> Option<Resource> {
        if let Some(p) = s.strip_prefix("file:") {
            Some(Resource::file(p))
        } else if let Some(rest) = s.strip_prefix("net:") {
            let (host, port) = rest.rsplit_once(':')?;
            Some(Resource::net(host, port.parse().ok()?))
        } else if let Some(name) = s.strip_prefix("dev:") {
            Some(Resource::device(name))
        } else if let Some(rest) = s.strip_prefix("svc:") {
            let (name, action) = rest.split_once('/')?;
            Some(Resource::service(name, action))
        } else {
            None
        }
    }
}

impl fmt::Display for Resource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Resource::File { path } => write!(f, "file:{}", path.display()),
            Resource::Net { host, port } => write!(f, "net:{host}:{port}"),
            Resource::Device { name } => write!(f, "dev:{name}"),
            Resource::Service { name, action } => write!(f, "svc:{name}/{action}"),
        }
    }
}

// A grant's stable identity. Recorded in the audit log so a grant survives a
// restart even though the live handle that exercises it does not.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct GrantId([u8; 16]);

impl GrantId {
    pub fn random() -> GrantId {
        let mut a = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut a);
        GrantId(a)
    }
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
    pub fn from_hex(s: &str) -> Option<GrantId> {
        let v = hex::decode(s).ok()?;
        if v.len() != 16 {
            return None;
        }
        let mut a = [0u8; 16];
        a.copy_from_slice(&v);
        Some(GrantId(a))
    }
    pub(crate) fn bytes(&self) -> &[u8; 16] {
        &self.0
    }
    pub(crate) fn from_bytes(a: [u8; 16]) -> GrantId {
        GrantId(a)
    }
}

impl fmt::Display for GrantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for GrantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GrantId({})", &self.to_hex()[..8])
    }
}

// The limits that make a grant scoped in time and use, not just in resource.
#[derive(Clone, Copy, Default, Debug)]
pub struct Limits {
    pub expires_unix: Option<u64>,
    pub max_uses: Option<u32>,
}

impl Limits {
    pub fn none() -> Limits {
        Limits::default()
    }
    pub fn until(expires_unix: u64) -> Limits {
        Limits {
            expires_unix: Some(expires_unix),
            max_uses: None,
        }
    }
    pub fn uses(max_uses: u32) -> Limits {
        Limits {
            expires_unix: None,
            max_uses: Some(max_uses),
        }
    }
    pub fn with_expiry(mut self, expires_unix: u64) -> Limits {
        self.expires_unix = Some(expires_unix);
        self
    }
    pub fn with_uses(mut self, max_uses: u32) -> Limits {
        self.max_uses = Some(max_uses);
        self
    }
}

// The persisted policy decision: principal P may exercise `rights` on
// `resource`, within `limits`. Rebuilt from the audit log on open.
#[derive(Clone, Debug)]
pub struct Grant {
    pub id: GrantId,
    pub principal: PrincipalId,
    pub resource: Resource,
    pub rights: Rights,
    pub granted_unix: u64,
    pub expires_unix: Option<u64>,
    pub max_uses: Option<u32>,
}

// The live, unforgeable handle a holder presents to exercise a grant. The
// secret is minted by the broker and never written to the log, so it cannot be
// guessed from the record and does not outlive the session. Fields are
// crate-private: only the broker can build or inspect one.
#[derive(Clone)]
pub struct Capability {
    pub(crate) grant: GrantId,
    pub(crate) secret: [u8; 32],
}

impl Capability {
    pub fn grant_id(&self) -> GrantId {
        self.grant
    }
}

impl fmt::Debug for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // never print the secret
        write!(f, "Capability(grant={:?})", self.grant)
    }
}

// Proof that an access was authorized and audited. In the running OS this would
// carry the brokered fd or socket; here it carries what was granted.
#[derive(Clone, Debug)]
pub struct Lease {
    pub grant: GrantId,
    pub resource: Resource,
    pub rights: Rights,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Status {
    Active,
    Revoked,
    Expired,
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Status::Active => "active",
            Status::Revoked => "revoked",
            Status::Expired => "expired",
        })
    }
}

// A read-only view of a grant for listing in the CLI or Glass.
#[derive(Clone, Debug)]
pub struct GrantInfo {
    pub id: GrantId,
    pub principal: PrincipalId,
    pub resource: Resource,
    pub rights: Rights,
    pub granted_unix: u64,
    pub expires_unix: Option<u64>,
    pub max_uses: Option<u32>,
    pub uses: u32,
    pub status: Status,
}
