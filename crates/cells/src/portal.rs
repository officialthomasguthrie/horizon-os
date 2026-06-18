// The broker fd-passing seam. A confined principal's only ambient channel is a
// Unix socket to the broker. It asks for a resource; the broker checks the
// request against the capability it holds, turns the resulting Lease into a real
// open file or connected socket, and passes that fd back over SCM_RIGHTS. The
// principal ends up holding a working fd it could never have opened itself,
// which is what makes weave's Lease real and keeps "no ambient authority"
// honest: the cell has no path to the file and no route to the host, only what
// the broker chose to hand it.

use std::io::{IoSlice, IoSliceMut};
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use nix::sys::socket::{recvmsg, sendmsg, ControlMessage, ControlMessageOwned, MsgFlags};
use weave::{Lease, Resource, Rights};

use crate::error::{Error, Result};

// Turn an authorized Lease into a real OS object. This runs in the broker, which
// holds the authority the principal does not: an open file for a File grant
// (flags matching the rights), a connected socket for a Net grant.
pub fn materialize(lease: &Lease) -> Result<OwnedFd> {
    match &lease.resource {
        Resource::File { path } => {
            let write = lease.rights.contains(Rights::WRITE);
            let read = lease.rights.contains(Rights::READ) || !write;
            let file = std::fs::OpenOptions::new()
                .read(read)
                .write(write)
                .open(path)?;
            Ok(OwnedFd::from(file))
        }
        Resource::Net { host, port } => {
            let stream = std::net::TcpStream::connect((host.as_str(), *port))?;
            Ok(OwnedFd::from(stream))
        }
        other => Err(Error::Confine(format!("cannot materialize {other}"))),
    }
}

// Principal side, inside the cell: ask the broker over `sock` for an fd granting
// `rights` on `resource`. Returns the fd the broker passed, or its refusal.
pub fn request(sock: RawFd, resource: &Resource, rights: Rights) -> Result<OwnedFd> {
    let line = format!("{resource} {rights}\n");
    send_fds(sock, line.as_bytes(), &[])?;
    let (reply, mut fds) = recv_fds(sock)?;
    if reply.starts_with(b"ok") {
        if let Some(fd) = fds.pop() {
            for extra in fds {
                close(extra); // any extra fds are unexpected
            }
            return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
        }
        return Err(Error::Confine("broker acknowledged but sent no fd".into()));
    }
    for fd in fds {
        close(fd);
    }
    Err(Error::Confine(
        String::from_utf8_lossy(&reply).trim().to_string(),
    ))
}

// Broker side: read one request on `sock`, decide it through `handler` (where
// weave's access() check and materialize() live), and answer with the fd or an
// error message. A real broker calls this in a loop, one turn per request.
pub fn serve_once(
    sock: RawFd,
    handler: impl FnOnce(&Resource, Rights) -> Result<OwnedFd>,
) -> Result<()> {
    let (line, stray) = recv_fds(sock)?;
    for fd in stray {
        close(fd); // a request carries no fds
    }
    let text = String::from_utf8_lossy(&line);
    let text = text.trim();
    let (res_str, rights_str) = text.split_once(' ').unwrap_or((text, ""));
    let resource = Resource::parse(res_str);
    let rights = Rights::parse(rights_str).unwrap_or(Rights::NONE);

    let made = match resource {
        Some(r) => handler(&r, rights),
        None => Err(Error::Confine(format!("unparseable request: {text}"))),
    };
    match made {
        Ok(fd) => {
            send_fds(sock, b"ok\n", &[fd.as_raw_fd()])?;
            Ok(())
        }
        Err(e) => {
            let _ = send_fds(sock, format!("err {e}\n").as_bytes(), &[]);
            Err(e)
        }
    }
}

// --- SCM_RIGHTS plumbing ---

fn send_fds(sock: RawFd, data: &[u8], fds: &[RawFd]) -> Result<()> {
    let iov = [IoSlice::new(data)];
    let cmsgs = [ControlMessage::ScmRights(fds)];
    let cmsgs = if fds.is_empty() {
        &cmsgs[..0]
    } else {
        &cmsgs[..]
    };
    sendmsg::<()>(sock, &iov, cmsgs, MsgFlags::empty(), None).map_err(errno_io)?;
    Ok(())
}

fn recv_fds(sock: RawFd) -> Result<(Vec<u8>, Vec<RawFd>)> {
    let mut buf = [0u8; 512];
    let mut iov = [IoSliceMut::new(&mut buf)];
    let mut space = nix::cmsg_space!([RawFd; 8]);
    let msg =
        recvmsg::<()>(sock, &mut iov, Some(&mut space), MsgFlags::empty()).map_err(errno_io)?;
    let mut fds = Vec::new();
    for c in msg.cmsgs().map_err(errno_io)? {
        if let ControlMessageOwned::ScmRights(rfds) = c {
            fds.extend(rfds);
        }
    }
    let n = msg.bytes;
    Ok((buf[..n].to_vec(), fds))
}

fn close(fd: RawFd) {
    unsafe {
        libc::close(fd);
    }
}

fn errno_io(e: nix::errno::Errno) -> Error {
    Error::Io(std::io::Error::from_raw_os_error(e as i32))
}
