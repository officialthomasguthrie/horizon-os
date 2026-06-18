// The broker fd-passing seam, end to end: a confined principal with no ambient
// authority obtains a real fd only by asking the weave broker over its one
// socket, and the access lands in the audit log. Skipped where the kernel
// forbids unprivileged user namespaces.
#![cfg(target_os = "linux")]

use std::os::unix::io::{AsRawFd, RawFd};

use cells::{portal, Cell, Payload};
use weave::{Broker, Limits, Policy, Resource, Rights};

fn socketpair() -> (RawFd, RawFd) {
    let mut fds = [0 as RawFd; 2];
    assert_eq!(
        unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) },
        0
    );
    (fds[0], fds[1])
}

fn new_broker(dir: &std::path::Path) -> Broker {
    let ls = lifestream::Lifestream::init(dir.join("store"), &[7u8; 32]).unwrap();
    Broker::open(ls, Policy::DenyAll).unwrap()
}

#[test]
fn broker_hands_a_confined_principal_a_file_fd() {
    if !cells::available() {
        eprintln!("skipping: unprivileged user namespaces unavailable");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let secret = dir.path().join("doc");
    std::fs::write(&secret, b"capability").unwrap();
    let host_path = secret.to_str().unwrap().to_string();

    let mut broker = new_broker(dir.path());
    let cap = broker
        .grant(
            "app".into(),
            Resource::file(secret.clone()),
            Rights::READ,
            Limits::none(),
        )
        .unwrap();

    let (sv, cl) = socketpair();

    let path_for_cell = host_path.clone();
    let child = Cell::new()
        .keep_fd(cl)
        .spawn(Payload::call(move || {
            // The principal cannot reach the file by path: nothing is bound.
            let c = std::ffi::CString::new(path_for_cell.as_str()).unwrap();
            let direct = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY) };
            if direct >= 0 {
                unsafe { libc::close(direct) };
                return 10;
            }
            // The only way in is the broker.
            let res = Resource::file(path_for_cell.clone());
            let fd = match portal::request(cl, &res, Rights::READ) {
                Ok(f) => f,
                Err(_) => return 11,
            };
            let mut buf = [0u8; 10];
            let n =
                unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr() as *mut libc::c_void, 10) };
            if n == 10 && &buf == b"capability" {
                0
            } else {
                12
            }
        }))
        .expect("spawn cell");

    // This side is the broker. Drop our copy of the principal's end first.
    unsafe { libc::close(cl) };
    portal::serve_once(sv, |res, rights| {
        let lease = broker
            .access(&cap, res, rights)
            .map_err(|e| cells::Error::Confine(e.to_string()))?;
        portal::materialize(&lease)
    })
    .expect("broker serve");
    unsafe { libc::close(sv) };

    let status = child.wait().expect("wait cell");
    assert!(
        status.success(),
        "principal failed (code {:?})",
        status.code
    );

    // The brokered access is recorded.
    let used = broker
        .grants()
        .iter()
        .any(|g| g.id == cap.grant_id() && g.uses == 1);
    assert!(used, "the broker did not record the use");
}

#[test]
fn broker_hands_a_confined_principal_a_socket_fd() {
    if !cells::available() {
        eprintln!("skipping: unprivileged user namespaces unavailable");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let mut broker = new_broker(dir.path());
    let cap = broker
        .grant(
            "app".into(),
            Resource::net("127.0.0.1", port),
            Rights::READ | Rights::WRITE,
            Limits::none(),
        )
        .unwrap();

    let (sv, cl) = socketpair();

    let child = Cell::new()
        .keep_fd(cl)
        .spawn(Payload::call(move || {
            // The cell has an empty network namespace; the only way out is a
            // brokered socket.
            let res = Resource::net("127.0.0.1", port);
            let fd = match portal::request(cl, &res, Rights::READ | Rights::WRITE) {
                Ok(f) => f,
                Err(_) => return 11,
            };
            let msg = b"ping";
            let n = unsafe {
                libc::write(
                    fd.as_raw_fd(),
                    msg.as_ptr() as *const libc::c_void,
                    msg.len(),
                )
            };
            if n == msg.len() as isize {
                0
            } else {
                12
            }
        }))
        .expect("spawn cell");

    unsafe { libc::close(cl) };
    portal::serve_once(sv, |res, rights| {
        let lease = broker
            .access(&cap, res, rights)
            .map_err(|e| cells::Error::Confine(e.to_string()))?;
        portal::materialize(&lease)
    })
    .expect("broker serve");
    unsafe { libc::close(sv) };

    let status = child.wait().expect("wait cell");
    assert!(
        status.success(),
        "principal failed (code {:?})",
        status.code
    );

    // The bytes the principal sent arrived over the brokered socket.
    let (mut conn, _) = listener.accept().unwrap();
    use std::io::Read;
    let mut got = [0u8; 4];
    conn.read_exact(&mut got).unwrap();
    assert_eq!(&got, b"ping");
}
