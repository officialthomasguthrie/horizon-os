// Confinement tests. Each runs a closure inside a real Cell and checks, at the
// syscall level, what the cell can and cannot reach: an empty filesystem, no
// network, an enforced seccomp filter, and exactly the fds handed in. Skipped
// where the kernel forbids unprivileged user namespaces (a hardened host, or a
// CI runner that restricts them), so the suite stays green everywhere.
#![cfg(target_os = "linux")]

use std::os::unix::io::RawFd;

use cells::{Cell, Payload, Seccomp};

fn skip_if_unavailable() -> bool {
    if cells::available() {
        return false;
    }
    eprintln!("skipping: unprivileged user namespaces are unavailable on this host");
    true
}

// Open a path read-only from inside the cell, returning the raw fd or -errno.
fn open_ro(path: &str) -> i32 {
    match std::ffi::CString::new(path) {
        Ok(c) => unsafe { libc::open(c.as_ptr(), libc::O_RDONLY) },
        Err(_) => -1,
    }
}

#[test]
fn a_bind_is_the_only_way_a_file_gets_in() {
    if skip_if_unavailable() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let secret = dir.path().join("secret");
    std::fs::write(&secret, b"horizon").unwrap();
    let host_path = secret.to_str().unwrap().to_string();

    // No bind: the host file does not exist inside the sealed tmpfs world.
    let st = Cell::new()
        .run(Payload::call(move || {
            let fd = open_ro(&host_path);
            if fd < 0 {
                0
            } else {
                unsafe { libc::close(fd) };
                1
            }
        }))
        .expect("run sealed cell");
    assert!(
        st.success(),
        "an unbound host file was reachable inside the cell"
    );

    // With a read-only bind: the file appears at /secret and reads back.
    let st = Cell::new()
        .bind_ro(secret.clone(), "/secret")
        .run(Payload::call(|| {
            let fd = open_ro("/secret");
            if fd < 0 {
                return 2;
            }
            let mut buf = [0u8; 7];
            let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, 7) };
            unsafe { libc::close(fd) };
            if n == 7 && &buf == b"horizon" {
                0
            } else {
                3
            }
        }))
        .expect("run bound cell");
    assert!(
        st.success(),
        "bound file was not readable inside (code {:?})",
        st.code
    );
}

#[test]
fn a_read_only_bind_cannot_be_written() {
    if skip_if_unavailable() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ro");
    std::fs::write(&path, b"x").unwrap();

    let st = Cell::new()
        .bind_ro(path.clone(), "/ro")
        .run(Payload::call(|| {
            let c = std::ffi::CString::new("/ro").unwrap();
            let fd = unsafe { libc::open(c.as_ptr(), libc::O_WRONLY) };
            if fd < 0 {
                0 // open for write refused, as it should be on a ro mount
            } else {
                unsafe { libc::close(fd) };
                1
            }
        }))
        .expect("run cell");
    assert!(st.success(), "a read-only bind accepted a write open");
}

#[test]
fn the_cell_has_no_network() {
    if skip_if_unavailable() {
        return;
    }
    // The cell is in an empty network namespace, so a connect must fail with no
    // route. This never touches the real network: there is no route out.
    let st = Cell::new()
        .run(Payload::call(|| {
            let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
            if fd < 0 {
                return 0;
            }
            let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            addr.sin_family = libc::AF_INET as libc::sa_family_t;
            addr.sin_port = 53u16.to_be();
            addr.sin_addr.s_addr = u32::from_ne_bytes([8, 8, 8, 8]);
            let r = unsafe {
                libc::connect(
                    fd,
                    &addr as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            };
            unsafe { libc::close(fd) };
            if r < 0 {
                0
            } else {
                1
            }
        }))
        .expect("run cell");
    assert!(st.success(), "the cell reached the network");
}

#[test]
fn seccomp_refuses_a_blocked_syscall() {
    if skip_if_unavailable() {
        return;
    }
    let st = Cell::new()
        .seccomp(Seccomp::Block(vec![libc::SYS_chdir]))
        .run(Payload::call(|| {
            let root = b"/\0";
            let r = unsafe { libc::chdir(root.as_ptr() as *const libc::c_char) };
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if r < 0 && e == libc::EPERM {
                0
            } else {
                1
            }
        }))
        .expect("run cell");
    assert!(st.success(), "seccomp did not refuse the blocked syscall");
}

#[test]
fn a_brokered_fd_is_usable_inside() {
    if skip_if_unavailable() {
        return;
    }
    // A pipe stands in for a brokered resource: the cell is handed only the
    // write end, with no other authority, and uses it.
    let mut fds = [0 as RawFd; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    let (r, w) = (fds[0], fds[1]);

    let st = Cell::new()
        .keep_fd(w)
        .run(Payload::call(move || {
            let msg = b"weave";
            let n = unsafe { libc::write(w, msg.as_ptr() as *const libc::c_void, msg.len()) };
            if n == msg.len() as isize {
                0
            } else {
                1
            }
        }))
        .expect("run cell");
    assert!(st.success(), "the cell could not use the brokered fd");

    unsafe { libc::close(w) };
    let mut buf = [0u8; 5];
    let n = unsafe { libc::read(r, buf.as_mut_ptr() as *mut libc::c_void, 5) };
    unsafe { libc::close(r) };
    assert_eq!(n, 5);
    assert_eq!(&buf, b"weave");
}

#[test]
fn the_payload_exit_code_comes_back() {
    if skip_if_unavailable() {
        return;
    }
    let st = Cell::new().run(Payload::call(|| 42)).expect("run cell");
    assert_eq!(st.code, Some(42));
    assert!(!st.success());
}
