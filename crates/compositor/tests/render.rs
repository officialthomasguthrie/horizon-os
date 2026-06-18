//! Headless rendering test: a real in-process Wayland client attaches a solid
//! colour shm buffer to a toplevel, the compositor imports it and composites the
//! scene into an offscreen framebuffer, and we read the pixels back and assert
//! on them. No display and no GPU: the pixman software renderer turns the
//! client's buffer into pixels, so the "windows become visible" step is proven
//! the same way the protocol is, automatically, in CI.
//!
//! Only built with the `render` feature (the offscreen renderer). The protocol
//! and scene tests in `compositor.rs` run without it.

#![cfg(all(target_os = "linux", feature = "render"))]

use std::io::Write;
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::sync::OnceLock;
use std::thread;
use std::time::{Duration, Instant};

use compositor::Compositor;
use wayland_client::globals::{registry_queue_init, GlobalListContents};
use wayland_client::protocol::wl_buffer::{self, WlBuffer};
use wayland_client::protocol::wl_compositor::{self, WlCompositor};
use wayland_client::protocol::wl_registry::{self, WlRegistry};
use wayland_client::protocol::wl_shm::{self, WlShm};
use wayland_client::protocol::wl_shm_pool::{self, WlShmPool};
use wayland_client::protocol::wl_surface::{self, WlSurface};
use wayland_client::{Connection, Dispatch, QueueHandle};
use wayland_protocols::xdg::shell::client::xdg_surface::{self, XdgSurface};
use wayland_protocols::xdg::shell::client::xdg_toplevel::{self, XdgToplevel};
use wayland_protocols::xdg::shell::client::xdg_wm_base::{self, XdgWmBase};

const WIN: i32 = 64;
// Opaque magenta as a 0xAARRGGBB word: A=FF, R=FF, G=00, B=FF.
const MAGENTA: u32 = 0xFFFF_00FF;
// The clear colour the renderer paints behind everything: opaque black.
const BLACK: u32 = 0xFF00_0000;

fn runtime_dir() -> &'static Path {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        let d = std::env::temp_dir().join(format!("horizon-render-test.{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).ok();
        std::env::set_var("XDG_RUNTIME_DIR", &d);
        d
    })
    .as_path()
}

fn pump_until<T>(comp: &mut Compositor, rx: &Receiver<T>, what: &str) -> T {
    let start = Instant::now();
    loop {
        comp.dispatch(Some(Duration::from_millis(20)))
            .expect("dispatch");
        match rx.try_recv() {
            Ok(v) => return v,
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => panic!("client thread died before {what}"),
        }
        if start.elapsed() > Duration::from_secs(10) {
            panic!("timed out waiting for {what}");
        }
    }
}

// A client maps a 64x64 magenta toplevel; the compositor composites it and the
// readback shows magenta where the window is and the clear colour elsewhere.
#[test]
fn composites_client_buffer_into_pixels() {
    let _ = runtime_dir();
    let mut comp = Compositor::new().expect("start compositor");
    let (ow, oh) = comp.output_size();
    assert!(ow >= 256 && oh >= 256, "output too small: {ow}x{oh}");
    let path = runtime_dir().join(comp.socket_name());

    let (ready_tx, ready_rx) = mpsc::channel::<()>();
    let (done_tx, done_rx) = mpsc::channel::<()>();
    let client = thread::spawn(move || {
        let conn = Connection::from_socket(UnixStream::connect(&path).unwrap()).unwrap();
        let (globals, mut queue) = registry_queue_init::<App>(&conn).unwrap();
        let qh = queue.handle();
        let mut app = App;

        let wl_compositor: WlCompositor = globals.bind(&qh, 1..=1, ()).unwrap();
        let wm_base: XdgWmBase = globals.bind(&qh, 1..=1, ()).unwrap();
        let shm: WlShm = globals.bind(&qh, 1..=1, ()).unwrap();

        let surface = wl_compositor.create_surface(&qh, ());
        let xdg_surface = wm_base.get_xdg_surface(&surface, &qh, ());
        let toplevel = xdg_surface.get_toplevel(&qh, ());
        toplevel.set_title("horizon-render".to_string());
        // Initial commit with no buffer; the server replies with a configure.
        surface.commit();
        queue.roundtrip(&mut app).unwrap();

        // A shm pool backed by a file filled with opaque magenta. The server
        // mmaps the same fd, so writing the bytes here makes them visible there.
        let stride = WIN * 4;
        let len = (stride * WIN) as usize;
        let mut file = tempfile::tempfile().unwrap();
        let mut bytes = Vec::with_capacity(len);
        for _ in 0..(WIN * WIN) {
            bytes.extend_from_slice(&MAGENTA.to_le_bytes());
        }
        file.write_all(&bytes).unwrap();
        file.flush().unwrap();

        let pool = shm.create_pool(file.as_fd(), len as i32, &qh, ());
        let buffer = pool.create_buffer(0, WIN, WIN, stride, wl_shm::Format::Argb8888, &qh, ());

        surface.attach(Some(&buffer), 0, 0);
        surface.damage(0, 0, WIN, WIN);
        surface.commit();
        queue.roundtrip(&mut app).unwrap();

        ready_tx.send(()).unwrap();
        // Keep the buffer and its backing file alive while the server renders.
        done_rx.recv().unwrap();
        toplevel.destroy();
        xdg_surface.destroy();
        surface.destroy();
        conn.flush().unwrap();
    });

    pump_until(&mut comp, &ready_rx, "buffer commit");
    // A few more batches so the buffer commit is fully processed.
    for _ in 0..3 {
        comp.dispatch(Some(Duration::from_millis(20))).unwrap();
    }

    let frame = comp.render().expect("render");
    assert_eq!(frame.width as i32, ow);
    assert_eq!(frame.height as i32, oh);

    // The window maps at the scene origin, so its pixels are magenta and a point
    // far outside it is the clear colour.
    let inside = frame.argb(WIN as u32 / 2, WIN as u32 / 2);
    let outside = frame.argb((ow - 1) as u32, (oh - 1) as u32);
    assert_eq!(
        inside, MAGENTA,
        "window pixel was {inside:#010x}, want magenta"
    );
    assert_eq!(
        outside, BLACK,
        "background pixel was {outside:#010x}, want black"
    );

    done_tx.send(()).unwrap();
    client.join().unwrap();
}

struct App;

impl Dispatch<WlRegistry, GlobalListContents> for App {
    fn event(
        _: &mut Self,
        _: &WlRegistry,
        _: wl_registry::Event,
        _: &GlobalListContents,
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<WlCompositor, ()> for App {
    fn event(
        _: &mut Self,
        _: &WlCompositor,
        _: wl_compositor::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<WlSurface, ()> for App {
    fn event(
        _: &mut Self,
        _: &WlSurface,
        _: wl_surface::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<WlShm, ()> for App {
    fn event(
        _: &mut Self,
        _: &WlShm,
        _: wl_shm::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<WlShmPool, ()> for App {
    fn event(
        _: &mut Self,
        _: &WlShmPool,
        _: wl_shm_pool::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<WlBuffer, ()> for App {
    fn event(
        _: &mut Self,
        _: &WlBuffer,
        _: wl_buffer::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<XdgWmBase, ()> for App {
    fn event(
        _: &mut Self,
        wm_base: &XdgWmBase,
        event: xdg_wm_base::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        if let xdg_wm_base::Event::Ping { serial } = event {
            wm_base.pong(serial);
        }
    }
}

impl Dispatch<XdgSurface, ()> for App {
    fn event(
        _: &mut Self,
        xdg_surface: &XdgSurface,
        event: xdg_surface::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        if let xdg_surface::Event::Configure { serial } = event {
            xdg_surface.ack_configure(serial);
        }
    }
}

impl Dispatch<XdgToplevel, ()> for App {
    fn event(
        _: &mut Self,
        _: &XdgToplevel,
        _: xdg_toplevel::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}
