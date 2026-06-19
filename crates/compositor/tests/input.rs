//! Headless input test: a real in-process Wayland client maps a window and binds
//! the seat, the compositor is fed synthetic pointer and keyboard input, and the
//! client is checked to receive the right wl_pointer and wl_keyboard events. No
//! display: the seat focus and event routing are driven directly through the
//! `Compositor` API, the same path a display backend (winit now, libinput later)
//! drives, so "input reaches the focused client" is proven the same way the
//! protocol and the rendering are, automatically, in CI.
//!
//! Built with the `render` feature because input hit-testing reads the surface
//! geometry the renderer records on commit; without it a window has no area to
//! land the pointer on. The pointer path always runs; the keyboard path needs a
//! seat keyboard (an xkb keymap), so its assertions are gated on `has_keyboard`.

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
use wayland_client::protocol::wl_keyboard::{self, WlKeyboard};
use wayland_client::protocol::wl_pointer::{self, WlPointer};
use wayland_client::protocol::wl_registry::{self, WlRegistry};
use wayland_client::protocol::wl_seat::{self, WlSeat};
use wayland_client::protocol::wl_shm::{self, WlShm};
use wayland_client::protocol::wl_shm_pool::{self, WlShmPool};
use wayland_client::protocol::wl_surface::{self, WlSurface};
use wayland_client::{Connection, Dispatch, QueueHandle, WEnum};
use wayland_protocols::xdg::shell::client::xdg_surface::{self, XdgSurface};
use wayland_protocols::xdg::shell::client::xdg_toplevel::{self, XdgToplevel};
use wayland_protocols::xdg::shell::client::xdg_wm_base::{self, XdgWmBase};

const WIN: i32 = 64;
// Opaque magenta as a 0xAARRGGBB word, so the window has an opaque area to hit.
const MAGENTA: u32 = 0xFFFF_00FF;
// Linux evdev codes the test injects: a left mouse button and the "A" key.
const BTN_LEFT: u32 = 0x110;
const KEY_A: u32 = 30;

fn runtime_dir() -> &'static Path {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        let d = std::env::temp_dir().join(format!("horizon-input-test.{}", std::process::id()));
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

// What the client observed, sent back once it has seen the pointer leave that
// ends the run.
#[derive(Default, Clone, Copy)]
struct Recorded {
    pointer_entered: bool,
    pointer_motion: bool,
    button: Option<u32>,
    kbd_entered: bool,
    key: Option<u32>,
}

// The client maps a window over the scene origin and binds the seat; the server
// moves the pointer onto it, clicks, types, then moves the pointer off (the
// leave is the client's cue to stop). The client must see enter + motion +
// button, and, where the seat has a keyboard, keyboard enter + key.
#[test]
fn forwards_pointer_and_keyboard_to_client() {
    let _ = runtime_dir();
    let mut comp = Compositor::new().expect("start compositor");
    let (ow, oh) = comp.output_size();
    assert!(ow >= 256 && oh >= 256, "output too small: {ow}x{oh}");
    let had_keyboard = comp.has_keyboard();
    let path = runtime_dir().join(comp.socket_name());

    let (ready_tx, ready_rx) = mpsc::channel::<()>();
    let (result_tx, result_rx) = mpsc::channel::<Recorded>();
    let client = thread::spawn(move || {
        let conn = Connection::from_socket(UnixStream::connect(&path).unwrap()).unwrap();
        let (globals, mut queue) = registry_queue_init::<App>(&conn).unwrap();
        let qh = queue.handle();
        let mut app = App::default();

        let wl_compositor: WlCompositor = globals.bind(&qh, 1..=1, ()).unwrap();
        let wm_base: XdgWmBase = globals.bind(&qh, 1..=1, ()).unwrap();
        let shm: WlShm = globals.bind(&qh, 1..=1, ()).unwrap();
        // A v1 seat carries the core pointer and keyboard events this checks.
        // Take only the capabilities it actually advertises (asking for a missing
        // one is a protocol error), which the roundtrip below delivers.
        let _seat: WlSeat = globals.bind(&qh, 1..=1, ()).unwrap();
        queue.roundtrip(&mut app).unwrap();

        let surface = wl_compositor.create_surface(&qh, ());
        let xdg_surface = wm_base.get_xdg_surface(&surface, &qh, ());
        let toplevel = xdg_surface.get_toplevel(&qh, ());
        toplevel.set_title("horizon-input".to_string());
        // Initial commit with no buffer; the server replies with a configure.
        surface.commit();
        queue.roundtrip(&mut app).unwrap();

        // A magenta shm buffer gives the window an opaque area to hit-test.
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

        // Remember our surface so the enter events can be matched to it.
        app.surface = Some(surface.clone());
        ready_tx.send(()).unwrap();

        // Read events until the pointer leaves (the server's terminator), then
        // report what we saw.
        while !app.pointer_left {
            queue.blocking_dispatch(&mut app).unwrap();
        }
        result_tx.send(app.rec).unwrap();

        toplevel.destroy();
        xdg_surface.destroy();
        surface.destroy();
        conn.flush().unwrap();
    });

    pump_until(&mut comp, &ready_rx, "client ready");
    // A few batches so the buffer commit has settled into window geometry.
    for _ in 0..3 {
        comp.dispatch(Some(Duration::from_millis(20))).unwrap();
    }

    // Move onto the window (enter) and again within it (a motion), click it
    // (which focuses it), type a key, release the click (a held button grabs the
    // pointer), then move off the window so the pointer leaves, which is the
    // client's cue to stop.
    comp.pointer_motion(10.0, 10.0);
    comp.pointer_motion(20.0, 20.0);
    comp.pointer_button(BTN_LEFT, true);
    // The press landed on the client window, so it is the window's click, not a
    // shell-background one: nothing should be reported to the shell.
    assert!(
        comp.take_shell_click().is_none(),
        "a click on a client window is not a shell click"
    );
    comp.keyboard_key(KEY_A, true);
    comp.keyboard_key(KEY_A, false);
    comp.pointer_button(BTN_LEFT, false);
    comp.pointer_motion((ow + 100) as f64, (oh + 100) as f64);

    let rec = pump_until(&mut comp, &result_rx, "input result");
    client.join().unwrap();

    assert!(
        rec.pointer_entered,
        "client did not get a pointer enter on its surface"
    );
    assert!(rec.pointer_motion, "client did not get pointer motion");
    assert_eq!(
        rec.button,
        Some(BTN_LEFT),
        "client did not get the button press"
    );
    if had_keyboard {
        assert!(
            rec.kbd_entered,
            "client did not get a keyboard enter on its surface"
        );
        assert_eq!(rec.key, Some(KEY_A), "client did not get the key press");
    } else {
        eprintln!("input test: seat has no keyboard (no xkb data); skipped keyboard checks");
    }
}

// A press on empty space (no client window under the cursor) is reported as a
// shell-background click in output-logical pixels and cleared when taken. No
// display or client is needed: this is pure input routing, the seam Horizon
// resolves through the Glass scene to a `sever`. The "a window click is not a
// shell click" half is asserted in the test above, where a window is mapped.
#[test]
fn shell_background_clicks_are_reported_and_cleared() {
    let _ = runtime_dir();
    let mut comp = Compositor::new().expect("start compositor");
    assert!(comp.take_shell_click().is_none(), "nothing clicked yet");

    // Move onto empty space and press: the press is recorded at the cursor.
    comp.pointer_motion(300.0, 220.0);
    comp.pointer_button(BTN_LEFT, true);
    assert_eq!(
        comp.take_shell_click(),
        Some((300, 220)),
        "an empty-space press is a shell click at the cursor"
    );
    // Taking it clears it.
    assert!(
        comp.take_shell_click().is_none(),
        "the shell click was consumed"
    );

    // Releasing the button is not a new click (only presses record one).
    comp.pointer_button(BTN_LEFT, false);
    assert!(comp.take_shell_click().is_none(), "release is not a click");
}

#[derive(Default)]
struct App {
    surface: Option<WlSurface>,
    // Held so the seat's pointer/keyboard are not released back to the server.
    pointer: Option<WlPointer>,
    keyboard: Option<WlKeyboard>,
    rec: Recorded,
    pointer_left: bool,
}

impl Dispatch<WlSeat, ()> for App {
    fn event(
        app: &mut Self,
        seat: &WlSeat,
        event: wl_seat::Event,
        _: &(),
        _: &Connection,
        qh: &QueueHandle<Self>,
    ) {
        if let wl_seat::Event::Capabilities {
            capabilities: WEnum::Value(caps),
        } = event
        {
            if caps.contains(wl_seat::Capability::Pointer) && app.pointer.is_none() {
                app.pointer = Some(seat.get_pointer(qh, ()));
            }
            if caps.contains(wl_seat::Capability::Keyboard) && app.keyboard.is_none() {
                app.keyboard = Some(seat.get_keyboard(qh, ()));
            }
        }
    }
}

impl Dispatch<WlPointer, ()> for App {
    fn event(
        app: &mut Self,
        _: &WlPointer,
        event: wl_pointer::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        match event {
            wl_pointer::Event::Enter { surface, .. } => {
                app.rec.pointer_entered = app.surface.as_ref() == Some(&surface);
            }
            wl_pointer::Event::Motion { .. } => app.rec.pointer_motion = true,
            wl_pointer::Event::Button {
                button,
                state: WEnum::Value(wl_pointer::ButtonState::Pressed),
                ..
            } => app.rec.button = Some(button),
            wl_pointer::Event::Leave { .. } => app.pointer_left = true,
            _ => {}
        }
    }
}

impl Dispatch<WlKeyboard, ()> for App {
    fn event(
        app: &mut Self,
        _: &WlKeyboard,
        event: wl_keyboard::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        match event {
            wl_keyboard::Event::Enter { surface, .. } => {
                app.rec.kbd_entered = app.surface.as_ref() == Some(&surface);
            }
            wl_keyboard::Event::Key {
                key,
                state: WEnum::Value(wl_keyboard::KeyState::Pressed),
                ..
            } => app.rec.key = Some(key),
            _ => {}
        }
    }
}

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
