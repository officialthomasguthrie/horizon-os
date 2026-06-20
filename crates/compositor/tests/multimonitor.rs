//! Headless multi-monitor test: place several outputs in one shared logical space
//! and prove each one renders its own region of the scene rather than mirroring
//! the whole thing. A real in-process Wayland client maps a window; the compositor
//! reads each output back through the software renderer and we assert on the
//! pixels. No display: the per-output region rendering the DRM backend scans out
//! is exercised through `output_render_elements`, the same headless split the
//! single-output render test uses.
//!
//! Only built with the `render` feature (the offscreen renderer and the id-based
//! output API).

#![cfg(all(target_os = "linux", feature = "render"))]

use std::collections::{HashMap, HashSet};
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
use wayland_client::protocol::wl_output::{self, WlOutput};
use wayland_client::protocol::wl_registry::{self, WlRegistry};
use wayland_client::protocol::wl_shm::{self, WlShm};
use wayland_client::protocol::wl_shm_pool::{self, WlShmPool};
use wayland_client::protocol::wl_surface::{self, WlSurface};
use wayland_client::{Connection, Dispatch, QueueHandle, WEnum};
use wayland_protocols::xdg::shell::client::xdg_surface::{self, XdgSurface};
use wayland_protocols::xdg::shell::client::xdg_toplevel::{self, XdgToplevel};
use wayland_protocols::xdg::shell::client::xdg_wm_base::{self, XdgWmBase};

const WIN: i32 = 64;
// Each test monitor; small so the layout math is easy to read in the assertions.
const OW: i32 = 300;
const OH: i32 = 200;
// Opaque magenta as a 0xAARRGGBB word: A=FF, R=FF, G=00, B=FF.
const MAGENTA: u32 = 0xFFFF_00FF;
// The clear colour behind everything: opaque black.
const BLACK: u32 = 0xFF00_0000;

fn runtime_dir() -> &'static Path {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        let d = std::env::temp_dir().join(format!("horizon-multimon-test.{}", std::process::id()));
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

// Spawn a client that maps a WIN x WIN magenta toplevel and holds it open until
// told to quit. Returns the channels: ready (buffer committed) and a quit sender.
fn spawn_window(path: PathBuf) -> (Receiver<()>, mpsc::Sender<()>, thread::JoinHandle<()>) {
    let (ready_tx, ready_rx) = mpsc::channel::<()>();
    let (quit_tx, quit_rx) = mpsc::channel::<()>();
    let handle = thread::spawn(move || {
        let conn = Connection::from_socket(UnixStream::connect(&path).unwrap()).unwrap();
        let (globals, mut queue) = registry_queue_init::<App>(&conn).unwrap();
        let qh = queue.handle();
        let mut app = App::default();

        let wl_compositor: WlCompositor = globals.bind(&qh, 1..=1, ()).unwrap();
        let wm_base: XdgWmBase = globals.bind(&qh, 1..=1, ()).unwrap();
        let shm: WlShm = globals.bind(&qh, 1..=1, ()).unwrap();

        let surface = wl_compositor.create_surface(&qh, ());
        let xdg_surface = wm_base.get_xdg_surface(&surface, &qh, ());
        let toplevel = xdg_surface.get_toplevel(&qh, ());
        toplevel.set_title("horizon-multimon".to_string());
        surface.commit();
        queue.roundtrip(&mut app).unwrap();

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
        quit_rx.recv().unwrap();
        toplevel.destroy();
        xdg_surface.destroy();
        surface.destroy();
        conn.flush().unwrap();
    });
    (ready_rx, quit_tx, handle)
}

// Two outputs side by side; the window maps at the scene origin, so it falls on
// the left output. The left reads back the window, the right reads back nothing:
// each output paints its own region, the right is not a mirror of the left.
#[test]
fn window_shows_only_on_the_output_that_covers_it() {
    let _ = runtime_dir();
    let mut comp = Compositor::new().expect("start compositor");
    let path = runtime_dir().join(comp.socket_name());

    // Left at the origin, right immediately to its logical right.
    let left = comp.add_output("LEFT", OW, OH, 1, 0, 0);
    let right = comp.add_output("RIGHT", OW, OH, 1, OW, 0);

    let (ready_rx, quit_tx, client) = spawn_window(path);
    pump_until(&mut comp, &ready_rx, "buffer commit");
    for _ in 0..3 {
        comp.dispatch(Some(Duration::from_millis(20))).unwrap();
    }

    // The left output covers logical (0,0), where the window maps.
    let lf = comp.render_output(left).expect("render left");
    assert_eq!(lf.width as i32, OW);
    assert_eq!(lf.height as i32, OH);
    assert_eq!(
        lf.argb(WIN as u32 / 2, WIN as u32 / 2),
        MAGENTA,
        "the window should appear on the left output"
    );
    assert_eq!(
        lf.argb(OW as u32 - 1, OH as u32 - 1),
        BLACK,
        "empty space on the left output should be the clear colour"
    );

    // The right output's region starts at logical x=OW, past the window, so it
    // shows nothing: it is not mirroring the left.
    let rf = comp.render_output(right).expect("render right");
    for (x, y) in [
        (WIN as u32 / 2, WIN as u32 / 2),
        (10, 10),
        (OW as u32 / 2, OH as u32 / 2),
    ] {
        assert_eq!(
            rf.argb(x, y),
            BLACK,
            "the right output must not mirror the window at {x},{y}"
        );
    }

    quit_tx.send(()).unwrap();
    client.join().unwrap();
}

// One output, one window at the scene origin. Moving the output across the shared
// space changes which region it shows, and the window lands at the matching local
// offset: this proves an output renders its own logical region, not the whole
// scene from a fixed origin.
#[test]
fn moving_an_output_shifts_the_region_it_renders() {
    let _ = runtime_dir();
    let mut comp = Compositor::new().expect("start compositor");
    let path = runtime_dir().join(comp.socket_name());

    let out = comp.add_output("SOLO", OW, OH, 1, 0, 0);

    let (ready_rx, quit_tx, client) = spawn_window(path);
    pump_until(&mut comp, &ready_rx, "buffer commit");
    for _ in 0..3 {
        comp.dispatch(Some(Duration::from_millis(20))).unwrap();
    }

    // At the origin the window sits at the output's top-left: local (0,0)..(WIN,WIN).
    let f0 = comp.render_output(out).expect("render at origin");
    assert_eq!(f0.argb(10, 10), MAGENTA, "window at the output's top-left");
    assert_eq!(
        f0.argb(WIN as u32 + 10, 10),
        BLACK,
        "just right of the window is clear"
    );

    // Shift the output left in logical space (its origin goes negative), so the
    // window, still at logical (0,0), appears SHIFT pixels in from the left edge.
    const SHIFT: i32 = 40;
    comp.move_output(out, -SHIFT, 0);
    comp.dispatch(Some(Duration::from_millis(20))).unwrap();

    let f1 = comp.render_output(out).expect("render after move");
    assert_eq!(
        f1.argb(10, 10),
        BLACK,
        "the window's old top-left is now clear: the region moved"
    );
    assert_eq!(
        f1.argb(SHIFT as u32 + 10, 10),
        MAGENTA,
        "the window now renders at its logical position offset by the output origin"
    );
    assert_eq!(
        f1.argb((SHIFT + WIN) as u32 + 10, 10),
        BLACK,
        "past the shifted window is clear again"
    );

    quit_tx.send(()).unwrap();
    client.join().unwrap();
}

// Two outputs side by side, each advertised to clients as its own wl_output. A
// client enumerates exactly the two monitors (the default placeholder is retired
// once real outputs are placed), reads each one's logical position and mode, and a
// window at the origin is told it entered only the left output, the one its region
// covers. So the per-monitor globals are real and wired to the shared layout, not
// just minted: a client learns where each screen is and which one a window is on.
#[test]
fn clients_enumerate_one_wl_output_per_monitor() {
    let _ = runtime_dir();
    let mut comp = Compositor::new().expect("start compositor");
    let path = runtime_dir().join(comp.socket_name());

    comp.add_output("LEFT", OW, OH, 1, 0, 0);
    comp.add_output("RIGHT", OW, OH, 1, OW, 0);

    let (tx, rx) = mpsc::channel::<Summary>();
    let client = thread::spawn(move || tx.send(probe(path)).unwrap());
    let summary = pump_until(&mut comp, &rx, "probe results");
    client.join().unwrap();

    let left = OutInfo {
        x: 0,
        y: 0,
        w: OW,
        h: OH,
        scale: 1,
    };
    let right = OutInfo {
        x: OW,
        y: 0,
        w: OW,
        h: OH,
        scale: 1,
    };

    // Exactly one wl_output per monitor, each at its layout position and mode, and
    // no phantom placeholder alongside them.
    assert_eq!(
        summary.outputs.len(),
        2,
        "one wl_output per monitor, no placeholder: {:?}",
        summary.outputs
    );
    assert!(
        summary.outputs.contains(&left),
        "left monitor advertised at the origin: {:?}",
        summary.outputs
    );
    assert!(
        summary.outputs.contains(&right),
        "right monitor advertised to its right: {:?}",
        summary.outputs
    );

    // The window at the origin overlaps only the left monitor.
    assert_eq!(
        summary.entered,
        vec![left],
        "surface should enter only the left output: {:?}",
        summary.entered
    );
}

// An ordinary monitor and a HiDPI one side by side, each advertised with its own
// scale. A client reads scale 1 off the first and scale 2 off the second, and
// both still report their full pixel mode, so the client derives the logical size
// itself (mode / scale). This is the last multi-monitor gap: a client now learns
// not just where each screen is but how dense it is.
#[test]
fn a_hidpi_output_advertises_its_scale_to_clients() {
    let _ = runtime_dir();
    let mut comp = Compositor::new().expect("start compositor");
    let path = runtime_dir().join(comp.socket_name());

    // Ordinary monitor at the origin (scale 1, so OW wide in logical space), then
    // a HiDPI one at logical x=OW with the same pixel mode but scale 2.
    comp.add_output("ORDINARY", OW, OH, 1, 0, 0);
    comp.add_output("HIDPI", OW, OH, 2, OW, 0);

    let (tx, rx) = mpsc::channel::<Summary>();
    let client = thread::spawn(move || tx.send(probe(path)).unwrap());
    let summary = pump_until(&mut comp, &rx, "probe results");
    client.join().unwrap();

    // Sorted by logical x: the ordinary monitor first, the HiDPI one to its right.
    assert_eq!(
        summary.outputs.len(),
        2,
        "one wl_output per monitor: {:?}",
        summary.outputs
    );
    let ordinary = summary.outputs[0];
    let hidpi = summary.outputs[1];
    assert_eq!(ordinary.scale, 1, "the ordinary monitor is scale 1");
    assert_eq!(
        hidpi.scale, 2,
        "the HiDPI monitor is advertised at scale 2: {:?}",
        hidpi
    );
    // The mode stays the full pixel size on both; the client divides by the scale.
    assert_eq!(
        (hidpi.w, hidpi.h),
        (OW, OH),
        "the HiDPI monitor advertises its physical pixel mode, not the logical size"
    );
    assert_eq!(
        hidpi.x, OW,
        "the HiDPI monitor sits to the right of the first"
    );
}

// A single HiDPI output renders its region at its scale: a 64-logical window is
// composited to 128 physical pixels. The discriminating pixel is at 100,100,
// inside the window only because it draws at 2x (it would be the clear colour at
// 1x, where the window ends at 64). This proves the scale flows all the way
// through to the pixels, not just the wl_output advertisement, the same headless
// readback the single-scale region tests use.
#[test]
fn a_hidpi_output_renders_its_region_at_scale() {
    let _ = runtime_dir();
    let mut comp = Compositor::new().expect("start compositor");
    let path = runtime_dir().join(comp.socket_name());

    // One scale-2 monitor at the origin; its mode is OW x OH physical pixels.
    let out = comp.add_output("HIDPI", OW, OH, 2, 0, 0);

    let (ready_rx, quit_tx, client) = spawn_window(path);
    pump_until(&mut comp, &ready_rx, "buffer commit");
    for _ in 0..3 {
        comp.dispatch(Some(Duration::from_millis(20))).unwrap();
    }

    let f = comp.render_output(out).expect("render hidpi");
    // The readback is the full physical mode of the output.
    assert_eq!(f.width as i32, OW);
    assert_eq!(f.height as i32, OH);
    assert_eq!(
        f.argb(10, 10),
        MAGENTA,
        "the window is present at the top-left"
    );
    assert_eq!(
        f.argb(100, 100),
        MAGENTA,
        "the window is drawn at 2x: 100,100 falls inside its 128px extent (clear at 1x)"
    );
    assert_eq!(
        f.argb(160, 160),
        BLACK,
        "past the 2x-scaled window is the clear colour"
    );

    quit_tx.send(()).unwrap();
    client.join().unwrap();
}

// Connect a client, bind every wl_output, map a WIN x WIN window at the scene
// origin, and settle until the surface has entered an output. Returns what the
// client saw: the enumerated outputs and the ones it entered.
fn probe(path: PathBuf) -> Summary {
    let conn = Connection::from_socket(UnixStream::connect(&path).unwrap()).unwrap();
    let (globals, mut queue) = registry_queue_init::<App>(&conn).unwrap();
    let qh = queue.handle();
    let mut app = App::default();

    // Bind every advertised output (udata = its registry name, so its events and a
    // later surface.enter resolve back to it).
    for global in globals.contents().clone_list() {
        if global.interface == "wl_output" {
            let output: WlOutput =
                globals
                    .registry()
                    .bind(global.name, global.version, &qh, global.name);
            app.bound.push((output, global.name));
        }
    }

    // Map a window at the scene origin (lands on the left output).
    let wl_compositor: WlCompositor = globals.bind(&qh, 1..=1, ()).unwrap();
    let wm_base: XdgWmBase = globals.bind(&qh, 1..=1, ()).unwrap();
    let shm: WlShm = globals.bind(&qh, 1..=1, ()).unwrap();
    let surface = wl_compositor.create_surface(&qh, ());
    let xdg_surface = wm_base.get_xdg_surface(&surface, &qh, ());
    let toplevel = xdg_surface.get_toplevel(&qh, ());
    toplevel.set_title("horizon-probe".to_string());
    surface.commit();
    queue.roundtrip(&mut app).unwrap();

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

    // Settle: the output geometry/mode arrive right after binding; the surface
    // enter follows once the buffer maps and the server refreshes. Roundtrip until
    // both have landed, bounded so a missing event fails the assertion, not hangs.
    for _ in 0..30 {
        queue.roundtrip(&mut app).unwrap();
        let outputs_ready = app.info.len() == app.bound.len()
            && app.info.values().all(|i| i.w > 0 && i.h > 0 && i.scale > 0);
        if outputs_ready && !app.entered.is_empty() {
            break;
        }
    }

    let mut outputs: Vec<OutInfo> = app.info.values().copied().collect();
    outputs.sort_by_key(|o| o.x);
    // Resolve entered names to geometries, de-duplicated in arrival order.
    let mut seen = HashSet::new();
    let entered: Vec<OutInfo> = app
        .entered
        .iter()
        .filter(|name| seen.insert(**name))
        .filter_map(|name| app.info.get(name).copied())
        .collect();

    Summary { outputs, entered }
}

// One advertised monitor as a client sees it: its logical position (the
// `wl_output.geometry` x/y), its current mode size in physical pixels (the
// `wl_output.mode` w/h), and its integer scale (the `wl_output.scale` factor),
// from which a client derives the logical size mode/scale.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct OutInfo {
    x: i32,
    y: i32,
    w: i32,
    h: i32,
    scale: i32,
}

// The client's view after probing: every `wl_output` it enumerated, and the
// outputs its surface was told it entered. Sent back to the test thread.
struct Summary {
    outputs: Vec<OutInfo>,
    entered: Vec<OutInfo>,
}

// The in-process client. Unit-struct-like for the render tests (which never bind a
// wl_output, so the fields stay empty), but it also records what the output-probe
// test needs: each bound output's geometry/mode, keyed by its registry name, and
// which outputs the surface entered.
#[derive(Default)]
struct App {
    // (proxy, registry name) for each bound wl_output, so a surface.enter (which
    // carries the output proxy) resolves back to a name.
    bound: Vec<(WlOutput, u32)>,
    // Registry name -> geometry/mode collected from the output's events.
    info: HashMap<u32, OutInfo>,
    // Registry names of the outputs the surface entered, in arrival order.
    entered: Vec<u32>,
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
        state: &mut Self,
        _: &WlSurface,
        event: wl_surface::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        // The compositor tells the surface which output(s) it is on. Resolve the
        // output proxy back to the registry name we bound it under.
        if let wl_surface::Event::Enter { output } = event {
            if let Some((_, name)) = state.bound.iter().find(|(o, _)| o == &output) {
                state.entered.push(*name);
            }
        }
    }
}

impl Dispatch<WlOutput, u32> for App {
    fn event(
        state: &mut Self,
        _: &WlOutput,
        event: wl_output::Event,
        name: &u32,
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        let info = state.info.entry(*name).or_default();
        match event {
            // The output's position in the global compositor space: its logical
            // position at scale 1, what the layout placed it at.
            wl_output::Event::Geometry { x, y, .. } => {
                info.x = x;
                info.y = y;
            }
            // The current mode carries the pixel size. Other (non-current) modes
            // would arrive with the flag clear; this compositor advertises one.
            wl_output::Event::Mode {
                flags,
                width,
                height,
                ..
            } => {
                if matches!(flags, WEnum::Value(f) if f.contains(wl_output::Mode::Current)) {
                    info.w = width;
                    info.h = height;
                }
            }
            // The integer scale the compositor derived for this monitor; a HiDPI
            // output reports 2, an ordinary one 1.
            wl_output::Event::Scale { factor } => {
                info.scale = factor;
            }
            _ => {}
        }
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
