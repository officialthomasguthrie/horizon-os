//! The software (pixman) DRM/KMS scanout backend: drive real displays through KMS
//! with no GPU in the path.
//!
//! The `udev` backend needs a GBM/GLES device: virtio-gpu with virgl, or real
//! hardware with a working EGL stack. Plain QEMU (no virgl) and a fair amount of
//! real hardware offer only a dumb-buffer KMS device with no usable 3D, and there
//! the GLES path cannot start. This backend drives exactly those: it composites
//! the scene with the same pixman software renderer the headless tests assert on,
//! straight into a DRM dumb buffer (ordinary CPU memory the scanout engine reads),
//! and page-flips it. So it is both the QEMU boot target and the no-GPU fallback a
//! "boots anywhere" Key wants, the path that works on any KMS device.
//!
//! It sits on the same split as the rest of the compositor, so almost nothing here
//! is new logic. The frame is [`output_render_elements`], the exact scene the
//! headless render test asserts on, handed to a Smithay `DrmOutput`; the input is
//! the same seat routing the headless input test drives, now fed by libinput. The
//! one thing the GLES backend gets for free that this has to express itself is the
//! shell background: the GLES path draws it as a `MemoryRenderBufferRenderElement`,
//! which requires a `Send` texture the pixman one is not, so here it is a
//! [`TextureRenderElement`] over a cached pixman texture instead (no `Send` bound),
//! which is the only real difference from `drm.rs`.
//!
//! Like the GLES backend it is now multi-device, multi-output, and hotplug-aware,
//! over the same seat routing and compositing it already shared. Every KMS device
//! udev reports is brought up and watched; a device hotplugged in or out is added
//! or dropped, and each one rescans its connectors on a udev change, so plugging or
//! unplugging a monitor lights or drops its output. Every lit connector is placed
//! in one shared logical space (a left-to-right [`layout`](crate::layout)) and scans
//! out its own region, with the cursor roaming the whole span, and is advertised to
//! clients as its own `wl_output` global at its position, mode, and scale. A VT
//! switch away and back is recovered: every device is reactivated and every
//! swapchain reset. Input devices are picked up live too: the path backend is
//! rescanned on a timer, so a keyboard or mouse plugged in after boot starts working
//! (one-shot-at-startup was the old limitation). Unlike the GLES backend there is no
//! multi-GPU manager: one pixman software renderer composites every output on every
//! device straight into its dumb buffer (CPU memory binds anywhere), so the
//! cross-GPU copy the GLES path needs does not arise here.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use smithay::backend::allocator::dumb::DumbAllocator;
use smithay::backend::allocator::Fourcc;
use smithay::backend::drm::compositor::{DrmCompositor, FrameFlags};
use smithay::backend::drm::{DrmDevice, DrmDeviceFd, DrmEvent, DrmNode};
use smithay::backend::input::{
    AbsolutePositionEvent, Axis, ButtonState, InputEvent, KeyState, KeyboardKeyEvent,
    PointerAxisEvent, PointerButtonEvent, PointerMotionEvent,
};
use smithay::backend::libinput::{LibinputInputBackend, LibinputSessionInterface};
use smithay::backend::renderer::element::texture::{TextureBuffer, TextureRenderElement};
use smithay::backend::renderer::element::Kind;
use smithay::backend::renderer::pixman::{PixmanRenderer, PixmanTexture};
use smithay::backend::renderer::{Color32F, ImportDma};
use smithay::backend::session::libseat::LibSeatSession;
use smithay::backend::session::{Event as SessionEvent, Session};
use smithay::backend::udev::{self, UdevBackend, UdevEvent};
use smithay::output::{Mode as OutputMode, Output, PhysicalProperties, Scale, Subpixel};
use smithay::reexports::calloop::timer::{TimeoutAction, Timer};
use smithay::reexports::calloop::{EventLoop, LoopHandle, RegistrationToken};
use smithay::reexports::drm::control::{
    connector, crtc, Device as ControlDevice, Mode as DrmMode, ModeTypeFlags,
};
use smithay::reexports::input::{Device as InputDevice, Libinput};
use smithay::reexports::rustix::fs::OFlags;
use smithay::reexports::wayland_server::backend::GlobalId;
use smithay::reexports::wayland_server::DisplayHandle;
use smithay::utils::{DeviceFd, Logical, Point, Size, Transform};

use crate::render::output_render_elements;
use crate::server::ShellEvent;
use crate::{layout, Compositor, Error, Result};

// The scanout types for the no-GPU path: a dumb-buffer allocator (always linear CPU
// memory), the device fd as the framebuffer exporter (a dumb buffer is already a GEM
// object the device turns into a scanout framebuffer), `()` per-frame user data, and
// the device fd as the device handle. No gbm device exists (the cursor plane it would
// feed is unused; the cursor composites into the frame), so unlike the GLES backend
// there is no GLES context and no multi-GPU manager: one pixman renderer paints every
// output into a dumb buffer.
// `DumbAllocator` is not `Clone`, so unlike the GLES backend this cannot use
// `DrmOutputManager` (which clones the allocator to spawn each output's compositor);
// each output instead gets its own `DrmCompositor` built directly with a fresh
// allocator over the shared device fd, and the raw `DrmDevice` is kept per device to
// create surfaces, rescan connectors, and pause/resume across a VT switch.
type SoftCompositor = DrmCompositor<DumbAllocator, DrmDeviceFd, (), DrmDeviceFd>;

// A frame draws two kinds of element: client window surfaces and, behind them, the
// shell background. `DrmOutput::render_frame` takes a homogeneous slice, so they
// unify into one enum. Unlike the GLES backend's `ShellElement` (whose background is
// a `MemoryRenderBufferRenderElement`, needing a `Send` texture), the background here
// is a `TextureRenderElement` over the pixman texture, which has no `Send` bound, so
// the concrete pixman renderer form of the macro is what fits.
//
// In its own module because `render_elements!` expands to code that names a bare
// `Result`, which would otherwise resolve to this crate's `Result` alias; inside
// `elements` `Result` is still the std one.
mod elements {
    use smithay::backend::renderer::element::render_elements;
    use smithay::backend::renderer::element::surface::WaylandSurfaceRenderElement;
    use smithay::backend::renderer::element::texture::TextureRenderElement;
    use smithay::backend::renderer::pixman::{PixmanRenderer, PixmanTexture};

    render_elements! {
        pub ShellElement<=PixmanRenderer>;
        Surface = WaylandSurfaceRenderElement<PixmanRenderer>,
        Background = TextureRenderElement<PixmanTexture>,
    }
}
use elements::ShellElement;

// 8-bit scanout formats, which every KMS device and dumb-buffer allocator handles;
// pixman binds both as linear buffers. The order is the swapchain preference order.
const COLOR_FORMATS: &[Fourcc] = &[Fourcc::Argb8888, Fourcc::Xrgb8888];

// How often to rescan `/dev/input` for input devices plugged in after startup. The
// path backend has no udev monitor of its own, so a cheap readdir on a timer is how
// a keyboard or mouse hotplugged later starts working.
const INPUT_RESCAN: Duration = Duration::from_secs(1);

// One lit output, driven by one CRTC.
struct OutputSurface {
    drm: SoftCompositor,
    // The smithay Output the DrmCompositor reads its mode/scale/transform from, also
    // mapped into the compositor's shared `Space` (at its logical layout position) so
    // this surface scans out its own region of the scene.
    output: Output,
    // This monitor's `wl_output` global, withdrawn when the connector is unplugged or
    // its device goes.
    global: GlobalId,
    // True between queue_frame and the vblank that retires it: do not draw the next
    // frame on this output until the page flip completes.
    pending: bool,
}

// One KMS device: the raw DRM device, the dumb-buffer formats its outputs are built
// with, the outputs lit on it, and the connector -> CRTC map a rescan diffs against.
// Dropping it tears down its outputs (each `DrmCompositor` releases its CRTC on drop)
// and closes the device.
struct Device {
    // Declared before `drm` so the outputs drop first: each `DrmCompositor` releases
    // its CRTC cleanly while the device is still open.
    surfaces: HashMap<crtc::Handle, OutputSurface>,
    connectors: HashMap<connector::Handle, crtc::Handle>,
    // The raw device, kept to create surfaces, rescan connectors, and pause/resume it
    // across a VT switch.
    drm: DrmDevice,
    // The device fd, cloned per output for that output's `DumbAllocator` and as the
    // framebuffer exporter.
    drm_fd: DrmDeviceFd,
    // The scanout formats the pixman renderer can bind, used to build each output's
    // compositor (the renderer is device-independent, so this is the same per device).
    render_formats: Vec<smithay::backend::allocator::Format>,
    // The DRM vblank/error event source, removed when the device goes away.
    drm_token: RegistrationToken,
}

// The backend's resources, shared with the event-loop sources as the loop data. The
// Wayland server stays in the `Compositor`, driven separately each iteration exactly
// as the winit and GLES loops drive it; that is why the seat routing and scene here
// are the already-tested ones.
struct SoftBackend {
    // The Wayland display handle, to create and withdraw a `wl_output` global per
    // connector as monitors come and go.
    dh: DisplayHandle,
    // Held so the seat stays ours and to open the devices and input through.
    session: LibSeatSession,
    // The one software renderer, held across frames. It composites every output of
    // every device into the dumb buffer that output's compositor hands it; CPU memory
    // binds anywhere, so no per-GPU renderer or cross-GPU copy is needed.
    renderer: PixmanRenderer,
    // The KMS device udev names as primary (or the first one seen), only so its
    // outputs sort first in the layout (the primary monitor at the origin).
    primary: Option<DrmNode>,
    devices: HashMap<DrmNode, Device>,
    loop_handle: LoopHandle<'static, SoftBackend>,
    // Kept for suspend/resume across a session change; the event source holds its own
    // clone. The path backend, so it is rescanned for hotplugged input devices.
    libinput: Libinput,
    // Input nodes already seen, keyed by their `/dev/input` path: `Some(device)` was
    // added to libinput (and is removed when the node vanishes), `None` was a node
    // libinput would not take, recorded so the rescan does not retry it every tick.
    known_inputs: HashMap<PathBuf, Option<InputDevice>>,
    // Input drained and routed to the compositor after each dispatch, so a calloop
    // callback never has to borrow the compositor.
    input_events: Vec<InputEvent<LibinputInputBackend>>,
    // The cursor position in output-logical pixels; libinput pointer motion is
    // relative, so we accumulate and clamp it ourselves.
    cursor: Point<f64, Logical>,
    // Cursor clamp bounds: the whole multi-monitor span, so the pointer can cross
    // from one screen to the next instead of being trapped on the first.
    output_size: Size<i32, Logical>,
    // The outputs currently mapped into the compositor's shared space, so a relayout
    // can drop the old arrangement before installing the new one.
    mapped: Vec<Output>,
    // Set when the set of lit outputs changes (a monitor or device was plugged or
    // unplugged), so the next loop iteration recomputes the layout and remaps.
    outputs_dirty: bool,
    // The shell background as a cached pixman texture, drawn behind every window.
    // Rebuilt only when the compositor's background generation changes (an idle
    // desktop is not re-imported each frame), and carrying a stable id so the
    // damage tracking skips re-scanning out an unchanged frame.
    background: Option<TextureBuffer<PixmanTexture>>,
    // The compositor background generation `background` was built from.
    background_gen: u64,
    // Whether the session owns the devices right now (false while switched away).
    active: bool,
}

/// Bring up the software DRM/KMS backend and run it until the process is stopped.
/// Drives the Wayland server (`comp`) between frames, so clients connect and map
/// exactly as in the headless core; their windows are then scanned out to every
/// screen with no GPU in the path.
pub(crate) fn run(
    comp: &mut Compositor,
    mut on_shell: impl FnMut(ShellEvent) -> Option<Vec<u8>>,
) -> Result<()> {
    let mut event_loop: EventLoop<'static, SoftBackend> =
        EventLoop::try_new().map_err(|e| Error::Init(format!("event loop: {e}")))?;
    let mut backend = setup(event_loop.handle(), comp.display_handle())?;

    // A single readiness line once the scanout is up, summarizing what was lit (each
    // connector also logged its own "lit at WxH"). The "software scanout" phrase is the
    // signal the boot is on screen, the same one the QEMU verify waits for.
    let outputs: usize = backend.devices.values().map(|d| d.surfaces.len()).sum();
    println!(
        "compositor: software scanout up, {} output(s) on {} device(s)",
        outputs,
        backend.devices.len()
    );

    let start = Instant::now();
    loop {
        // Service the backend's fd sources (udev hotplug, vblank, libinput, session
        // changes, the input rescan timer).
        event_loop
            .dispatch(Some(Duration::from_millis(16)), &mut backend)
            .map_err(|e| Error::Loop(e.to_string()))?;

        // Route the input this batch collected to the focused client(s).
        let output_size = backend.output_size;
        let events = std::mem::take(&mut backend.input_events);
        for event in events {
            apply_input(comp, event, &mut backend.cursor, output_size);
        }

        // A press on the shell background (no client window over it) is offered to
        // the owner; if it redraws the surface (e.g. a Glass `sever` button was
        // clicked), set the new background, which the next frame composites.
        if let Some((x, y)) = comp.take_shell_click() {
            if let Some(rgba) = on_shell(ShellEvent::Click(x, y)) {
                let (ow, oh) = comp.output_size();
                comp.set_shell_background(&rgba, ow, oh);
            }
        }

        // Keystrokes that arrived while no client held focus belong to the shell
        // (its command palette); the next frame composites any redraw they cause.
        for key in comp.take_shell_keys() {
            if let Some(rgba) = on_shell(ShellEvent::Key(key)) {
                let (ow, oh) = comp.output_size();
                comp.set_shell_background(&rgba, ow, oh);
            }
        }

        // Offer a tick so the owner can poll for changes made outside the shell
        // (e.g. the audit log grew) and refresh the background. The owner rate-
        // limits this, so an idle desktop pays only a cheap check per iteration.
        if let Some(rgba) = on_shell(ShellEvent::Tick) {
            let (ow, oh) = comp.output_size();
            comp.set_shell_background(&rgba, ow, oh);
        }

        // A monitor or device came or went: recompute the left-to-right layout and
        // remap the shared space before this frame, so each output scans out its own
        // region. Cheap and skipped when nothing changed.
        if backend.outputs_dirty {
            backend.relayout(comp);
        }

        // Service Wayland clients (accept, dispatch, flush) between frames.
        comp.dispatch(Some(Duration::ZERO))?;

        // Present every output that is not waiting on a page flip.
        if backend.active {
            render_all(comp, &mut backend);
        }

        // Let animating clients draw their next frame.
        comp.send_frames(start.elapsed().as_millis() as u32);
    }
}

// Composite the current scene onto every output of every device that is ready for a
// new frame. One pixman renderer paints them all: each output's own region of the
// shared scene (only the windows that fall on it, offset to its logical origin), then
// the shell background appended last so it sits behind them (render_frame draws the
// element list front to back). An empty (undamaged) frame is not queued, so an idle
// desktop does no scanout work and the dispatch timeout paces the loop.
fn render_all(comp: &mut Compositor, backend: &mut SoftBackend) {
    let clear = Color32F::new(0.06, 0.06, 0.06, 1.0);
    // Rebuild the cached background texture if the shell changed it (cheap when
    // unchanged: just a generation compare).
    sync_background(comp, backend);

    for device in backend.devices.values_mut() {
        for surface in device.surfaces.values_mut() {
            if surface.pending {
                continue;
            }
            let mut elements: Vec<ShellElement> =
                output_render_elements(&mut backend.renderer, comp.space(), &surface.output)
                    .into_iter()
                    .map(ShellElement::Surface)
                    .collect();
            if let Some(buffer) = &backend.background {
                let element = TextureRenderElement::from_texture_buffer(
                    (0.0, 0.0),
                    buffer,
                    None,
                    None,
                    None,
                    Kind::Unspecified,
                );
                elements.push(ShellElement::Background(element));
            }

            // `empty()` (not `DEFAULT`): never try to promote an element onto a
            // hardware plane for direct scanout. Direct scanout needs a buffer the
            // device can scan out by itself (a dmabuf), and here every element is CPU
            // memory (a client's shm surface, the pixman background texture), so a
            // promotion could only ever fall back to compositing anyway. Forcing
            // everything through the renderer into the primary dumb buffer is both
            // correct and what a software path should do.
            match surface.drm.render_frame(
                &mut backend.renderer,
                &elements,
                clear,
                FrameFlags::empty(),
            ) {
                Ok(result) if !result.is_empty => match surface.drm.queue_frame(()) {
                    Ok(()) => surface.pending = true,
                    Err(e) => eprintln!("compositor: queue frame: {e}"),
                },
                Ok(_) => {}
                Err(e) => eprintln!("compositor: render frame: {e}"),
            }
        }
    }
}

// Rebuild the cached background texture when the compositor's shell background changes
// (tracked by generation), so an unchanged desktop is imported at most once rather
// than every frame. A fresh `TextureBuffer` carries a new id, so the compositor's
// damage tracker redraws it once and then, while the id and geometry hold steady,
// treats it as unchanged and skips re-scanning out. The bytes are `Abgr8888` (R, G,
// B, A), what `glass::Pixmap` produces, drawn at native size at the output origin.
fn sync_background(comp: &Compositor, backend: &mut SoftBackend) {
    let generation = comp.background_generation();
    if generation == backend.background_gen {
        return;
    }
    backend.background_gen = generation;
    backend.background = match comp.background() {
        Some(bg) => TextureBuffer::from_memory(
            &mut backend.renderer,
            bg.rgba(),
            Fourcc::Abgr8888,
            (bg.width(), bg.height()),
            false,
            1,
            Transform::Normal,
            None,
        )
        .map_err(|e| eprintln!("compositor: background import: {e}"))
        .ok(),
        None => None,
    };
}

// Build the backend: take the seat, start libinput on the path backend, insert the
// session, input, udev, and input-rescan sources, then bring up whatever KMS devices
// are already present. Each device's connectors are scanned as it comes up; hotplug
// after that is driven by the udev source.
fn setup(loop_handle: LoopHandle<'static, SoftBackend>, dh: DisplayHandle) -> Result<SoftBackend> {
    // Become the session's DRM master via libseat, so opening the devices and the
    // input devices works without real root.
    let (session, notifier) =
        LibSeatSession::new().map_err(|e| Error::Init(format!("libseat session: {e}")))?;
    let seat_name = session.seat();

    // The pixman software renderer paints every frame.
    let renderer = PixmanRenderer::new().map_err(|e| Error::Render(format!("pixman: {e}")))?;

    // libinput, sharing the session so it opens input devices through the seat. The
    // minimal Horizon boot runs no udev daemon, so libinput's udev backend would find
    // nothing (it filters devices on the ID_INPUT/ID_SEAT properties udev rules set).
    // Use the path backend instead: enumerate the evdev nodes devtmpfs creates and add
    // each directly, opened through libseat, so it needs neither real root nor udevd.
    // A timer rescans for nodes plugged in later (input hotplug).
    let libinput = Libinput::new_from_path(LibinputSessionInterface::from(session.clone()));
    let libinput_source = LibinputInputBackend::new(libinput.clone());

    // The KMS device udev names as primary, if any; the first one seen becomes primary
    // otherwise (decided in device_added). Only used to order the layout.
    let primary = udev::primary_gpu(&seat_name)
        .ok()
        .flatten()
        .and_then(|path| DrmNode::from_path(path).ok());

    // Session changes: a VT switch away pauses every device and input; coming back
    // reactivates them, resets the now-stale swapchains, and forces a full redraw.
    loop_handle
        .insert_source(
            notifier,
            |event, _, backend: &mut SoftBackend| match event {
                SessionEvent::PauseSession => {
                    backend.libinput.suspend();
                    for device in backend.devices.values_mut() {
                        device.drm.pause();
                    }
                    backend.active = false;
                }
                SessionEvent::ActivateSession => {
                    if backend.libinput.resume().is_err() {
                        eprintln!("compositor: libinput resume failed");
                    }
                    for device in backend.devices.values_mut() {
                        // activate(true) re-acquires DRM master and resets the device; each
                        // surface's compositor then reset_state()s its view of the now-stale
                        // KMS state and reset_buffers drops the swapchain, so the next frame
                        // reallocates and reprograms the mode.
                        if let Err(e) = device.drm.activate(true) {
                            eprintln!("compositor: drm reactivate failed: {e}");
                        }
                        for surface in device.surfaces.values_mut() {
                            if let Err(e) = surface.drm.reset_state() {
                                eprintln!("compositor: surface reset failed: {e}");
                            }
                            surface.drm.reset_buffers();
                            // The in-flight frame's vblank never arrived while paused.
                            surface.pending = false;
                        }
                    }
                    backend.active = true;
                }
            },
        )
        .map_err(|e| Error::Init(format!("insert session source: {e}")))?;

    // Raw input: collected now, routed to the compositor after dispatch returns.
    loop_handle
        .insert_source(libinput_source, |event, _, backend: &mut SoftBackend| {
            backend.input_events.push(event);
        })
        .map_err(|e| Error::Init(format!("insert libinput source: {e}")))?;

    // Rescan /dev/input on a timer so a keyboard or mouse plugged in after boot is
    // added to the path backend (and one unplugged is removed).
    loop_handle
        .insert_source(Timer::from_duration(INPUT_RESCAN), |_, _, backend| {
            backend.rescan_input();
            TimeoutAction::ToDuration(INPUT_RESCAN)
        })
        .map_err(|e| Error::Init(format!("insert input timer: {e}")))?;

    // Device discovery and hotplug. The current devices are listed now; later add /
    // change / remove events come through the source.
    let udev_backend =
        UdevBackend::new(&seat_name).map_err(|e| Error::Init(format!("udev: {e}")))?;
    let initial: Vec<(_, _)> = udev_backend
        .device_list()
        .map(|(id, path)| (id, path.to_path_buf()))
        .collect();
    loop_handle
        .insert_source(
            udev_backend,
            |event, _, backend: &mut SoftBackend| match event {
                UdevEvent::Added { device_id, path } => {
                    if let Ok(node) = DrmNode::from_dev_id(device_id) {
                        backend.device_added(node, &path);
                    }
                }
                UdevEvent::Changed { device_id } => {
                    if let Ok(node) = DrmNode::from_dev_id(device_id) {
                        backend.device_changed(node);
                    }
                }
                UdevEvent::Removed { device_id } => {
                    if let Ok(node) = DrmNode::from_dev_id(device_id) {
                        backend.device_removed(node);
                    }
                }
            },
        )
        .map_err(|e| Error::Init(format!("insert udev source: {e}")))?;

    let mut backend = SoftBackend {
        dh,
        session,
        renderer,
        primary,
        devices: HashMap::new(),
        loop_handle,
        libinput,
        known_inputs: HashMap::new(),
        input_events: Vec::new(),
        cursor: Point::from((0.0, 0.0)),
        output_size: Size::from((1920, 1080)),
        mapped: Vec::new(),
        outputs_dirty: false,
        background: None,
        background_gen: 0,
        active: true,
    };

    // The input devices already present.
    backend.rescan_input();

    // Bring up the KMS devices already present.
    for (device_id, path) in initial {
        if let Ok(node) = DrmNode::from_dev_id(device_id) {
            backend.device_added(node, &path);
        }
    }
    if backend.devices.is_empty() {
        eprintln!("compositor: no KMS device found yet; waiting for one to appear");
    }

    // Start the cursor centered on the primary output.
    backend.cursor = Point::from((
        backend.output_size.w as f64 / 2.0,
        backend.output_size.h as f64 / 2.0,
    ));

    Ok(backend)
}

impl SoftBackend {
    // Bring a KMS device online: open it through the session, keep its raw DRM device
    // and the scanout formats its outputs are built with, register its vblank source,
    // and scan its connectors for displays to light. A failure on one device is logged
    // and skipped, not fatal: the others still run.
    fn device_added(&mut self, node: DrmNode, path: &Path) {
        let fd = match self.session.clone().open(
            path,
            OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOCTTY | OFlags::NONBLOCK,
        ) {
            Ok(fd) => fd,
            Err(e) => {
                eprintln!("compositor: open {}: {e}", path.display());
                return;
            }
        };
        let drm_fd = DrmDeviceFd::new(DeviceFd::from(fd));
        // disable_connectors true so the device starts from a known reset state.
        let (drm, drm_notifier) = match DrmDevice::new(drm_fd.clone(), true) {
            Ok(drm) => drm,
            Err(e) => {
                eprintln!("compositor: drm {}: {e}", path.display());
                return;
            }
        };

        // The scanout formats the pixman renderer can bind, materialized so each
        // output's compositor is built from them (the renderer is CPU, so they do not
        // vary per device).
        let render_formats: Vec<_> = self.renderer.dmabuf_formats().into_iter().collect();

        // Vblanks retire the queued frame on the matching output; errors are logged.
        // The captured node names the device in the shared loop data.
        let drm_token = match self.loop_handle.insert_source(
            drm_notifier,
            move |event, _, backend: &mut SoftBackend| match event {
                DrmEvent::VBlank(crtc) => {
                    if let Some(surface) = backend
                        .devices
                        .get_mut(&node)
                        .and_then(|device| device.surfaces.get_mut(&crtc))
                    {
                        let _ = surface.drm.frame_submitted();
                        surface.pending = false;
                    }
                }
                DrmEvent::Error(e) => eprintln!("compositor: drm error: {e}"),
            },
        ) {
            Ok(token) => token,
            Err(e) => {
                eprintln!("compositor: insert drm source {}: {e}", path.display());
                return;
            }
        };

        if self.primary.is_none() {
            self.primary = Some(node);
        }
        self.devices.insert(
            node,
            Device {
                surfaces: HashMap::new(),
                connectors: HashMap::new(),
                drm,
                drm_fd,
                render_formats,
                drm_token,
            },
        );

        self.scan_connectors(node);
    }

    // A KMS device was unplugged: drop its device (which tears down its outputs and
    // closes it) and remove its vblank source.
    fn device_removed(&mut self, node: DrmNode) {
        let Some(device) = self.devices.remove(&node) else {
            return;
        };
        // Withdraw the wl_output global of every monitor this device drove; the
        // surfaces drop with the device.
        for surface in device.surfaces.values() {
            crate::server::remove_output_global(&self.dh, surface.global.clone());
        }
        self.loop_handle.remove(device.drm_token);
        if self.primary == Some(node) {
            self.primary = self.devices.keys().next().copied();
        }
        self.outputs_dirty = true;
        println!("compositor: KMS device {node:?} removed");
    }

    // udev signalled this device changed (a connector was plugged or unplugged):
    // rescan its connectors.
    fn device_changed(&mut self, node: DrmNode) {
        if self.devices.contains_key(&node) {
            self.scan_connectors(node);
        }
    }

    // Diff a device's connectors against what is lit: light a newly connected display
    // on a free CRTC, drop the output of one that was unplugged. Called when the
    // device comes up and whenever udev signals it changed.
    fn scan_connectors(&mut self, node: DrmNode) {
        let mut changed = false;
        // Cloned up front so the global create/withdraw below borrow the handle, not
        // `self`, while `device` holds a mutable borrow of `self.devices`.
        let dh = self.dh.clone();

        {
            let Some(device) = self.devices.get_mut(&node) else {
                return;
            };

            // Phase 1: read the current connector layout. Which connectors are
            // connected, and for each one not yet lit, a free CRTC and a mode.
            let (connected, to_add) = {
                let drm = &device.drm;
                let res = match drm.resource_handles() {
                    Ok(res) => res,
                    Err(e) => {
                        eprintln!("compositor: drm resources: {e}");
                        return;
                    }
                };
                let mut used: HashSet<crtc::Handle> = device.surfaces.keys().copied().collect();
                let mut connected: Vec<connector::Handle> = Vec::new();
                let mut to_add: Vec<(connector::Handle, crtc::Handle, DrmMode)> = Vec::new();

                for conn_handle in res.connectors() {
                    let Ok(conn) = drm.get_connector(*conn_handle, true) else {
                        continue;
                    };
                    if conn.state() != connector::State::Connected {
                        continue;
                    }
                    connected.push(*conn_handle);
                    if device.connectors.contains_key(conn_handle) {
                        continue; // already lit
                    }
                    // Prefer the connector's preferred mode, else its first.
                    let mode = conn
                        .modes()
                        .iter()
                        .find(|m| m.mode_type().contains(ModeTypeFlags::PREFERRED))
                        .or_else(|| conn.modes().first())
                        .copied();
                    let Some(mode) = mode else {
                        continue;
                    };
                    // A free CRTC reachable through one of the connector's encoders.
                    let crtc = conn.encoders().iter().find_map(|enc_handle| {
                        let enc = drm.get_encoder(*enc_handle).ok()?;
                        res.filter_crtcs(enc.possible_crtcs())
                            .into_iter()
                            .find(|crtc| !used.contains(crtc))
                    });
                    let Some(crtc) = crtc else {
                        continue;
                    };
                    used.insert(crtc);
                    to_add.push((*conn_handle, crtc, mode));
                }
                (connected, to_add)
            };

            // Phase 2: drop outputs whose connector is gone.
            let removed: Vec<connector::Handle> = device
                .connectors
                .keys()
                .copied()
                .filter(|conn| !connected.contains(conn))
                .collect();
            for conn in removed {
                if let Some(crtc) = device.connectors.remove(&conn) {
                    if let Some(surface) = device.surfaces.remove(&crtc) {
                        crate::server::remove_output_global(&dh, surface.global);
                    }
                    changed = true;
                    println!("compositor: display on {conn:?} unplugged");
                }
            }

            // Phase 3: light the newly connected displays, each its own DrmCompositor
            // over a fresh dumb-buffer allocator on the shared device fd.
            for (conn, crtc, mode) in to_add {
                let planes = device.drm.planes(&crtc).ok();
                let Ok(conn_info) = device.drm.get_connector(conn, false) else {
                    continue;
                };
                let output = make_output(&conn_info, &mode);
                let surface = match device.drm.create_surface(crtc, mode, &[conn]) {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("compositor: create surface: {e}");
                        continue;
                    }
                };
                // No gbm device (None): the cursor plane it would feed is unused, the
                // cursor composites into the frame instead.
                let compositor = SoftCompositor::new(
                    &output,
                    surface,
                    planes,
                    DumbAllocator::new(device.drm_fd.clone()),
                    device.drm_fd.clone(),
                    COLOR_FORMATS.iter().copied(),
                    device.render_formats.iter().copied(),
                    device.drm.cursor_size(),
                    None,
                );
                match compositor {
                    Ok(drm) => {
                        let (w, h) = mode.size();
                        let global = crate::server::create_output_global(&dh, &output);
                        device.surfaces.insert(
                            crtc,
                            OutputSurface {
                                drm,
                                output,
                                global,
                                pending: false,
                            },
                        );
                        device.connectors.insert(conn, crtc);
                        changed = true;
                        println!("compositor: display on {conn:?} lit at {w}x{h}");
                    }
                    Err(e) => eprintln!("compositor: drm compositor: {e}"),
                }
            }
        }

        self.outputs_dirty |= changed;
    }

    // Recompute the left-to-right layout over every lit output and resync the
    // compositor's shared space to it: drop the old mapping, place each output at its
    // new logical position, and clamp the cursor to the whole span. Called from the
    // run loop (which holds the compositor) whenever the lit set changed.
    fn relayout(&mut self, comp: &mut Compositor) {
        // Gather every lit output across all devices in a stable order: the primary
        // device's outputs first (so the primary monitor sits at the origin, where new
        // windows open), then by connector name, so the arrangement is deterministic
        // across hotplug.
        let mut entries: Vec<(bool, String, Output)> = self
            .devices
            .iter()
            .flat_map(|(node, device)| {
                let primary = self.primary == Some(*node);
                device
                    .surfaces
                    .values()
                    .map(move |s| (primary, s.output.name(), s.output.clone()))
            })
            .collect();
        entries.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
        let outputs: Vec<Output> = entries.into_iter().map(|(_, _, output)| output).collect();
        // Lay outputs out by their logical size (mode divided by scale), since the
        // shared space, the windows, and the cursor are all in logical units.
        let sizes: Vec<(i32, i32)> = outputs.iter().map(logical_size).collect();
        let positions = layout::arrange(&sizes);

        // Drop the previous arrangement, then install the new one.
        for old in self.mapped.drain(..) {
            comp.unmap_output(&old);
        }
        for (output, &(x, y)) in outputs.iter().zip(positions.iter()) {
            comp.map_output(output, x, y);
            self.mapped.push(output.clone());
        }

        // The cursor roams the whole desktop; never let the clamp box collapse.
        let (w, h) = layout::span(&sizes);
        self.output_size = Size::from((w.max(1), h.max(1)));

        // Each real monitor is now advertised on its own, so retire the placeholder
        // global; if every monitor went dark, restore it so a client still sees one.
        comp.set_placeholder_global(outputs.is_empty());
        self.outputs_dirty = false;
    }

    // Rescan `/dev/input` and reconcile the path backend with it: add every evdev node
    // not already handed to libinput, and remove ones whose node has vanished. Each is
    // opened through the session interface (libseat), so no real root and no udev
    // daemon are needed. Called once at startup and on the rescan timer (input
    // hotplug). A node libinput rejects (not an input device) is recorded as absent so
    // it is not retried every tick.
    fn rescan_input(&mut self) {
        let mut present: HashSet<PathBuf> = HashSet::new();
        if let Ok(dir) = std::fs::read_dir("/dev/input") {
            let mut paths: Vec<PathBuf> = dir
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.starts_with("event"))
                })
                .collect();
            paths.sort();
            for p in paths {
                present.insert(p.clone());
                if self.known_inputs.contains_key(&p) {
                    continue;
                }
                let Some(s) = p.to_str() else { continue };
                // None means libinput would not take it (not an input device);
                // recorded either way so the rescan does not retry it every tick.
                let dev = self.libinput.path_add_device(s);
                if dev.is_some() {
                    println!("compositor: input {s} added");
                }
                self.known_inputs.insert(p, dev);
            }
        }
        // Remove devices whose node has vanished (unplugged).
        let gone: Vec<PathBuf> = self
            .known_inputs
            .keys()
            .filter(|p| !present.contains(*p))
            .cloned()
            .collect();
        for p in gone {
            if let Some(Some(dev)) = self.known_inputs.remove(&p) {
                self.libinput.path_remove_device(dev);
                println!("compositor: input {} removed", p.display());
            }
        }
    }
}

// Describe a connected connector and its mode as a smithay Output, used as a surface's
// mode source. The caller advertises its wl_output global once the surface initializes
// (in scan_connectors). The output's scale is derived from the panel's pixel density
// (`layout::scale_for`), so a HiDPI monitor is advertised at 2x and renders its region
// at 2x, while occupying half its pixel size in the shared logical layout.
fn make_output(conn: &connector::Info, mode: &DrmMode) -> Output {
    let name = format!("{:?}-{}", conn.interface(), conn.interface_id());
    let (phys_w, phys_h) = conn.size().unwrap_or((0, 0));
    let output = Output::new(
        name,
        PhysicalProperties {
            size: (phys_w as i32, phys_h as i32).into(),
            subpixel: Subpixel::Unknown,
            make: "Horizon".into(),
            model: "DRM".into(),
        },
    );
    let (w, h) = mode.size();
    let wl_mode = OutputMode {
        size: (w as i32, h as i32).into(),
        // drm reports the refresh in Hz; smithay's mode is in mHz.
        refresh: mode.vrefresh() as i32 * 1000,
    };
    let scale = layout::scale_for((w as i32, h as i32), (phys_w as i32, phys_h as i32));
    output.change_current_state(
        Some(wl_mode),
        Some(Transform::Normal),
        Some(Scale::Integer(scale)),
        Some((0, 0).into()),
    );
    output.set_preferred(wl_mode);
    output
}

// An output's logical size: its physical mode divided by its scale, rounded the same
// way smithay's `Space::output_geometry` does (ceil), so the layout advances by
// exactly the region each output renders.
fn logical_size(output: &Output) -> (i32, i32) {
    match output.current_mode() {
        Some(mode) => {
            let scale = output.current_scale().fractional_scale();
            let size = mode.size.to_f64().to_logical(scale).to_i32_ceil();
            (size.w, size.h)
        }
        None => (0, 0),
    }
}

// Translate one libinput event into a seat action on the compositor, the same routing
// the GLES backend and the headless test exercise. Smithay maps libinput's evdev
// keycodes up to xkb codes (evdev + 8), the same convention winit reports, so we map
// back to evdev for `keyboard_key` (which re-adds the offset). Button codes are raw
// evdev. Pointer motion is relative, so we accumulate it into a cursor clamped to the
// output span.
fn apply_input(
    comp: &mut Compositor,
    event: InputEvent<LibinputInputBackend>,
    cursor: &mut Point<f64, Logical>,
    output: Size<i32, Logical>,
) {
    match event {
        InputEvent::PointerMotion { event } => {
            cursor.x = (cursor.x + event.delta_x()).clamp(0.0, output.w as f64);
            cursor.y = (cursor.y + event.delta_y()).clamp(0.0, output.h as f64);
            comp.pointer_motion(cursor.x, cursor.y);
        }
        InputEvent::PointerMotionAbsolute { event } => {
            let pos = event.position_transformed(output);
            *cursor = pos;
            comp.pointer_motion(pos.x, pos.y);
        }
        InputEvent::PointerButton { event } => {
            comp.pointer_button(event.button_code(), event.state() == ButtonState::Pressed);
        }
        InputEvent::PointerAxis { event } => {
            let h = event.amount(Axis::Horizontal).unwrap_or(0.0);
            let v = event.amount(Axis::Vertical).unwrap_or(0.0);
            comp.pointer_axis(h, v);
        }
        InputEvent::Keyboard { event } => {
            let evdev = event.key_code().raw().saturating_sub(8);
            comp.keyboard_key(evdev, event.state() == KeyState::Pressed);
        }
        _ => {}
    }
}
