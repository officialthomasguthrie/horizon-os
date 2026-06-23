//! The software (pixman) DRM/KMS scanout backend: drive a real display through
//! KMS with no GPU in the path.
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
//! is new logic. The frame is [`space_render_elements`], the exact scene the
//! headless render test asserts on, handed to a Smithay `DrmCompositor`; the input
//! is the same seat routing the headless input test drives, now fed by libinput.
//! The one thing the GLES backend gets for free that this has to express itself is
//! the shell background: the GLES path draws it as a `MemoryRenderBufferRenderElement`,
//! which requires a `Send` texture the pixman one is not, so here it is a
//! [`TextureRenderElement`] over a cached pixman texture instead (no `Send` bound),
//! which is the only real difference from `drm.rs`.
//!
//! This first cut is single device, single output, no hotplug, exactly where the
//! GLES backend started before its multi-GPU/hotplug/VT-switch hardening; the same
//! hardening can follow here, over the same seat routing and compositing it already
//! shares. The KMS plumbing it does have, allocating the dumb buffers, exporting
//! them for pixman to bind, assigning planes, and the page-flip lifecycle, is all
//! Smithay's `DrmCompositor`, the same machinery the GLES backend trusts; only the
//! renderer and the buffer kind differ.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use smithay::backend::allocator::dumb::DumbAllocator;
use smithay::backend::allocator::Fourcc;
use smithay::backend::drm::compositor::{DrmCompositor, FrameFlags};
use smithay::backend::drm::{DrmDevice, DrmDeviceFd, DrmEvent};
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
use smithay::backend::udev::{self, UdevBackend};
use smithay::output::OutputModeSource;
use smithay::reexports::calloop::{EventLoop, LoopHandle, RegistrationToken};
use smithay::reexports::drm::control::{
    connector, crtc, Device as ControlDevice, Mode as DrmMode, ModeTypeFlags,
};
use smithay::reexports::input::Libinput;
use smithay::reexports::rustix::fs::OFlags;
use smithay::utils::{DeviceFd, Logical, Point, Scale, Size, Transform};

use crate::render::space_render_elements;
use crate::server::ShellEvent;
use crate::{Compositor, Error, Result};

// The scanout compositor for one output: a Smithay `DrmCompositor` parameterized
// for the no-GPU path. The allocator is `DumbAllocator` (dumb buffers, always
// linear CPU memory), the framebuffer exporter is the `DrmDeviceFd` itself (a
// dumb buffer is already a GEM object the device turns straight into a scanout
// framebuffer), the per-frame user data is `()`, and the device handle is the
// `DrmDeviceFd`. It is constructed with no gbm device and a pixman renderer, so no
// GLES context and no multi-GPU manager exist: one software renderer paints every
// frame into a dumb buffer.
type SoftCompositor = DrmCompositor<DumbAllocator, DrmDeviceFd, (), DrmDeviceFd>;

// A frame draws two kinds of element: client window surfaces and, behind them, the
// shell background. `DrmCompositor::render_frame` takes a homogeneous slice, so
// they unify into one enum. Unlike the GLES backend's `ShellElement` (whose
// background is a `MemoryRenderBufferRenderElement`, needing a `Send` texture), the
// background here is a `TextureRenderElement` over the pixman texture, which has no
// `Send` bound, so the concrete pixman renderer form of the macro is what fits.
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

// The backend's resources, shared with the event-loop sources as the loop data.
// The Wayland server stays in the `Compositor`, driven separately each iteration
// exactly as the winit and GLES loops drive it; that is why the seat routing and
// scene here are the already-tested ones.
struct SoftBackend {
    // Held so the seat stays ours for the backend's lifetime (dropping it would
    // release the session); the device and input were opened through it in setup,
    // and libinput keeps its own clone for suspend/resume across a VT switch.
    #[allow(dead_code)]
    session: LibSeatSession,
    // The one software renderer, held across frames (the offscreen readback path
    // makes a fresh one per call, but a present loop reuses textures, so this one
    // persists). It composites every frame into the dumb buffer the compositor
    // hands it.
    renderer: PixmanRenderer,
    // The single output's scanout compositor: owns the dumb-buffer swapchain, the
    // plane assignment, and the page-flip lifecycle.
    compositor: SoftCompositor,
    // The DRM vblank/error event source, kept for the loop's lifetime.
    #[allow(dead_code)]
    drm_token: RegistrationToken,
    // Kept for suspend/resume across a session change; the event source holds its
    // own clone.
    libinput: Libinput,
    // Input drained and routed to the compositor after each dispatch, so a calloop
    // callback never has to borrow the compositor.
    input_events: Vec<InputEvent<LibinputInputBackend>>,
    // The cursor position in output-logical pixels; libinput pointer motion is
    // relative, so we accumulate and clamp it ourselves.
    cursor: Point<f64, Logical>,
    // The output's logical size, the cursor clamp bound.
    output_size: Size<i32, Logical>,
    // The shell background as a cached pixman texture, drawn behind every window.
    // Rebuilt only when the compositor's background generation changes (an idle
    // desktop is not re-imported each frame), and carrying a stable id so the
    // compositor's damage tracking skips re-scanning out an unchanged frame.
    background: Option<TextureBuffer<PixmanTexture>>,
    // The compositor background generation `background` was built from.
    background_gen: u64,
    // True between queue_frame and the vblank that retires it: do not draw the next
    // frame until the page flip completes.
    pending: bool,
    // Whether the session owns the device right now (false while switched away).
    active: bool,
}

/// Bring up the software DRM/KMS backend and run it until the process is stopped.
/// Drives the Wayland server (`comp`) between frames, so clients connect and map
/// exactly as in the headless core; their windows are then scanned out to the
/// screen with no GPU in the path.
pub(crate) fn run(
    comp: &mut Compositor,
    mut on_shell: impl FnMut(ShellEvent) -> Option<Vec<u8>>,
) -> Result<()> {
    let mut event_loop: EventLoop<'static, SoftBackend> =
        EventLoop::try_new().map_err(|e| Error::Init(format!("event loop: {e}")))?;
    let mut backend = setup(event_loop.handle())?;

    let start = Instant::now();
    loop {
        // Service the backend's fd sources (vblank, libinput, session changes).
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

        // Service Wayland clients (accept, dispatch, flush) between frames.
        comp.dispatch(Some(Duration::ZERO))?;

        // Present, unless the previous frame is still on its way to the screen.
        if backend.active && !backend.pending {
            render(comp, &mut backend);
        }

        // Let animating clients draw their next frame.
        comp.send_frames(start.elapsed().as_millis() as u32);
    }
}

// Composite the current scene into the next dumb buffer and queue it for scanout.
// The window surfaces come from `space_render_elements` (the whole space from the
// origin, since this is a single output), and the shell background is appended last
// so it sits behind them (render_frame draws the element list front to back). An
// empty (undamaged) frame is not queued, so an idle desktop does no scanout work
// and the dispatch timeout paces the loop.
fn render(comp: &mut Compositor, backend: &mut SoftBackend) {
    let clear = Color32F::new(0.06, 0.06, 0.06, 1.0);
    // Rebuild the cached background texture if the shell changed it (cheap when
    // unchanged: just a generation compare).
    sync_background(comp, backend);

    let mut elements: Vec<ShellElement> =
        space_render_elements(&mut backend.renderer, comp.space())
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

    // `empty()` (not `DEFAULT`): never try to promote an element onto a hardware
    // plane for direct scanout. Direct scanout needs a buffer the device can scan
    // out by itself (a dmabuf), and here every element is CPU memory (a client's shm
    // surface, the pixman background texture), so a promotion could only ever fall
    // back to compositing anyway. Forcing everything through the renderer into the
    // one primary dumb buffer is both correct and what a software path should do.
    match backend.compositor.render_frame(
        &mut backend.renderer,
        &elements,
        clear,
        FrameFlags::empty(),
    ) {
        Ok(result) if !result.is_empty => match backend.compositor.queue_frame(()) {
            Ok(()) => backend.pending = true,
            Err(e) => eprintln!("compositor: queue frame: {e}"),
        },
        Ok(_) => {}
        Err(e) => eprintln!("compositor: render frame: {e}"),
    }
}

// Rebuild the cached background texture when the compositor's shell background
// changes (tracked by generation), so an unchanged desktop is imported at most
// once rather than every frame. A fresh `TextureBuffer` carries a new id, so the
// compositor's damage tracker redraws it once and then, while the id and geometry
// hold steady, treats it as unchanged and skips re-scanning out. The bytes are
// `Abgr8888` (R, G, B, A), what `glass::Pixmap` produces, drawn at native size at
// the output origin.
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

// Build the backend: take the seat, start libinput, open the one DRM device, light
// its first connected display, and wire the pixman renderer and the dumb-buffer
// scanout compositor. Single device, single output: enough for the QEMU boot and
// the common no-GPU machine, with multi-output and hotplug left to a later pass.
fn setup(loop_handle: LoopHandle<'static, SoftBackend>) -> Result<SoftBackend> {
    // Become the session's DRM master via libseat, so opening the device and the
    // input devices works without real root.
    let (session, notifier) =
        LibSeatSession::new().map_err(|e| Error::Init(format!("libseat session: {e}")))?;
    let seat_name = session.seat();

    // libinput, sharing the session so it opens input devices through the seat.
    let mut libinput = Libinput::new_with_udev(LibinputSessionInterface::from(session.clone()));
    libinput
        .udev_assign_seat(&seat_name)
        .map_err(|_| Error::Init("libinput seat assign failed".into()))?;
    let libinput_source = LibinputInputBackend::new(libinput.clone());

    // Session changes: a VT switch away pauses the device and input; coming back
    // reactivates them, resets the now-stale swapchain, and forces a full redraw.
    loop_handle
        .insert_source(
            notifier,
            |event, _, backend: &mut SoftBackend| match event {
                SessionEvent::PauseSession => {
                    backend.libinput.suspend();
                    backend.active = false;
                }
                SessionEvent::ActivateSession => {
                    if backend.libinput.resume().is_err() {
                        eprintln!("compositor: libinput resume failed");
                    }
                    // Drop the now-stale swapchain so the next frame reallocates and
                    // reprograms the mode; the in-flight frame's vblank never arrived.
                    backend.compositor.reset_buffers();
                    backend.pending = false;
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

    // Open the one KMS device through the session.
    let path = device_path(&seat_name)?;
    let fd = session
        .clone()
        .open(
            &path,
            OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOCTTY | OFlags::NONBLOCK,
        )
        .map_err(|e| Error::Init(format!("open {}: {e}", path.display())))?;
    let drm_fd = DrmDeviceFd::new(DeviceFd::from(fd));
    // disable_connectors true so the device starts from a known reset state.
    let (mut drm, drm_notifier) = DrmDevice::new(drm_fd.clone(), true)
        .map_err(|e| Error::Init(format!("drm {}: {e}", path.display())))?;

    // Pick the first connected connector, its preferred mode, and a CRTC that can
    // drive it, then create the KMS surface for that combination.
    let (conn, crtc, mode) = pick_output(&drm)?;
    let surface = drm
        .create_surface(crtc, mode, &[conn])
        .map_err(|e| Error::Init(format!("create surface: {e}")))?;

    // The pixman software renderer paints every frame; its dmabuf formats tell the
    // compositor what the dumb buffers it allocates can be bound as for compositing.
    let renderer = PixmanRenderer::new().map_err(|e| Error::Render(format!("pixman: {e}")))?;
    let render_formats = renderer.dmabuf_formats();

    // The static mode source: a single output at the connector's mode, scale 1, no
    // transform. The whole-space elements are built at scale 1, so this matches.
    let (w, h) = mode.size();
    let output_size = Size::<i32, Logical>::from((w as i32, h as i32));
    let mode_source = OutputModeSource::Static {
        size: Size::from((w as i32, h as i32)),
        scale: Scale::from(1.0),
        transform: Transform::Normal,
    };

    // The dumb-buffer scanout compositor. The allocator makes dumb buffers, the
    // device fd exports each as a scanout framebuffer, and there is no GBM device
    // (None): the cursor plane it would feed is unused (this backend composites the
    // cursor into the frame rather than driving a hardware cursor plane).
    let allocator = DumbAllocator::new(drm_fd.clone());
    let compositor: SoftCompositor = DrmCompositor::new(
        mode_source,
        surface,
        None,
        allocator,
        drm_fd.clone(),
        COLOR_FORMATS.iter().copied(),
        render_formats,
        (64, 64).into(),
        None,
    )
    .map_err(|e| Error::Init(format!("drm compositor: {e}")))?;

    // Vblanks retire the queued frame; errors are logged.
    let drm_token = loop_handle
        .insert_source(
            drm_notifier,
            |event, _, backend: &mut SoftBackend| match event {
                DrmEvent::VBlank(_crtc) => {
                    let _ = backend.compositor.frame_submitted();
                    backend.pending = false;
                }
                DrmEvent::Error(e) => eprintln!("compositor: drm error: {e}"),
            },
        )
        .map_err(|e| Error::Init(format!("insert drm source: {e}")))?;

    println!(
        "compositor: software scanout on {} at {w}x{h}",
        path.display()
    );

    Ok(SoftBackend {
        session,
        renderer,
        compositor,
        drm_token,
        libinput,
        input_events: Vec::new(),
        cursor: Point::from((output_size.w as f64 / 2.0, output_size.h as f64 / 2.0)),
        output_size,
        background: None,
        background_gen: 0,
        pending: false,
        active: true,
    })
}

// The path of the KMS device to drive: the seat's primary GPU if udev names one,
// else the first device udev lists. A no-GPU machine still has a KMS device (the
// display controller), which is what this opens.
fn device_path(seat_name: &str) -> Result<PathBuf> {
    if let Ok(Some(path)) = udev::primary_gpu(seat_name) {
        return Ok(path);
    }
    let udev_backend =
        UdevBackend::new(seat_name).map_err(|e| Error::Init(format!("udev: {e}")))?;
    let path = udev_backend
        .device_list()
        .next()
        .map(|(_, path)| path.to_path_buf());
    path.ok_or_else(|| Error::Init("no KMS device found".into()))
}

// Scan a device's connectors for the first connected display, returning its
// connector, a CRTC that can drive it, and its preferred mode (or first mode). The
// same selection the GLES backend's connector scan does, taking the first match
// since this backend lights one output.
fn pick_output(drm: &DrmDevice) -> Result<(connector::Handle, crtc::Handle, DrmMode)> {
    let res = drm
        .resource_handles()
        .map_err(|e| Error::Init(format!("drm resources: {e}")))?;

    for conn_handle in res.connectors() {
        let Ok(conn) = drm.get_connector(*conn_handle, true) else {
            continue;
        };
        if conn.state() != connector::State::Connected {
            continue;
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
        // A CRTC reachable through one of the connector's encoders.
        let crtc = conn.encoders().iter().find_map(|enc_handle| {
            let enc = drm.get_encoder(*enc_handle).ok()?;
            res.filter_crtcs(enc.possible_crtcs()).into_iter().next()
        });
        let Some(crtc) = crtc else {
            continue;
        };
        return Ok((*conn_handle, crtc, mode));
    }
    Err(Error::Init("no connected display found".into()))
}

// Translate one libinput event into a seat action on the compositor, the same
// routing the GLES backend and the headless test exercise. Smithay maps libinput's
// evdev keycodes up to xkb codes (evdev + 8), the same convention winit reports, so
// we map back to evdev for `keyboard_key` (which re-adds the offset). Button codes
// are raw evdev. Pointer motion is relative, so we accumulate it into a cursor
// clamped to the output.
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
