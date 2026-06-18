//! The bare-metal DRM/KMS + libinput backend: drive a real display directly off
//! the GPU, with no session to nest in. This is the path Horizon boots into on
//! hardware, where there is no Wayland or X server to host a nested window.
//!
//! It sits on the same split as the rest of the compositor, so almost nothing
//! here is new logic. The frame is [`space_render_elements`], the exact scene the
//! headless render test asserts on, handed to a Smithay `DrmOutput`; the input is
//! routed through the seat by the same [`Compositor`] methods the headless input
//! test drives. What is new is only the backend plumbing that a screen needs:
//! taking the GPU through a seat (libseat) so it works without real root, scanning
//! a connector and CRTC, a GBM-backed GLES renderer, page-flip-driven
//! presentation, and libinput for the keyboard and pointer. That plumbing needs a
//! real GPU and a seat, so, like the winit backend, it is compile-checked in CI
//! and eye-verified on bare metal.
//!
//! Single GPU, single output, no hotplug: the first connected connector is bound
//! at startup. Multi-GPU, connector hotplug, and VT-switch buffer recovery come
//! later; the seat routing and compositing they would feed already exist.

use std::time::{Duration, Instant};

use smithay::backend::allocator::gbm::{GbmAllocator, GbmBufferFlags, GbmDevice};
use smithay::backend::allocator::Fourcc;
use smithay::backend::drm::compositor::FrameFlags;
use smithay::backend::drm::exporter::gbm::GbmFramebufferExporter;
use smithay::backend::drm::output::{DrmOutput, DrmOutputManager, DrmOutputRenderElements};
use smithay::backend::drm::{DrmDevice, DrmDeviceFd, DrmEvent, DrmNode};
use smithay::backend::egl::context::ContextPriority;
use smithay::backend::input::{
    AbsolutePositionEvent, Axis, ButtonState, InputEvent, KeyState, KeyboardKeyEvent,
    PointerAxisEvent, PointerButtonEvent, PointerMotionEvent,
};
use smithay::backend::libinput::{LibinputInputBackend, LibinputSessionInterface};
use smithay::backend::renderer::element::surface::WaylandSurfaceRenderElement;
use smithay::backend::renderer::gles::GlesRenderer;
use smithay::backend::renderer::multigpu::gbm::GbmGlesBackend;
use smithay::backend::renderer::multigpu::{GpuManager, MultiRenderer};
use smithay::backend::renderer::Color32F;
use smithay::backend::session::libseat::LibSeatSession;
use smithay::backend::session::{Event as SessionEvent, Session};
use smithay::backend::udev;
use smithay::output::{Mode as OutputMode, Output, PhysicalProperties, Scale, Subpixel};
use smithay::reexports::calloop::{EventLoop, LoopHandle};
use smithay::reexports::drm::control::{
    connector, crtc, Device as ControlDevice, Mode as DrmMode, ModeTypeFlags,
};
use smithay::reexports::input::Libinput;
use smithay::reexports::rustix::fs::OFlags;
use smithay::utils::{DeviceFd, Logical, Point, Size, Transform};

use crate::render::space_render_elements;
use crate::{Compositor, Error, Result};

// The renderer is a single-GPU GBM/GLES backend driven through Smithay's
// multi-GPU manager: even with one card, `GpuManager` is the path that wires the
// EGL context, the dmabuf import, and the scanout formats together for us.
type GbmGles = GbmGlesBackend<GlesRenderer, DrmDeviceFd>;
type UdevRenderer<'a> = MultiRenderer<'a, 'a, GbmGles, GbmGles>;
type SceneElement<'a> = WaylandSurfaceRenderElement<UdevRenderer<'a>>;
type DrmAlloc = GbmAllocator<DrmDeviceFd>;
type DrmExport = GbmFramebufferExporter<DrmDeviceFd>;
type OutputManager = DrmOutputManager<DrmAlloc, DrmExport, (), DrmDeviceFd>;
type Surface = DrmOutput<DrmAlloc, DrmExport, (), DrmDeviceFd>;

// 8-bit scanout formats, which every GPU and panel handles; Horizon does not need
// the deeper formats yet. The order is the preference order for the swapchain.
const COLOR_FORMATS: &[Fourcc] = &[Fourcc::Argb8888, Fourcc::Xrgb8888];

// The backend's own resources, kept together so the event-loop sources (vblank,
// libinput, session) can reach them as the loop's shared data. The Wayland server
// itself stays in the `Compositor`, driven separately each iteration, exactly as
// the winit backend drives it; that is why the seat routing and scene here are the
// already-tested ones.
struct DrmBackend {
    // Held so the seat stays ours; dropping it would hand the GPU back.
    #[allow(dead_code)]
    session: LibSeatSession,
    gpus: GpuManager<GbmGles>,
    render_node: DrmNode,
    // Owns the DrmDevice; kept alive for the surface and the vblank source. Also
    // paused and reactivated across a VT switch.
    output_manager: OutputManager,
    surface: Surface,
    // The smithay Output describing the bound connector's mode, used as the
    // surface's mode source. Held for its lifetime.
    #[allow(dead_code)]
    output: Output,
    // The libinput context, kept for suspend/resume across a session change; the
    // event source holds its own clone.
    libinput: Libinput,
    // Input events drained and routed to the compositor after each dispatch, so a
    // calloop callback never has to borrow the compositor.
    input_events: Vec<InputEvent<LibinputInputBackend>>,
    // The cursor position in output-logical pixels; libinput pointer motion is
    // relative, so we accumulate and clamp it ourselves.
    cursor: Point<f64, Logical>,
    output_size: Size<i32, Logical>,
    // Whether the session owns the GPU right now (false while switched away).
    active: bool,
    // True between queue_frame and the vblank that retires it: do not draw another
    // frame until the page flip completes.
    frame_pending: bool,
}

/// Bring up the DRM/KMS backend and run it until the process is stopped. Drives
/// the Wayland server (`comp`) between frames, so clients connect and map exactly
/// as in the headless core; their windows are then scanned out to the screen.
pub(crate) fn run(comp: &mut Compositor) -> Result<()> {
    let mut event_loop: EventLoop<'static, DrmBackend> =
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

        // Service Wayland clients (accept, dispatch, flush) between frames.
        comp.dispatch(Some(Duration::ZERO))?;

        // Present a frame when the session is active and no page flip is pending.
        if backend.active && !backend.frame_pending {
            render(comp, &mut backend, start.elapsed())?;
        }
    }
}

// Composite the current scene and queue it for scan-out. Builds the same render
// elements the offscreen and winit paths build, then lets the `DrmOutput` clear,
// draw, and page-flip them onto the connector.
fn render(comp: &mut Compositor, backend: &mut DrmBackend, elapsed: Duration) -> Result<()> {
    let clear = Color32F::new(0.06, 0.06, 0.06, 1.0);
    let queued = {
        let mut renderer = backend
            .gpus
            .single_renderer(&backend.render_node)
            .map_err(|e| Error::Render(format!("renderer: {e}")))?;
        let elements = space_render_elements(&mut renderer, comp.space());
        let result = backend
            .surface
            .render_frame(&mut renderer, &elements, clear, FrameFlags::DEFAULT)
            .map_err(|e| Error::Render(format!("render frame: {e}")))?;
        !result.is_empty
    };

    // Only a frame with damage is queued; an empty one is retried next iteration
    // (the dispatch timeout paces it), so a newly mapped window still appears.
    if queued {
        backend
            .surface
            .queue_frame(())
            .map_err(|e| Error::Render(format!("queue frame: {e}")))?;
        backend.frame_pending = true;
    }

    // Let animating clients draw their next frame.
    comp.send_frames(elapsed.as_millis() as u32);
    Ok(())
}

// Build the backend: take the seat, open the primary GPU, scan a connector and
// CRTC, wire the GBM/GLES renderer and the DRM output, start libinput, and insert
// every event source into `loop_handle`.
fn setup(loop_handle: LoopHandle<'static, DrmBackend>) -> Result<DrmBackend> {
    // Become the session's DRM master via libseat, so opening the GPU and the
    // input devices works without real root.
    let (session, notifier) =
        LibSeatSession::new().map_err(|e| Error::Init(format!("libseat session: {e}")))?;
    let seat_name = session.seat();

    // Pick the primary GPU, falling back to the first DRM node udev reports.
    let gpu_path = udev::primary_gpu(&seat_name)
        .map_err(|e| Error::Init(format!("primary gpu: {e}")))?
        .or_else(|| {
            udev::all_gpus(&seat_name)
                .ok()
                .and_then(|gpus| gpus.into_iter().next())
        })
        .ok_or_else(|| Error::Init("no GPU found".into()))?;
    let render_node =
        DrmNode::from_path(&gpu_path).map_err(|e| Error::Init(format!("drm node: {e}")))?;

    // Open the card through the session and wrap it for DRM and GBM.
    let mut open_session = session.clone();
    let fd = open_session
        .open(
            &gpu_path,
            OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOCTTY | OFlags::NONBLOCK,
        )
        .map_err(|e| Error::Init(format!("open {}: {e}", gpu_path.display())))?;
    let drm_fd = DrmDeviceFd::new(DeviceFd::from(fd));
    let (drm, drm_notifier) =
        DrmDevice::new(drm_fd.clone(), false).map_err(|e| Error::Init(format!("drm: {e}")))?;
    let gbm = GbmDevice::new(drm_fd).map_err(|e| Error::Init(format!("gbm: {e}")))?;

    // The GLES renderer over GBM, registered with the multi-GPU manager.
    let mut gpus = GpuManager::new(
        GbmGlesBackend::<GlesRenderer, DrmDeviceFd>::with_context_priority(ContextPriority::High),
    )
    .map_err(|e| Error::Render(format!("gpu manager: {e}")))?;
    gpus.as_mut()
        .add_node(render_node, gbm.clone())
        .map_err(|e| Error::Render(format!("add gpu node: {e}")))?;

    // Find a connected connector, its preferred mode, and a CRTC that can drive
    // it, then describe that as a smithay Output.
    let (connector_handle, crtc_handle, drm_mode) = pick_output(&drm)?;
    let conn_info = drm
        .get_connector(connector_handle, false)
        .map_err(|e| Error::Init(format!("connector info: {e}")))?;
    let output = make_output(&conn_info, &drm_mode);
    let planes = drm
        .planes(&crtc_handle)
        .map_err(|e| Error::Init(format!("planes: {e}")))?;

    // The swapchain allocator and the framebuffer exporter both ride the GBM
    // device; the renderer's own formats tell the manager what it can scan out.
    let allocator = GbmAllocator::new(
        gbm.clone(),
        GbmBufferFlags::RENDERING | GbmBufferFlags::SCANOUT,
    );
    let exporter = GbmFramebufferExporter::new(gbm.clone(), Some(render_node));

    let mut renderer = gpus
        .single_renderer(&render_node)
        .map_err(|e| Error::Render(format!("renderer: {e}")))?;
    let render_formats = renderer
        .as_mut()
        .egl_context()
        .dmabuf_render_formats()
        .clone();

    let mut output_manager: OutputManager = DrmOutputManager::new(
        drm,
        allocator,
        exporter,
        Some(gbm),
        COLOR_FORMATS.iter().copied(),
        render_formats,
    );

    // Bind the CRTC + connector + mode. An empty initial element set is fine: the
    // real elements come every frame from `render`.
    let init_elements: DrmOutputRenderElements<UdevRenderer, SceneElement> =
        DrmOutputRenderElements::default();
    let surface = output_manager
        .initialize_output(
            crtc_handle,
            drm_mode,
            &[connector_handle],
            &output,
            Some(planes),
            &mut renderer,
            &init_elements,
        )
        .map_err(|e| Error::Render(format!("initialize output: {e}")))?;
    drop(renderer); // release the borrow on `gpus` before the backend takes it

    // libinput, sharing the session so it opens input devices through the seat.
    let mut libinput = Libinput::new_with_udev(LibinputSessionInterface::from(session.clone()));
    libinput
        .udev_assign_seat(&seat_name)
        .map_err(|_| Error::Init("libinput seat assign failed".into()))?;
    let libinput_source = LibinputInputBackend::new(libinput.clone());

    // Session changes: a VT switch away pauses the GPU and input; coming back
    // reactivates them and forces a redraw.
    loop_handle
        .insert_source(notifier, |event, _, backend: &mut DrmBackend| match event {
            SessionEvent::PauseSession => {
                backend.libinput.suspend();
                backend.output_manager.pause();
                backend.active = false;
            }
            SessionEvent::ActivateSession => {
                if backend.libinput.resume().is_err() {
                    eprintln!("compositor: libinput resume failed");
                }
                if let Err(e) = backend.output_manager.activate(false) {
                    eprintln!("compositor: drm reactivate failed: {e}");
                }
                backend.active = true;
                backend.frame_pending = false;
            }
        })
        .map_err(|e| Error::Init(format!("insert session source: {e}")))?;

    // Page-flip completions: retire the queued frame so the next one can draw.
    loop_handle
        .insert_source(
            drm_notifier,
            |event, _, backend: &mut DrmBackend| match event {
                DrmEvent::VBlank(_crtc) => {
                    let _ = backend.surface.frame_submitted();
                    backend.frame_pending = false;
                }
                DrmEvent::Error(e) => eprintln!("compositor: drm error: {e}"),
            },
        )
        .map_err(|e| Error::Init(format!("insert drm source: {e}")))?;

    // Raw input: collected now, routed to the compositor after dispatch returns.
    loop_handle
        .insert_source(libinput_source, |event, _, backend: &mut DrmBackend| {
            backend.input_events.push(event);
        })
        .map_err(|e| Error::Init(format!("insert libinput source: {e}")))?;

    let (mode_w, mode_h) = drm_mode.size();
    let output_size = Size::<i32, Logical>::from((mode_w as i32, mode_h as i32));

    Ok(DrmBackend {
        session,
        gpus,
        render_node,
        output_manager,
        surface,
        output,
        libinput,
        input_events: Vec::new(),
        cursor: Point::from((output_size.w as f64 / 2.0, output_size.h as f64 / 2.0)),
        output_size,
        active: true,
        frame_pending: false,
    })
}

// Scan the device for the first connected connector with a usable mode and a CRTC
// that can drive it. Returns the connector, the CRTC, and the mode to set.
fn pick_output(drm: &DrmDevice) -> Result<(connector::Handle, crtc::Handle, DrmMode)> {
    let res = drm
        .resource_handles()
        .map_err(|e| Error::Init(format!("drm resources: {e}")))?;

    for conn_handle in res.connectors() {
        let conn = match drm.get_connector(*conn_handle, true) {
            Ok(conn) => conn,
            Err(_) => continue,
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
        // Find a CRTC reachable through one of the connector's encoders.
        for enc_handle in conn.encoders() {
            let Ok(enc) = drm.get_encoder(*enc_handle) else {
                continue;
            };
            if let Some(crtc) = res.filter_crtcs(enc.possible_crtcs()).into_iter().next() {
                return Ok((*conn_handle, crtc, mode));
            }
        }
    }

    Err(Error::Init("no connected display found".into()))
}

// Describe a bound connector and mode as a smithay Output, used as the surface's
// mode source. No global is created: the compositor already advertises its output
// to clients; this one only carries the geometry the surface scans out at.
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
    output.change_current_state(
        Some(wl_mode),
        Some(Transform::Normal),
        Some(Scale::Integer(1)),
        Some((0, 0).into()),
    );
    output.set_preferred(wl_mode);
    output
}

// Translate one libinput event into a seat action on the compositor, the same
// routing the winit backend and the headless test exercise. Smithay maps
// libinput's evdev keycodes up to xkb codes (evdev + 8), the same convention
// winit reports, so we map back to evdev for `keyboard_key` (which re-adds the
// offset). Button codes are raw evdev. Pointer motion is relative, so we
// accumulate it into a cursor clamped to the output.
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
