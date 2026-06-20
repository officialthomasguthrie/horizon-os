//! The bare-metal DRM/KMS + libinput backend: drive real displays directly off
//! the GPU(s), with no session to nest in. This is the path Horizon boots into on
//! hardware, where there is no Wayland or X server to host a nested window.
//!
//! It sits on the same split as the rest of the compositor, so almost nothing
//! here is new logic. The frame is [`space_render_elements`], the exact scene the
//! headless render test asserts on, handed to a Smithay `DrmOutput`; the input is
//! routed through the seat by the same [`Compositor`] methods the headless input
//! test drives, now fed by libinput. What is new is the backend plumbing a screen
//! needs, and that is the part that waits for hardware: taking the GPUs and input
//! devices through a seat (libseat) so it runs without real root, discovering the
//! GPUs off udev, scanning each one's connectors for a mode and a CRTC, GBM-backed
//! GLES renderers, and a page-flip present loop per output.
//!
//! Devices and connectors are tracked live off udev. Every GPU udev reports is
//! brought up (multi-GPU), a GPU hotplugged in or out is added or dropped, and
//! each device rescans its connectors when udev signals a change, so plugging or
//! unplugging a monitor lights or drops its output. A VT switch away and back is
//! recovered: every device and swapchain is reset on reactivation. Clients here
//! attach shm (CPU) buffers, so a window composites on whichever GPU drives the
//! output with no cross-GPU buffer sharing; a display-only secondary GPU (render
//! on one card, scan out on another) is the one multi-GPU case still left.
//!
//! Every output is placed in one shared logical space (a left-to-right
//! [`layout`](crate::layout)) and scans out its own region of the scene, so a real
//! multi-monitor desktop spans the screens instead of mirroring one onto all of
//! them, and the cursor roams the whole span. Each lit connector is advertised to
//! clients as its own `wl_output` global at its layout position and mode (created
//! when the connector is lit, withdrawn when it is unplugged or its GPU goes, the
//! placeholder retired while any real monitor exists), so a client enumerates the
//! real screens and learns where each one is. The window scene is shared; the shell
//! background is still drawn per output at its own origin (each monitor shows the
//! Glass desktop). Per-output scale is the remaining gap.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::{Duration, Instant};

use smithay::backend::allocator::gbm::{GbmAllocator, GbmBufferFlags, GbmDevice};
use smithay::backend::allocator::Fourcc;
use smithay::backend::drm::compositor::FrameFlags;
use smithay::backend::drm::exporter::gbm::GbmFramebufferExporter;
use smithay::backend::drm::output::{DrmOutput, DrmOutputManager, DrmOutputRenderElements};
use smithay::backend::drm::{DrmDevice, DrmDeviceFd, DrmEvent, DrmNode, NodeType};
use smithay::backend::egl::context::ContextPriority;
use smithay::backend::input::{
    AbsolutePositionEvent, Axis, ButtonState, InputEvent, KeyState, KeyboardKeyEvent,
    PointerAxisEvent, PointerButtonEvent, PointerMotionEvent,
};
use smithay::backend::libinput::{LibinputInputBackend, LibinputSessionInterface};
use smithay::backend::renderer::element::memory::{
    MemoryRenderBuffer, MemoryRenderBufferRenderElement,
};
use smithay::backend::renderer::element::surface::WaylandSurfaceRenderElement;
use smithay::backend::renderer::element::Kind;
use smithay::backend::renderer::gles::GlesRenderer;
use smithay::backend::renderer::multigpu::gbm::GbmGlesBackend;
use smithay::backend::renderer::multigpu::{GpuManager, MultiRenderer};
use smithay::backend::renderer::Color32F;
use smithay::backend::session::libseat::LibSeatSession;
use smithay::backend::session::{Event as SessionEvent, Session};
use smithay::backend::udev::{self, UdevBackend, UdevEvent};
use smithay::output::{Mode as OutputMode, Output, PhysicalProperties, Scale, Subpixel};
use smithay::reexports::calloop::{EventLoop, LoopHandle, RegistrationToken};
use smithay::reexports::drm::control::{
    connector, crtc, Device as ControlDevice, Mode as DrmMode, ModeTypeFlags,
};
use smithay::reexports::input::Libinput;
use smithay::reexports::rustix::fs::OFlags;
use smithay::reexports::wayland_server::backend::GlobalId;
use smithay::reexports::wayland_server::DisplayHandle;
use smithay::utils::{DeviceFd, Logical, Point, Size, Transform};

use crate::render::output_render_elements;
use crate::server::ShellEvent;
use crate::{layout, Compositor, Error, Result};

// The renderer is a GBM/GLES backend driven through Smithay's multi-GPU manager.
// One manager holds every GPU's node, so even the single-GPU case goes through
// the path that wires the EGL context, dmabuf import, and scanout formats.
type GbmGles = GbmGlesBackend<GlesRenderer, DrmDeviceFd>;
type UdevRenderer<'a> = MultiRenderer<'a, 'a, GbmGles, GbmGles>;
type SceneElement<'a> = WaylandSurfaceRenderElement<UdevRenderer<'a>>;
type DrmAlloc = GbmAllocator<DrmDeviceFd>;
type DrmExport = GbmFramebufferExporter<DrmDeviceFd>;
type OutputManager = DrmOutputManager<DrmAlloc, DrmExport, (), DrmDeviceFd>;
type DrmOut = DrmOutput<DrmAlloc, DrmExport, (), DrmDeviceFd>;

// A frame here draws two kinds of element: client window surfaces and, behind
// them, the shell background. `DrmOutput::render_frame` takes a homogeneous slice,
// so they unify into one enum. The background is a `MemoryRenderBufferRenderElement`
// (CPU bytes uploaded for scanout), the path the multi-GPU renderer's `Send`-able
// texture supports but the pixman one does not, which is why the offscreen/winit
// `paint_space` draws the background directly instead of as an element.
//
// In its own module because `render_elements!` expands to code that names a bare
// `Result`, which would otherwise resolve to this file's `crate::Result` alias
// (two of its arms then break); inside `elements` `Result` is still the std one.
mod elements {
    use smithay::backend::renderer::element::memory::MemoryRenderBufferRenderElement;
    use smithay::backend::renderer::element::render_elements;
    use smithay::backend::renderer::element::surface::WaylandSurfaceRenderElement;
    use smithay::backend::renderer::{ImportAll, ImportMem};

    render_elements! {
        pub ShellElement<R> where R: ImportMem + ImportAll;
        Surface = WaylandSurfaceRenderElement<R>,
        Background = MemoryRenderBufferRenderElement<R>,
    }
}
use elements::ShellElement;

// 8-bit scanout formats, which every GPU and panel handles; Horizon does not need
// the deeper formats yet. The order is the swapchain preference order.
const COLOR_FORMATS: &[Fourcc] = &[Fourcc::Argb8888, Fourcc::Xrgb8888];

// One lit output, driven by one CRTC.
struct OutputSurface {
    drm: DrmOut,
    // The smithay Output the DrmCompositor reads its mode/scale/transform from.
    // Also mapped into the compositor's shared `Space` (at its logical layout
    // position) so this surface scans out its own region of the scene.
    output: Output,
    // This monitor's `wl_output` global, so a client enumerates it at its layout
    // position and mode. Withdrawn when the connector is unplugged or its GPU goes.
    global: GlobalId,
    // True between queue_frame and the vblank that retires it: do not draw the
    // next frame on this output until the page flip completes.
    pending: bool,
}

// One GPU: its DRM output manager, the outputs lit on it, and the connector ->
// CRTC map a rescan diffs against. Dropping it tears down its outputs (each
// `DrmOut` releases its CRTC on drop) and closes the device.
struct Device {
    // This GPU's render node, the key into the shared GpuManager.
    render_node: DrmNode,
    // Declared before `output_manager` so the outputs drop first: each `DrmOut`
    // releases its CRTC cleanly while the device is still open, then the manager
    // closes the device.
    surfaces: HashMap<crtc::Handle, OutputSurface>,
    connectors: HashMap<connector::Handle, crtc::Handle>,
    output_manager: OutputManager,
    // The DRM vblank/error event source, removed when the GPU goes away.
    drm_token: RegistrationToken,
}

// The backend's resources, shared with the event-loop sources as the loop data.
// The Wayland server stays in the `Compositor`, driven separately each iteration
// exactly as the winit loop drives it; that is why the seat routing and scene here
// are the already-tested ones.
struct DrmBackend {
    // The Wayland display handle, to create and withdraw a `wl_output` global per
    // connector as monitors come and go (the connector scan has no compositor in
    // hand, only this).
    dh: DisplayHandle,
    // Held so the seat stays ours and to open the GPUs and input devices through.
    session: LibSeatSession,
    // The GPU clients are assumed to render on; its outputs set the cursor clamp.
    // None until the first GPU appears, then the first one seen if udev names no
    // primary.
    primary_gpu: Option<DrmNode>,
    gpus: GpuManager<GbmGles>,
    devices: HashMap<DrmNode, Device>,
    loop_handle: LoopHandle<'static, DrmBackend>,
    // Kept for suspend/resume across a session change; the event source holds its
    // own clone.
    libinput: Libinput,
    // Input drained and routed to the compositor after each dispatch, so a calloop
    // callback never has to borrow the compositor.
    input_events: Vec<InputEvent<LibinputInputBackend>>,
    // The cursor position in output-logical pixels; libinput pointer motion is
    // relative, so we accumulate and clamp it ourselves.
    cursor: Point<f64, Logical>,
    // Cursor clamp bounds: the whole multi-monitor span, so the pointer can cross
    // from one screen to the next instead of being trapped on the first.
    output_size: Size<i32, Logical>,
    // The outputs currently mapped into the compositor's shared space, so a
    // relayout can drop the old arrangement before installing the new one. Kept in
    // step with the lit surfaces across hotplug by `relayout`.
    mapped: Vec<Output>,
    // Set when the set of lit outputs changes (a monitor or GPU was plugged or
    // unplugged), so the next loop iteration recomputes the layout and remaps the
    // shared space. Cheap to leave true for a tick; relayout is a few map calls.
    outputs_dirty: bool,
    // The shell background uploaded for scanout, drawn behind every window. Shared
    // across every GPU and output (each imports it into its own renderer context
    // lazily, only re-uploading damaged regions). None when no background is set.
    background: Option<MemoryRenderBuffer>,
    // The compositor background generation `background` was built from, so an
    // unchanged desktop is rebuilt and re-uploaded at most once, not every frame.
    background_gen: u64,
    // Whether the session owns the GPUs right now (false while switched away).
    active: bool,
}

/// Bring up the DRM/KMS backend and run it until the process is stopped. Drives
/// the Wayland server (`comp`) between frames, so clients connect and map exactly
/// as in the headless core; their windows are then scanned out to every screen.
pub(crate) fn run(
    comp: &mut Compositor,
    mut on_shell: impl FnMut(ShellEvent) -> Option<Vec<u8>>,
) -> Result<()> {
    let mut event_loop: EventLoop<'static, DrmBackend> =
        EventLoop::try_new().map_err(|e| Error::Init(format!("event loop: {e}")))?;
    let mut backend = setup(event_loop.handle(), comp.display_handle())?;

    let start = Instant::now();
    loop {
        // Service the backend's fd sources (udev hotplug, vblank, libinput,
        // session changes).
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
        // clicked), set the new background, which the next frame uploads.
        if let Some((x, y)) = comp.take_shell_click() {
            if let Some(rgba) = on_shell(ShellEvent::Click(x, y)) {
                let (ow, oh) = comp.output_size();
                comp.set_shell_background(&rgba, ow, oh);
            }
        }

        // Keystrokes that arrived while no client held focus belong to the shell
        // (its command palette); the next frame uploads any redraw they cause.
        for key in comp.take_shell_keys() {
            if let Some(rgba) = on_shell(ShellEvent::Key(key)) {
                let (ow, oh) = comp.output_size();
                comp.set_shell_background(&rgba, ow, oh);
            }
        }

        // Offer a tick so the owner can poll for changes made outside the shell
        // (e.g. the audit log grew) and refresh the background; the next frame
        // uploads it. The owner rate-limits this, so an idle desktop pays only a
        // cheap check per iteration and re-uploads nothing.
        if let Some(rgba) = on_shell(ShellEvent::Tick) {
            let (ow, oh) = comp.output_size();
            comp.set_shell_background(&rgba, ow, oh);
        }

        // A monitor or GPU came or went: recompute the left-to-right layout and
        // remap the shared space before this frame, so each output scans out its
        // own region. Cheap and skipped when nothing changed.
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

// Composite the current scene onto every output of every GPU that is ready for a
// new frame. Each device renders with its own GLES renderer (client buffers are
// shm, so there is no cross-GPU import); only an output with damage is queued, an
// empty one is retried next iteration (the dispatch timeout paces it).
fn render_all(comp: &mut Compositor, backend: &mut DrmBackend) {
    let clear = Color32F::new(0.06, 0.06, 0.06, 1.0);
    // Rebuild the cached background upload if the shell changed it (cheap when
    // unchanged: just a generation compare).
    backend.sync_background(comp);
    for device in backend.devices.values_mut() {
        let mut renderer = match backend.gpus.single_renderer(&device.render_node) {
            Ok(renderer) => renderer,
            Err(e) => {
                eprintln!("compositor: renderer: {e}");
                continue;
            }
        };
        for surface in device.surfaces.values_mut() {
            if surface.pending {
                continue;
            }
            // This output's own region of the shared scene (only the windows that
            // fall on it, offset to its logical origin), then the shell background
            // appended last so it sits behind them (render_frame draws the element
            // list front to back). Built per output, not once per device, so each
            // screen shows its slice rather than the whole scene mirrored.
            let mut elements: Vec<ShellElement<UdevRenderer>> =
                output_render_elements(&mut renderer, comp.space(), &surface.output)
                    .into_iter()
                    .map(ShellElement::Surface)
                    .collect();
            if let Some(buffer) = &backend.background {
                match MemoryRenderBufferRenderElement::from_buffer(
                    &mut renderer,
                    (0.0, 0.0),
                    buffer,
                    None,
                    None,
                    None,
                    Kind::Unspecified,
                ) {
                    Ok(element) => elements.push(ShellElement::Background(element)),
                    Err(e) => eprintln!("compositor: background upload: {e}"),
                }
            }
            match surface
                .drm
                .render_frame(&mut renderer, &elements, clear, FrameFlags::DEFAULT)
            {
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

// Build the backend: take the seat, start the GPU manager and libinput, insert the
// session and udev sources, then bring up whatever GPUs are already present. Each
// GPU's connectors are scanned as it comes up; hotplug after that is driven by the
// udev source.
fn setup(loop_handle: LoopHandle<'static, DrmBackend>, dh: DisplayHandle) -> Result<DrmBackend> {
    // Become the session's DRM master via libseat, so opening the GPUs and the
    // input devices works without real root.
    let (session, notifier) =
        LibSeatSession::new().map_err(|e| Error::Init(format!("libseat session: {e}")))?;
    let seat_name = session.seat();

    // The GPU udev names as primary, if any; the first one seen becomes primary
    // otherwise (decided in device_added).
    let primary_gpu = udev::primary_gpu(&seat_name)
        .ok()
        .flatten()
        .and_then(|path| DrmNode::from_path(path).ok());

    let gpus = GpuManager::new(
        GbmGlesBackend::<GlesRenderer, DrmDeviceFd>::with_context_priority(ContextPriority::High),
    )
    .map_err(|e| Error::Render(format!("gpu manager: {e}")))?;

    // libinput, sharing the session so it opens input devices through the seat.
    let mut libinput = Libinput::new_with_udev(LibinputSessionInterface::from(session.clone()));
    libinput
        .udev_assign_seat(&seat_name)
        .map_err(|_| Error::Init("libinput seat assign failed".into()))?;
    let libinput_source = LibinputInputBackend::new(libinput.clone());

    // Session changes: a VT switch away pauses every GPU and input; coming back
    // reactivates them, resets the now-stale device and swapchains, and forces a
    // full redraw.
    loop_handle
        .insert_source(notifier, |event, _, backend: &mut DrmBackend| match event {
            SessionEvent::PauseSession => {
                backend.libinput.suspend();
                for device in backend.devices.values_mut() {
                    device.output_manager.pause();
                }
                backend.active = false;
            }
            SessionEvent::ActivateSession => {
                if backend.libinput.resume().is_err() {
                    eprintln!("compositor: libinput resume failed");
                }
                for device in backend.devices.values_mut() {
                    // activate(true) re-acquires master and reset_state()s the
                    // device and every surface; reset_buffers drops the swapchain
                    // so the next frame reallocates and reprograms the mode.
                    if let Err(e) = device.output_manager.activate(true) {
                        eprintln!("compositor: drm reactivate failed: {e}");
                    }
                    for surface in device.surfaces.values_mut() {
                        surface.drm.reset_buffers();
                        // The in-flight frame's vblank never arrived while paused.
                        surface.pending = false;
                    }
                }
                backend.active = true;
            }
        })
        .map_err(|e| Error::Init(format!("insert session source: {e}")))?;

    // Raw input: collected now, routed to the compositor after dispatch returns.
    loop_handle
        .insert_source(libinput_source, |event, _, backend: &mut DrmBackend| {
            backend.input_events.push(event);
        })
        .map_err(|e| Error::Init(format!("insert libinput source: {e}")))?;

    // GPU discovery and hotplug. The current devices are listed now; later add /
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
            |event, _, backend: &mut DrmBackend| match event {
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

    let mut backend = DrmBackend {
        dh,
        session,
        primary_gpu,
        gpus,
        devices: HashMap::new(),
        loop_handle,
        libinput,
        input_events: Vec::new(),
        cursor: Point::from((0.0, 0.0)),
        output_size: Size::from((1920, 1080)),
        mapped: Vec::new(),
        outputs_dirty: false,
        background: None,
        background_gen: 0,
        active: true,
    };

    // Bring up the GPUs that are already plugged in.
    for (device_id, path) in initial {
        if let Ok(node) = DrmNode::from_dev_id(device_id) {
            backend.device_added(node, &path);
        }
    }
    if backend.devices.is_empty() {
        eprintln!("compositor: no GPU found yet; waiting for one to appear");
    }

    // Start the cursor centered on the primary output.
    backend.cursor = Point::from((
        backend.output_size.w as f64 / 2.0,
        backend.output_size.h as f64 / 2.0,
    ));

    Ok(backend)
}

impl DrmBackend {
    // Rebuild the cached background upload when the compositor's shell background
    // changes (tracked by generation), so an unchanged desktop is uploaded at most
    // once rather than every frame. A fresh `MemoryRenderBuffer` carries full damage
    // and a new id, so the next frame redraws; the old upload's textures are freed
    // when it drops. The bytes are `Abgr8888` (R, G, B, A), what `glass::Pixmap`
    // produces, drawn at the buffer's native size at the output origin.
    fn sync_background(&mut self, comp: &Compositor) {
        let generation = comp.background_generation();
        if generation == self.background_gen {
            return;
        }
        self.background_gen = generation;
        self.background = comp.background().map(|bg| {
            MemoryRenderBuffer::from_slice(
                bg.rgba(),
                Fourcc::Abgr8888,
                (bg.width(), bg.height()),
                1,
                Transform::Normal,
                None,
            )
        });
    }

    // Bring a GPU online: open it through the session, wire a GBM/GLES renderer and
    // a DRM output manager, register its vblank source, and scan its connectors for
    // displays to light. A failure on one GPU is logged and skipped, not fatal: the
    // others still run.
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
        let gbm = match GbmDevice::new(drm_fd) {
            Ok(gbm) => gbm,
            Err(e) => {
                eprintln!("compositor: gbm {}: {e}", path.display());
                return;
            }
        };

        // The render node for this GPU, falling back to its primary node if it
        // exposes no separate render node.
        let render_node = node
            .node_with_type(NodeType::Render)
            .and_then(|r| r.ok())
            .unwrap_or(node);

        if let Err(e) = self.gpus.as_mut().add_node(render_node, gbm.clone()) {
            eprintln!("compositor: add gpu {}: {e}", path.display());
            return;
        }

        // The swapchain allocator and the framebuffer exporter both ride the GBM
        // device; the renderer's own formats tell the manager what it can scan out.
        let allocator = GbmAllocator::new(
            gbm.clone(),
            GbmBufferFlags::RENDERING | GbmBufferFlags::SCANOUT,
        );
        let exporter = GbmFramebufferExporter::new(gbm.clone(), Some(render_node));

        let render_formats = match self.gpus.single_renderer(&render_node) {
            Ok(mut renderer) => renderer
                .as_mut()
                .egl_context()
                .dmabuf_render_formats()
                .clone(),
            Err(e) => {
                eprintln!("compositor: renderer {}: {e}", path.display());
                self.gpus.as_mut().remove_node(&render_node);
                return;
            }
        };

        let output_manager: OutputManager = DrmOutputManager::new(
            drm,
            allocator,
            exporter,
            Some(gbm),
            COLOR_FORMATS.iter().copied(),
            render_formats,
        );

        // Vblanks retire the queued frame on the matching output; errors are
        // logged. The captured node names the device in the shared loop data.
        let drm_token = match self.loop_handle.insert_source(
            drm_notifier,
            move |event, _, backend: &mut DrmBackend| match event {
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
                self.gpus.as_mut().remove_node(&render_node);
                return;
            }
        };

        if self.primary_gpu.is_none() {
            self.primary_gpu = Some(node);
        }
        self.devices.insert(
            node,
            Device {
                render_node,
                output_manager,
                surfaces: HashMap::new(),
                connectors: HashMap::new(),
                drm_token,
            },
        );

        self.scan_connectors(node);
    }

    // A GPU was unplugged: drop its device (which tears down its outputs and closes
    // the card), drop its renderer node, and remove its vblank source.
    fn device_removed(&mut self, node: DrmNode) {
        let Some(device) = self.devices.remove(&node) else {
            return;
        };
        // Withdraw the wl_output global of every monitor this GPU drove, so clients
        // stop enumerating them; the surfaces drop with the device.
        for surface in device.surfaces.values() {
            crate::server::remove_output_global(&self.dh, surface.global.clone());
        }
        self.gpus.as_mut().remove_node(&device.render_node);
        self.loop_handle.remove(device.drm_token);
        if self.primary_gpu == Some(node) {
            self.primary_gpu = self.devices.keys().next().copied();
        }
        // Its outputs are gone, so the shared-space layout must be recomputed.
        self.outputs_dirty = true;
        println!("compositor: GPU {node:?} removed");
        // device (and its outputs) drop here.
    }

    // udev signalled this GPU changed (a connector was plugged or unplugged):
    // rescan its connectors.
    fn device_changed(&mut self, node: DrmNode) {
        if self.devices.contains_key(&node) {
            self.scan_connectors(node);
        }
    }

    // Diff a device's connectors against what is lit: light a newly connected
    // display on a free CRTC, drop the output of one that was unplugged. Called
    // when the GPU comes up and whenever udev signals it changed.
    fn scan_connectors(&mut self, node: DrmNode) {
        let mut changed = false;
        // Cloned up front so the global create/withdraw below borrow the handle,
        // not `self`, while `device` holds a mutable borrow of `self.devices`.
        let dh = self.dh.clone();

        {
            let Some(device) = self.devices.get_mut(&node) else {
                return;
            };
            let mut renderer = match self.gpus.single_renderer(&device.render_node) {
                Ok(renderer) => renderer,
                Err(e) => {
                    eprintln!("compositor: renderer for scan: {e}");
                    return;
                }
            };

            // Phase 1: read the current connector layout. Which connectors are
            // connected, and for each one not yet lit, a free CRTC and a mode.
            let (connected, to_add) = {
                let drm = device.output_manager.device();
                let res = match drm.resource_handles() {
                    Ok(res) => res,
                    Err(e) => {
                        eprintln!("compositor: drm resources: {e}");
                        return;
                    }
                };
                // CRTCs already driving an output, plus ones picked in this pass.
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
                    // Dropping the surface drops the DrmOut (freeing the CRTC); first
                    // withdraw the monitor's wl_output global so clients stop seeing it.
                    if let Some(surface) = device.surfaces.remove(&crtc) {
                        crate::server::remove_output_global(&dh, surface.global);
                    }
                    changed = true;
                    println!("compositor: display on {conn:?} unplugged");
                }
            }

            // Phase 3: light the newly connected displays.
            let init: DrmOutputRenderElements<UdevRenderer, SceneElement> =
                DrmOutputRenderElements::default();
            for (conn, crtc, mode) in to_add {
                let planes = device.output_manager.device().planes(&crtc).ok();
                let Ok(conn_info) = device.output_manager.device().get_connector(conn, false)
                else {
                    continue;
                };
                let output = make_output(&conn_info, &mode);
                match device.output_manager.initialize_output(
                    crtc,
                    mode,
                    &[conn],
                    &output,
                    planes,
                    &mut renderer,
                    &init,
                ) {
                    Ok(drm) => {
                        let (w, h) = mode.size();
                        // Advertise this monitor to clients as its own wl_output. Its
                        // layout position is set when relayout maps it into the space.
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
                    Err(e) => eprintln!("compositor: initialize output: {e}"),
                }
            }
        }

        // The lit set changed, so the shared-space layout needs recomputing on the
        // next loop iteration (where the compositor is in hand to map into).
        self.outputs_dirty |= changed;
    }

    // Recompute the left-to-right layout over every lit output and resync the
    // compositor's shared space to it: drop the old mapping, place each output at
    // its new logical position, and clamp the cursor to the whole span. Called from
    // the run loop (which holds the compositor) whenever the lit set changed.
    fn relayout(&mut self, comp: &mut Compositor) {
        // Gather every lit output across all GPUs in a stable order: the primary
        // GPU's outputs first (so the primary monitor sits at the origin, where new
        // windows open), then by connector name, so the arrangement is
        // deterministic across hotplug.
        let mut entries: Vec<(bool, String, Output)> = self
            .devices
            .iter()
            .flat_map(|(node, device)| {
                let primary = self.primary_gpu == Some(*node);
                device
                    .surfaces
                    .values()
                    .map(move |s| (primary, s.output.name(), s.output.clone()))
            })
            .collect();
        entries.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
        let outputs: Vec<Output> = entries.into_iter().map(|(_, _, output)| output).collect();
        let sizes: Vec<(i32, i32)> = outputs
            .iter()
            .map(|o| {
                o.current_mode()
                    .map(|m| (m.size.w, m.size.h))
                    .unwrap_or((0, 0))
            })
            .collect();
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
}

// Describe a connected connector and its mode as a smithay Output, used as a
// surface's mode source. The caller advertises its wl_output global once the
// surface initializes (in scan_connectors); this just carries the geometry the
// surface scans out and the global reports.
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
// libinput's evdev keycodes up to xkb codes (evdev + 8), the same convention winit
// reports, so we map back to evdev for `keyboard_key` (which re-adds the offset).
// Button codes are raw evdev. Pointer motion is relative, so we accumulate it into
// a cursor clamped to the output.
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
