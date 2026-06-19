//! The headless Wayland server: Smithay protocol state, the handler glue that
//! makes a client's window appear in the scene, and the event loop that drives
//! it. Owned by the `Compositor` type re-exported from the crate root.

use std::ffi::{OsStr, OsString};
use std::os::fd::AsFd;
use std::sync::Arc;
use std::time::{Duration, Instant};

use smithay::backend::input::{Axis, AxisSource, ButtonState, KeyState};
use smithay::desktop::{Space, Window, WindowSurfaceType};
use smithay::input::keyboard::{FilterResult, Keycode};
use smithay::input::pointer::{AxisFrame, ButtonEvent, CursorImageStatus, MotionEvent};
use smithay::input::{Seat, SeatHandler, SeatState};
use smithay::output::{Mode, Output, PhysicalProperties, Scale, Subpixel};
use smithay::reexports::calloop::generic::Generic;
use smithay::reexports::calloop::{EventLoop, Interest, Mode as CalloopMode, PostAction};
use smithay::reexports::wayland_protocols::xdg::shell::server::xdg_toplevel;
use smithay::reexports::wayland_server::backend::{ClientData, ClientId, DisconnectReason};
use smithay::reexports::wayland_server::protocol::wl_buffer::WlBuffer;
use smithay::reexports::wayland_server::protocol::wl_seat::WlSeat;
use smithay::reexports::wayland_server::protocol::wl_shm;
use smithay::reexports::wayland_server::protocol::wl_surface::WlSurface;
use smithay::reexports::wayland_server::{Client, Display, DisplayHandle};
use smithay::utils::{Logical, Point, Serial, Transform, SERIAL_COUNTER};
use smithay::wayland::buffer::BufferHandler;
use smithay::wayland::compositor::{
    with_states, CompositorClientState, CompositorHandler, CompositorState,
};
use smithay::wayland::output::{OutputHandler, OutputManagerState};
use smithay::wayland::shell::xdg::{
    PopupSurface, PositionerState, ToplevelSurface, XdgShellHandler, XdgShellState,
    XdgToplevelSurfaceData,
};
use smithay::wayland::shm::{ShmHandler, ShmState};
use smithay::wayland::socket::ListeningSocketSource;
use smithay::{
    delegate_compositor, delegate_output, delegate_seat, delegate_shm, delegate_xdg_shell,
};

use crate::{Error, Result};

// Everything the protocol handlers touch. The `Compositor` keeps this next to
// the `Display` so dispatch can hand it to both calloop and the Wayland core.
struct State {
    dh: DisplayHandle,
    compositor: CompositorState,
    shm: ShmState,
    xdg: XdgShellState,
    seats: SeatState<State>,
    // The seat carries the keyboard and pointer; the input methods below drive
    // it. The output global is advertised for its lifetime and held so it is not
    // withdrawn (we do not read `outputs` back: there is only the one output).
    seat: Seat<State>,
    #[allow(dead_code)]
    outputs: OutputManagerState,
    #[allow(dead_code)]
    output: Output,
    space: Space<Window>,
    // The shell background: the L5 home surface (Horizon draws Glass here) painted
    // behind every client window. None paints the clear color. Render-gated, since
    // drawing it needs a renderer.
    #[cfg(feature = "render")]
    background: Option<crate::render::ShellBackground>,
    // Where the next toplevel is placed. Without a real layout we just step
    // windows across so several are distinct in the scene.
    next_x: i32,
    // Last pointer position in output-logical pixels, so a click can pick the
    // window under the cursor for keyboard focus.
    pointer_loc: Point<f64, Logical>,
    // A press that landed on no client window (the shell background) records its
    // position here, in output-logical pixels, for the owner to resolve against
    // whatever it drew there (Horizon maps it to a Glass action). Taken and
    // cleared by `take_shell_click`. Not render-gated: this is input, not drawing.
    pending_shell_click: Option<(i32, i32)>,
    // Monotonic base for input event timestamps.
    start: Instant,
}

impl State {
    // The window in the scene backing this surface, if any. Used to drive the
    // initial configure and to unmap on destroy.
    fn window_for(&self, surface: &WlSurface) -> Option<Window> {
        self.space
            .elements()
            .find(|w| w.toplevel().map(|t| t.wl_surface()) == Some(surface))
            .cloned()
    }
}

// Input routing. A display/input backend feeds the compositor raw events (the
// winit backend now, a libinput one on bare metal later); a headless test drives
// the same methods directly. The seat does the wire work (sending enter/leave,
// motion, keys); these decide where each event lands: pointer focus follows the
// cursor, a click focuses the window under it, and keys go to that focus.
impl State {
    fn now_ms(&self) -> u32 {
        self.start.elapsed().as_millis() as u32
    }

    // The client surface under a point in output space, with its location, or
    // None over empty space. This is the pointer's focus target.
    fn surface_under(&self, pos: Point<f64, Logical>) -> Option<(WlSurface, Point<f64, Logical>)> {
        let (window, win_loc) = self.space.element_under(pos)?;
        let (surface, surf_loc) =
            window.surface_under(pos - win_loc.to_f64(), WindowSurfaceType::ALL)?;
        Some((surface, (win_loc + surf_loc).to_f64()))
    }

    // Give the keyboard to the toplevel under `pos` (click to focus): raise it,
    // mark it activated and the rest not, and point the keyboard at it. Over
    // empty space this clears focus.
    fn focus_at(&mut self, pos: Point<f64, Logical>, serial: Serial) {
        let window = self.space.element_under(pos).map(|(w, _)| w.clone());
        if let Some(window) = &window {
            self.space.raise_element(window, true);
        }
        let target = window
            .as_ref()
            .and_then(|w| w.toplevel())
            .map(|t| t.wl_surface().clone());
        for w in self.space.elements() {
            let Some(toplevel) = w.toplevel() else {
                continue;
            };
            let active = Some(toplevel.wl_surface()) == target.as_ref();
            toplevel.with_pending_state(|s| {
                if active {
                    s.states.set(xdg_toplevel::State::Activated);
                } else {
                    s.states.unset(xdg_toplevel::State::Activated);
                }
            });
            // Only sends if the activation actually changed.
            toplevel.send_pending_configure();
        }
        if let Some(keyboard) = self.seat.get_keyboard() {
            keyboard.set_focus(self, target, serial);
        }
    }

    fn pointer_motion(&mut self, x: f64, y: f64) {
        let pos = Point::<f64, Logical>::from((x, y));
        self.pointer_loc = pos;
        let Some(pointer) = self.seat.get_pointer() else {
            return;
        };
        let focus = self.surface_under(pos);
        let serial = SERIAL_COUNTER.next_serial();
        let time = self.now_ms();
        pointer.motion(
            self,
            focus,
            &MotionEvent {
                location: pos,
                serial,
                time,
            },
        );
        pointer.frame(self);
    }

    fn pointer_button(&mut self, button: u32, pressed: bool) {
        let Some(pointer) = self.seat.get_pointer() else {
            return;
        };
        let serial = SERIAL_COUNTER.next_serial();
        let time = self.now_ms();
        let state = if pressed {
            ButtonState::Pressed
        } else {
            ButtonState::Released
        };
        // A press picks the keyboard focus from the window under the cursor; a
        // press on no window at all is a click on the shell background, recorded
        // for the owner to resolve (Horizon maps it through the Glass scene).
        if pressed {
            let loc = self.pointer_loc;
            if self.space.element_under(loc).is_none() {
                self.pending_shell_click = Some((loc.x as i32, loc.y as i32));
            }
            self.focus_at(loc, serial);
        }
        pointer.button(
            self,
            &ButtonEvent {
                serial,
                time,
                button,
                state,
            },
        );
        pointer.frame(self);
    }

    fn pointer_axis(&mut self, horizontal: f64, vertical: f64) {
        let Some(pointer) = self.seat.get_pointer() else {
            return;
        };
        let mut frame = AxisFrame::new(self.now_ms()).source(AxisSource::Continuous);
        if horizontal != 0.0 {
            frame = frame.value(Axis::Horizontal, horizontal);
        }
        if vertical != 0.0 {
            frame = frame.value(Axis::Vertical, vertical);
        }
        pointer.axis(self, frame);
        pointer.frame(self);
    }

    fn keyboard_key(&mut self, keycode: u32, pressed: bool) {
        let Some(keyboard) = self.seat.get_keyboard() else {
            return;
        };
        let serial = SERIAL_COUNTER.next_serial();
        let time = self.now_ms();
        let state = if pressed {
            KeyState::Pressed
        } else {
            KeyState::Released
        };
        // Evdev keycodes sit 8 below the X keymap codes xkb compiles to; the
        // wire event is mapped back down by the seat.
        keyboard.input::<(), _>(
            self,
            Keycode::from(keycode + 8),
            state,
            serial,
            time,
            |_, _, _| FilterResult::Forward,
        );
    }
}

impl CompositorHandler for State {
    fn compositor_state(&mut self) -> &mut CompositorState {
        &mut self.compositor
    }

    fn client_compositor_state<'a>(&self, client: &'a Client) -> &'a CompositorClientState {
        &client.get_data::<ClientState>().unwrap().compositor
    }

    fn commit(&mut self, surface: &WlSurface) {
        // Track the committed buffer so the renderer can import it. Only the
        // render/winit features paint, so the headless core skips this.
        #[cfg(feature = "render")]
        smithay::backend::renderer::utils::on_commit_buffer_handler::<State>(surface);

        if let Some(window) = self.window_for(surface) {
            // Refresh the window's cached geometry from the new buffer, so the
            // scene bbox (and pointer hit-testing) tracks the client's size.
            window.on_commit();
            // xdg-shell requires a configure before the client attaches a buffer.
            // The client's initial commit (no buffer) is our cue to send it.
            if let Some(toplevel) = window.toplevel() {
                if !toplevel.is_initial_configure_sent() {
                    toplevel.send_configure();
                }
            }
        }
    }
}

impl XdgShellHandler for State {
    fn xdg_shell_state(&mut self) -> &mut XdgShellState {
        &mut self.xdg
    }

    fn new_toplevel(&mut self, surface: ToplevelSurface) {
        surface.with_pending_state(|state| {
            state.states.set(xdg_toplevel::State::Activated);
        });
        let window = Window::new_wayland_window(surface);
        let x = self.next_x;
        self.next_x = self.next_x.wrapping_add(32);
        self.space.map_element(window, (x, 0), false);
    }

    fn new_popup(&mut self, _surface: PopupSurface, _positioner: PositionerState) {}

    fn grab(&mut self, _surface: PopupSurface, _seat: WlSeat, _serial: Serial) {}

    fn reposition_request(
        &mut self,
        _surface: PopupSurface,
        _positioner: PositionerState,
        _token: u32,
    ) {
    }

    fn toplevel_destroyed(&mut self, surface: ToplevelSurface) {
        if let Some(window) = self.window_for(surface.wl_surface()) {
            self.space.unmap_elem(&window);
        }
    }
}

impl BufferHandler for State {
    fn buffer_destroyed(&mut self, _buffer: &WlBuffer) {}
}

impl ShmHandler for State {
    fn shm_state(&self) -> &ShmState {
        &self.shm
    }
}

impl SeatHandler for State {
    type KeyboardFocus = WlSurface;
    type PointerFocus = WlSurface;
    type TouchFocus = WlSurface;

    fn seat_state(&mut self) -> &mut SeatState<State> {
        &mut self.seats
    }

    fn focus_changed(&mut self, _seat: &Seat<Self>, _focused: Option<&WlSurface>) {}
    fn cursor_image(&mut self, _seat: &Seat<Self>, _image: CursorImageStatus) {}
}

impl OutputHandler for State {}

delegate_compositor!(State);
delegate_shm!(State);
delegate_xdg_shell!(State);
delegate_seat!(State);
delegate_output!(State);

// Per-client state the Wayland core hangs off each connection.
#[derive(Default)]
struct ClientState {
    compositor: CompositorClientState,
}

impl ClientData for ClientState {
    fn initialized(&self, _id: ClientId) {}
    fn disconnected(&self, _id: ClientId, _reason: DisconnectReason) {}
}

/// A running Horizon compositor: a real Wayland server, minus a display backend.
///
/// Clients connect over the Unix socket named by [`socket_name`] (under
/// `$XDG_RUNTIME_DIR`). [`dispatch`] services them one batch at a time; the
/// caller owns the loop, so it can do its own work between batches (a CLI prints
/// the windows that came and went; a test asserts on the scene).
///
/// [`socket_name`]: Compositor::socket_name
/// [`dispatch`]: Compositor::dispatch
pub struct Compositor {
    display: Display<State>,
    event_loop: EventLoop<'static, State>,
    state: State,
    socket: OsString,
}

impl Compositor {
    /// Bring up the server: create the protocol globals, bind a Wayland socket,
    /// and wire the event loop. Returns once clients can connect.
    pub fn new() -> Result<Compositor> {
        let event_loop: EventLoop<'static, State> =
            EventLoop::try_new().map_err(|e| Error::Init(e.to_string()))?;
        let display: Display<State> = Display::new().map_err(|e| Error::Init(e.to_string()))?;
        let dh = display.handle();

        let compositor = CompositorState::new::<State>(&dh);
        let formats: Vec<wl_shm::Format> = Vec::new();
        let shm = ShmState::new::<State>(&dh, formats);
        let xdg = XdgShellState::new::<State>(&dh);
        let outputs = OutputManagerState::new_with_xdg_output::<State>(&dh);

        let mut seats: SeatState<State> = SeatState::new();
        let mut seat = seats.new_wl_seat(&dh, "seat0");
        // The keyboard compiles an xkb keymap (libxkbcommon). Treat a failure as
        // non-fatal: a host with no xkb data can still run the compositor, just
        // without a keyboard, which is enough for the headless core.
        if let Err(e) = seat.add_keyboard(Default::default(), 200, 25) {
            eprintln!("compositor: no keyboard ({e})");
        }
        seat.add_pointer();

        // One virtual output so clients know the geometry they live on.
        let output = Output::new(
            "HEADLESS-1".into(),
            PhysicalProperties {
                size: (0, 0).into(),
                subpixel: Subpixel::Unknown,
                make: "Horizon".into(),
                model: "Headless".into(),
            },
        );
        let mode = Mode {
            size: (1920, 1080).into(),
            refresh: 60_000,
        };
        output.create_global::<State>(&dh);
        output.change_current_state(
            Some(mode),
            Some(Transform::Normal),
            Some(Scale::Integer(1)),
            Some((0, 0).into()),
        );
        output.set_preferred(mode);

        let mut space: Space<Window> = Space::default();
        space.map_output(&output, (0, 0));

        let state = State {
            dh: dh.clone(),
            compositor,
            shm,
            xdg,
            seats,
            seat,
            outputs,
            output,
            space,
            #[cfg(feature = "render")]
            background: None,
            next_x: 0,
            pointer_loc: (0.0, 0.0).into(),
            pending_shell_click: None,
            start: Instant::now(),
        };

        // New clients arrive here.
        let source = ListeningSocketSource::new_auto().map_err(|e| Error::Bind(e.to_string()))?;
        let socket = source.socket_name().to_os_string();
        event_loop
            .handle()
            .insert_source(source, |stream, _, state: &mut State| {
                if let Err(e) = state
                    .dh
                    .insert_client(stream, Arc::new(ClientState::default()))
                {
                    eprintln!("compositor: client insert failed ({e})");
                }
            })
            .map_err(|e| Error::Init(e.to_string()))?;

        // Wake the loop when a client has protocol traffic. The actual dispatch
        // of that traffic happens in `dispatch`, where we also own the Display.
        let fd = display.as_fd().try_clone_to_owned()?;
        event_loop
            .handle()
            .insert_source(
                Generic::new(fd, Interest::READ, CalloopMode::Level),
                |_, _, _| Ok(PostAction::Continue),
            )
            .map_err(|e| Error::Init(e.to_string()))?;

        Ok(Compositor {
            display,
            event_loop,
            state,
            socket,
        })
    }

    /// The Wayland socket name clients connect on (set `WAYLAND_DISPLAY` to it).
    pub fn socket_name(&self) -> &OsStr {
        &self.socket
    }

    /// Service pending events for up to `timeout`: accept new clients, dispatch
    /// their requests, prune dead windows, and flush replies. Returns after one
    /// batch so the caller stays in control of the loop.
    pub fn dispatch(&mut self, timeout: Option<Duration>) -> Result<()> {
        self.event_loop
            .dispatch(timeout, &mut self.state)
            .map_err(|e| Error::Loop(e.to_string()))?;
        self.display.dispatch_clients(&mut self.state)?;
        self.state.space.refresh();
        self.display.flush_clients()?;
        Ok(())
    }

    /// How many toplevel windows are currently mapped in the scene.
    pub fn window_count(&self) -> usize {
        self.state.space.elements().count()
    }

    /// The titles of the mapped toplevels, in scene order. A toplevel that has
    /// not set a title yet contributes nothing.
    pub fn window_titles(&self) -> Vec<String> {
        self.state
            .space
            .elements()
            .filter_map(|w| {
                let toplevel = w.toplevel()?;
                with_states(toplevel.wl_surface(), |states| {
                    states
                        .data_map
                        .get::<XdgToplevelSurfaceData>()
                        .and_then(|d| d.lock().ok())
                        .and_then(|d| d.title.clone())
                })
            })
            .collect()
    }

    /// Move the pointer to `(x, y)` in output-logical pixels and refocus it on
    /// the surface there (sending the client enter/leave and motion). A display
    /// backend drives this (the winit backend now, libinput on bare metal later);
    /// a test drives it directly.
    pub fn pointer_motion(&mut self, x: f64, y: f64) {
        self.state.pointer_motion(x, y);
    }

    /// Press or release a pointer `button` (a Linux evdev code, e.g. BTN_LEFT is
    /// 0x110). A press also gives the keyboard to the window under the pointer.
    pub fn pointer_button(&mut self, button: u32, pressed: bool) {
        self.state.pointer_button(button, pressed);
    }

    /// Scroll the focused surface by the given horizontal and vertical amounts.
    pub fn pointer_axis(&mut self, horizontal: f64, vertical: f64) {
        self.state.pointer_axis(horizontal, vertical);
    }

    /// Press or release `keycode` (a Linux evdev keycode, e.g. KEY_A is 30) on
    /// the keyboard-focused client. A no-op when nothing holds focus or the host
    /// has no keyboard.
    pub fn keyboard_key(&mut self, keycode: u32, pressed: bool) {
        self.state.keyboard_key(keycode, pressed);
    }

    /// Whether the seat has a keyboard. A host with no xkb data has none, and the
    /// keyboard path is then a no-op; callers gate keyboard assertions on this.
    pub fn has_keyboard(&self) -> bool {
        self.state.seat.get_keyboard().is_some()
    }

    /// Take the position of the most recent pointer press that landed on the
    /// shell background (no client window under the cursor), in output-logical
    /// pixels, clearing it. The owner resolves it against whatever it drew there:
    /// Horizon maps it through the Glass `Scene` to a `sever` action. Returns
    /// `None` if no such click is pending. At output scale 1 these coordinates are
    /// the shell background's own pixels, so they index its scene directly.
    pub fn take_shell_click(&mut self) -> Option<(i32, i32)> {
        self.state.pending_shell_click.take()
    }

    /// Composite the current scene into an offscreen framebuffer the size of the
    /// output and read the pixels back. This is the headless render path: it
    /// imports each window's shm buffer and paints the `Space` with a software
    /// (pixman) renderer, no display or GPU, so a test can assert on the result.
    #[cfg(feature = "render")]
    pub fn render(&mut self) -> Result<crate::render::RenderedFrame> {
        crate::render::render_space(
            &self.state.space,
            &self.state.output,
            self.state.background.as_ref(),
        )
    }

    /// Set the shell background: the full-screen image drawn behind every client
    /// window. `rgba` is `width * height` pixels, four bytes each in R, G, B, A
    /// order (what `glass::Pixmap` produces); an empty slice or a non-positive
    /// size clears it. Horizon renders the Glass surface and sets it here.
    #[cfg(feature = "render")]
    pub fn set_shell_background(&mut self, rgba: &[u8], width: i32, height: i32) {
        let ok = width > 0 && height > 0 && rgba.len() >= (width as usize * height as usize * 4);
        self.state.background =
            ok.then(|| crate::render::ShellBackground::new(rgba.to_vec(), width, height));
    }

    // The shell background the winit backend paints behind the scene, if set.
    #[cfg(feature = "winit")]
    pub(crate) fn background(&self) -> Option<&crate::render::ShellBackground> {
        self.state.background.as_ref()
    }

    /// The output's pixel size (width, height). The offscreen framebuffer and the
    /// winit window both render at this size.
    #[cfg(feature = "render")]
    pub fn output_size(&self) -> (i32, i32) {
        self.state
            .output
            .current_mode()
            .map(|m| (m.size.w, m.size.h))
            .unwrap_or((0, 0))
    }

    // The scene an on-screen backend paints: the same `Space` the headless render
    // path composites. Shared by the winit and DRM backends.
    #[cfg(any(feature = "winit", feature = "udev"))]
    pub(crate) fn space(&self) -> &Space<Window> {
        &self.state.space
    }

    // Tell each mapped client it may draw its next frame. A static client shows
    // its first buffer without this, but an animating one waits on the callback.
    #[cfg(any(feature = "winit", feature = "udev"))]
    pub(crate) fn send_frames(&self, time_ms: u32) {
        let output = self.state.output.clone();
        for window in self.state.space.elements() {
            window.send_frame(
                &output,
                Duration::from_millis(time_ms as u64),
                None,
                |_, _| Some(output.clone()),
            );
        }
    }

    /// Open a nested window and present the scene on screen until it is closed,
    /// driving the Wayland server between frames. Needs a real Wayland or X
    /// session to nest in (and a GPU); this is the eye-verified, on-screen path.
    ///
    /// `on_shell_click` is called with the output-logical position of each pointer
    /// press that lands on the shell background (no client window over it).
    /// Returning new full-screen RGBA (output-sized, the bytes `glass::Pixmap`
    /// produces) redraws the background; that is how a click on a Glass `sever`
    /// button severs the capability and refreshes the desktop. Return `None` to
    /// leave the background unchanged, or pass a closure that always returns `None`
    /// when there is no interactive shell.
    #[cfg(feature = "winit")]
    pub fn show(&mut self, on_shell_click: impl FnMut(i32, i32) -> Option<Vec<u8>>) -> Result<()> {
        crate::winit::run(self, on_shell_click)
    }

    /// Drive a real display directly off the GPU (DRM/KMS) with libinput input,
    /// running until the process is stopped and driving the Wayland server between
    /// frames. This is the bare-metal path Horizon boots into; it takes over a
    /// seat and a GPU, so it runs on a console (not nested), and is eye-verified
    /// on hardware.
    #[cfg(feature = "udev")]
    pub fn run_drm(&mut self) -> Result<()> {
        crate::drm::run(self)
    }
}
