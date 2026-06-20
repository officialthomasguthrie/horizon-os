//! The headless Wayland server: Smithay protocol state, the handler glue that
//! makes a client's window appear in the scene, and the event loop that drives
//! it. Owned by the `Compositor` type re-exported from the crate root.

use std::ffi::{OsStr, OsString};
use std::os::fd::AsFd;
use std::sync::Arc;
use std::time::{Duration, Instant};

use smithay::backend::input::{Axis, AxisSource, ButtonState, KeyState};
use smithay::desktop::{Space, Window, WindowSurfaceType};
use smithay::input::keyboard::{FilterResult, Keycode, Keysym};
use smithay::input::pointer::{AxisFrame, ButtonEvent, CursorImageStatus, MotionEvent};
use smithay::input::{Seat, SeatHandler, SeatState};
use smithay::output::{Mode, Output, PhysicalProperties, Scale, Subpixel};
use smithay::reexports::calloop::generic::Generic;
use smithay::reexports::calloop::{EventLoop, Interest, Mode as CalloopMode, PostAction};
use smithay::reexports::wayland_protocols::xdg::shell::server::xdg_toplevel;
use smithay::reexports::wayland_server::backend::{
    ClientData, ClientId, DisconnectReason, GlobalId,
};
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

/// A keystroke the compositor routes to the shell when no client holds keyboard
/// focus, i.e. the desktop itself is focused (a press on the background clears any
/// client focus, so typing then lands here). It is already translated from the
/// xkb keysym, so the owner edits text without touching keycodes; Horizon feeds
/// these into the Glass command palette. Only presses are reported, and only keys
/// with a text meaning: modifiers, function keys, and chords with Ctrl/Alt/Super
/// are dropped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShellKey {
    /// A printable character to insert at the cursor.
    Char(char),
    Backspace,
    Delete,
    Left,
    Right,
    Home,
    End,
    /// Commit the line (run the command).
    Enter,
    /// Cancel: clear the line.
    Escape,
}

/// What an on-screen backend is asking the shell owner to handle. Every arm may
/// return new full-screen RGBA (output-sized, the bytes `glass::Pixmap` yields)
/// to redraw the background, or `None` to leave it unchanged. This is the one
/// callback [`Compositor::show`] and [`Compositor::run_drm`] take, so the owner
/// holds the shell across clicks, keys, and ticks behind a single mutable borrow.
#[cfg(any(feature = "winit", feature = "udev"))]
pub enum ShellEvent {
    /// A pointer press landed on the shell background at this output-logical
    /// position (no client window was over it), e.g. a click on a Glass `sever`
    /// button.
    Click(i32, i32),
    /// A keystroke arrived while no client held keyboard focus, so the shell owns
    /// it: text for the Glass command palette (a launcher and command line).
    Key(ShellKey),
    /// A periodic tick, offered each loop iteration, so the owner can poll for
    /// changes made from outside (the audit log grew because another process
    /// granted, used, or revoked a capability) and refresh a live desktop without
    /// a click. The owner sets its own poll cadence; returning `None` is cheap.
    Tick,
}

// Translate an xkb keysym (already modified by shift, caps, etc.) into a shell
// key. Named editing keys are matched first because xkb maps several of them
// (Backspace, Return, Escape, Delete) to ASCII control characters, which are not
// text; anything else becomes a Char only if it is a printable character.
fn shell_key(sym: Keysym) -> Option<ShellKey> {
    match sym {
        Keysym::BackSpace => Some(ShellKey::Backspace),
        Keysym::Delete => Some(ShellKey::Delete),
        Keysym::Return | Keysym::KP_Enter => Some(ShellKey::Enter),
        Keysym::Escape => Some(ShellKey::Escape),
        Keysym::Left => Some(ShellKey::Left),
        Keysym::Right => Some(ShellKey::Right),
        Keysym::Home => Some(ShellKey::Home),
        Keysym::End => Some(ShellKey::End),
        other => other
            .key_char()
            .filter(|c| !c.is_control())
            .map(ShellKey::Char),
    }
}

/// A handle to an output placed in the shared logical space via
/// [`Compositor::add_output`], used to render or move it. Multi-monitor support:
/// each output occupies its own region of one coordinate space, so a window lives
/// at a single position across the whole desktop and each output paints only the
/// part it covers. The DRM backend builds the same arrangement from real
/// connectors; this id-based API is the headless way to set one up and read each
/// output back, so per-output region rendering is provable without a display.
#[cfg(feature = "render")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct OutputId(u32);

// An output placed in the shared logical space through the id-based API: the
// smithay `Output` (its mode/scale/location source and the Space mapping) plus the
// `wl_output` global that advertises this monitor to clients, so a client
// enumerates it and reads its logical position and mode. Removing the output
// withdraws the global.
#[cfg(feature = "render")]
struct PlacedOutput {
    output: Output,
    global: GlobalId,
}

// Everything the protocol handlers touch. The `Compositor` keeps this next to
// the `Display` so dispatch can hand it to both calloop and the Wayland core.
struct State {
    dh: DisplayHandle,
    compositor: CompositorState,
    shm: ShmState,
    xdg: XdgShellState,
    seats: SeatState<State>,
    // The seat carries the keyboard and pointer; the input methods below drive it.
    seat: Seat<State>,
    #[allow(dead_code)]
    outputs: OutputManagerState,
    // The default placeholder output: the single virtual screen the headless core
    // and the winit nested window present. The DRM backend and the headless
    // multi-monitor API place their own outputs instead and retire this one's
    // global (see `placeholder_global`).
    #[allow(dead_code)]
    output: Output,
    // The placeholder output's `wl_output` global while it is advertised, else None
    // while it is withdrawn in favour of explicit outputs (the headless
    // `add_output` monitors or the DRM connectors). Advertised by default so the
    // headless core and winit show one screen; withdrawn the moment a real output
    // is placed, so a client enumerates the actual monitors instead of a phantom.
    #[allow(dead_code)]
    placeholder_global: Option<GlobalId>,
    space: Space<Window>,
    // Outputs placed in the shared logical space through the id-based API, keyed by
    // their handle, so `render_output` can find one to read back and `move_output`
    // can relocate it. Each carries its own `wl_output` global, so a client
    // enumerates these monitors. The default `output` above is the always-present
    // placeholder the single-output paths use; these are extra ones a multi-monitor
    // setup maps in (the headless mirror of what the DRM backend builds from real
    // connectors). Render-gated: it drives the offscreen per-output readback.
    #[cfg(feature = "render")]
    extra_outputs: std::collections::HashMap<u32, PlacedOutput>,
    #[cfg(feature = "render")]
    next_output_id: u32,
    // The shell background: the L5 home surface (Horizon draws Glass here) painted
    // behind every client window. None paints the clear color. Render-gated, since
    // drawing it needs a renderer.
    #[cfg(feature = "render")]
    background: Option<crate::render::ShellBackground>,
    // Bumped on every `set_shell_background`. The DRM backend caches an upload of
    // the background and rebuilds it only when this changes, so an idle desktop is
    // not re-uploaded each frame (which would defeat its damage tracking). Only the
    // DRM path caches, so this is udev-gated; winit redraws every frame regardless.
    #[cfg(feature = "udev")]
    background_gen: u64,
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
    // Keystrokes that arrived while no client held keyboard focus, so the shell
    // owns the keyboard (its command palette). Already translated to `ShellKey`,
    // drained by `take_shell_keys`. Input, not drawing, so not render-gated.
    pending_shell_keys: Vec<ShellKey>,
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

// Toggle the placeholder output's `wl_output` global. The default output stands in
// for the single screen until explicit outputs (the headless `add_output` monitors
// or the real DRM connectors) are placed; then its global is withdrawn so clients
// enumerate the real monitors, and restored when the last explicit output is
// removed so a client still sees one screen. Idempotent. Only the multi-output
// paths call this, and every build that compiles them enables `render` (winit and
// udev both turn it on), so it is render-gated.
#[cfg(feature = "render")]
impl State {
    fn set_placeholder_global(&mut self, advertised: bool) {
        if advertised && self.placeholder_global.is_none() {
            self.placeholder_global = Some(self.output.create_global::<State>(&self.dh));
        } else if !advertised {
            if let Some(id) = self.placeholder_global.take() {
                self.dh.remove_global::<State>(id);
            }
        }
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
        // With a client focused, keys go to it. With nothing focused, the desktop
        // is focused: the shell owns the keyboard and the keystroke is recorded
        // for the owner (the Glass command palette) instead of forwarded.
        let to_shell = keyboard.current_focus().is_none();
        // Evdev keycodes sit 8 below the X keymap codes xkb compiles to; the
        // wire event is mapped back down by the seat.
        keyboard.input::<(), _>(
            self,
            Keycode::from(keycode + 8),
            state,
            serial,
            time,
            |data, mods, handle| {
                if !to_shell {
                    return FilterResult::Forward;
                }
                // Translate to a shell key on press only, skipping chords with a
                // command modifier so a shortcut never types text. Swallow it
                // either way: no client should see a key meant for the shell.
                if pressed && !mods.ctrl && !mods.alt && !mods.logo {
                    if let Some(k) = shell_key(handle.modified_sym()) {
                        data.pending_shell_keys.push(k);
                    }
                }
                FilterResult::Intercept(())
            },
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
        let placeholder_global = output.create_global::<State>(&dh);
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
            placeholder_global: Some(placeholder_global),
            space,
            #[cfg(feature = "render")]
            extra_outputs: std::collections::HashMap::new(),
            #[cfg(feature = "render")]
            next_output_id: 0,
            #[cfg(feature = "render")]
            background: None,
            #[cfg(feature = "udev")]
            background_gen: 0,
            next_x: 0,
            pointer_loc: (0.0, 0.0).into(),
            pending_shell_click: None,
            pending_shell_keys: Vec::new(),
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

    /// Take the keystrokes that arrived while no client held keyboard focus, in
    /// arrival order, clearing the queue. These are the keys the shell owns (the
    /// desktop is focused), already translated from xkb to [`ShellKey`]; Horizon
    /// feeds them into the Glass command palette. Empty when nothing is pending.
    /// A backend drains this each loop iteration alongside [`take_shell_click`].
    ///
    /// [`take_shell_click`]: Compositor::take_shell_click
    pub fn take_shell_keys(&mut self) -> Vec<ShellKey> {
        std::mem::take(&mut self.state.pending_shell_keys)
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

    /// Place an output of the given mode at logical position `(x, y)` in the one
    /// shared desktop space and return a handle to it. This is the headless way to
    /// build a multi-monitor arrangement: each added output owns its region, so a
    /// window at a logical position shows on whichever output covers it and each
    /// reads back only its own slice (the same per-output rendering the DRM backend
    /// scans out from real connectors). The output advertises its own `wl_output`
    /// global at this logical position and mode, so a client enumerates it as a
    /// distinct monitor; the first added output retires the default placeholder
    /// global so clients see the real monitors, not a phantom.
    #[cfg(feature = "render")]
    pub fn add_output(&mut self, name: &str, width: i32, height: i32, x: i32, y: i32) -> OutputId {
        let output = Output::new(
            name.to_string(),
            PhysicalProperties {
                size: (0, 0).into(),
                subpixel: Subpixel::Unknown,
                make: "Horizon".into(),
                model: "Virtual".into(),
            },
        );
        let mode = Mode {
            size: (width, height).into(),
            refresh: 60_000,
        };
        output.change_current_state(
            Some(mode),
            Some(Transform::Normal),
            Some(Scale::Integer(1)),
            Some((x, y).into()),
        );
        output.set_preferred(mode);
        let global = output.create_global::<State>(&self.state.dh);
        self.state.space.map_output(&output, (x, y));
        // The first explicit monitor retires the placeholder global, so a client
        // enumerates the real outputs and not the phantom default.
        self.state.set_placeholder_global(false);
        let id = self.state.next_output_id;
        self.state.next_output_id += 1;
        self.state
            .extra_outputs
            .insert(id, PlacedOutput { output, global });
        OutputId(id)
    }

    /// Move an added output to a new logical position, rearranging the desktop.
    /// A no-op for an unknown handle.
    #[cfg(feature = "render")]
    pub fn move_output(&mut self, id: OutputId, x: i32, y: i32) {
        if let Some(output) = self
            .state
            .extra_outputs
            .get(&id.0)
            .map(|p| p.output.clone())
        {
            // Update the advertised location (what the `wl_output` global reports to
            // clients) and the Space mapping (the region it renders) together, so a
            // client sees the monitor move and the output scans out its new region.
            output.change_current_state(None, None, None, Some((x, y).into()));
            self.state.space.map_output(&output, (x, y));
        }
    }

    /// Remove an added output from the shared space, withdrawing its `wl_output`
    /// global. A no-op for an unknown handle. Removing the last added output brings
    /// the placeholder global back, so a client still sees one screen.
    #[cfg(feature = "render")]
    pub fn remove_output(&mut self, id: OutputId) {
        if let Some(placed) = self.state.extra_outputs.remove(&id.0) {
            self.state.space.unmap_output(&placed.output);
            self.state.dh.remove_global::<State>(placed.global);
            if self.state.extra_outputs.is_empty() {
                self.state.set_placeholder_global(true);
            }
        }
    }

    /// Composite one added output's own region of the shared space into an
    /// offscreen framebuffer the size of its mode and read the pixels back. The
    /// window scene is shared across outputs, so this shows only what falls on this
    /// output, offset to its logical origin: the headless proof that outputs render
    /// their own region rather than mirroring the whole scene.
    #[cfg(feature = "render")]
    pub fn render_output(&mut self, id: OutputId) -> Result<crate::render::RenderedFrame> {
        let output = self
            .state
            .extra_outputs
            .get(&id.0)
            .map(|p| p.output.clone())
            .ok_or_else(|| Error::Render("unknown output".into()))?;
        crate::render::render_output(&self.state.space, &output, self.state.background.as_ref())
    }

    /// Place (or move) a real output in the shared logical space at `(x, y)`. The
    /// DRM backend calls this for each connector it lights, so its outputs render
    /// their own region exactly as the headless [`add_output`] ones do; it owns the
    /// `Output` (it is also the `DrmOutput`'s mode source), so this takes it by
    /// reference rather than minting one.
    ///
    /// [`add_output`]: Compositor::add_output
    #[cfg(feature = "udev")]
    pub(crate) fn map_output(&mut self, output: &Output, x: i32, y: i32) {
        // Keep the advertised location (what this output's `wl_output` global reports
        // to clients) and the Space mapping (the region it scans out) in step, so a
        // client sees the monitor exactly where the layout placed it.
        output.change_current_state(None, None, None, Some((x, y).into()));
        self.state.space.map_output(output, (x, y));
    }

    /// Remove a real output from the shared space (its connector was unplugged). Its
    /// `wl_output` global is withdrawn separately by the backend, which owns the id.
    #[cfg(feature = "udev")]
    pub(crate) fn unmap_output(&mut self, output: &Output) {
        self.state.space.unmap_output(output);
    }

    /// A clone of the Wayland display handle, for the DRM backend to create and
    /// withdraw a `wl_output` global per connector as monitors come and go (through
    /// [`create_output_global`] / [`remove_output_global`], which name the private
    /// server `State` this handle is typed against).
    #[cfg(feature = "udev")]
    pub(crate) fn display_handle(&self) -> DisplayHandle {
        self.state.dh.clone()
    }

    /// Advertise or withdraw the placeholder output's global. The DRM backend
    /// withdraws it once it lights its first real connector (so clients enumerate
    /// the actual monitors, not the phantom) and restores it if every monitor goes
    /// dark, so a client still sees one screen.
    #[cfg(feature = "udev")]
    pub(crate) fn set_placeholder_global(&mut self, advertised: bool) {
        self.state.set_placeholder_global(advertised);
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
        // A change (including a clear) invalidates the DRM backend's cached upload.
        #[cfg(feature = "udev")]
        {
            self.state.background_gen = self.state.background_gen.wrapping_add(1);
        }
    }

    // The shell background an on-screen backend paints behind the scene, if set.
    #[cfg(any(feature = "winit", feature = "udev"))]
    pub(crate) fn background(&self) -> Option<&crate::render::ShellBackground> {
        self.state.background.as_ref()
    }

    // A counter bumped on every `set_shell_background`, so the DRM backend knows
    // when to rebuild its cached background upload (an unchanged value means the
    // desktop is unchanged and the upload can be reused).
    #[cfg(feature = "udev")]
    pub(crate) fn background_generation(&self) -> u64 {
        self.state.background_gen
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
    /// `on_shell` handles both shell interactions through one [`ShellEvent`]:
    /// a [`Click`](ShellEvent::Click) reports a pointer press on the background
    /// (no client window over it), the path a Glass `sever` button takes, and a
    /// [`Tick`](ShellEvent::Tick) is offered each iteration so the owner can poll
    /// for outside changes. Returning new full-screen RGBA (output-sized, the
    /// bytes `glass::Pixmap` produces) redraws the background; `None` leaves it.
    /// Pass a closure that always returns `None` when there is no interactive
    /// shell. One closure, not two, so the owner holds the shell behind a single
    /// mutable borrow.
    #[cfg(feature = "winit")]
    pub fn show(&mut self, on_shell: impl FnMut(ShellEvent) -> Option<Vec<u8>>) -> Result<()> {
        crate::winit::run(self, on_shell)
    }

    /// Drive a real display directly off the GPU (DRM/KMS) with libinput input,
    /// running until the process is stopped and driving the Wayland server between
    /// frames. This is the bare-metal path Horizon boots into; it takes over a
    /// seat and a GPU, so it runs on a console (not nested), and is eye-verified
    /// on hardware.
    ///
    /// `on_shell` works exactly as in [`show`](Compositor::show): one closure
    /// over a [`ShellEvent`], a [`Click`](ShellEvent::Click) for a press on the
    /// background (the Glass `sever` path) and a [`Tick`](ShellEvent::Tick) each
    /// iteration to poll for outside changes, returning new full-screen RGBA to
    /// redraw the background or `None` to leave it. Pass a closure that always
    /// returns `None` when there is no interactive shell.
    #[cfg(feature = "udev")]
    pub fn run_drm(&mut self, on_shell: impl FnMut(ShellEvent) -> Option<Vec<u8>>) -> Result<()> {
        crate::drm::run(self, on_shell)
    }
}

/// Advertise `output` to clients as its own `wl_output` global, returning the id
/// that withdraws it. The DRM backend calls this for each connector it lights (it
/// holds the `Output` already, as the `DrmOutput`'s mode source), so a client
/// enumerates every real monitor at its layout position and mode. These live here,
/// not on the backend, because creating a global names the private server `State`
/// the display handle is typed against.
#[cfg(feature = "udev")]
pub(crate) fn create_output_global(dh: &DisplayHandle, output: &Output) -> GlobalId {
    output.create_global::<State>(dh)
}

/// Withdraw a `wl_output` global created by [`create_output_global`] (its connector
/// was unplugged or its GPU went away).
#[cfg(feature = "udev")]
pub(crate) fn remove_output_global(dh: &DisplayHandle, id: GlobalId) {
    dh.remove_global::<State>(id);
}
