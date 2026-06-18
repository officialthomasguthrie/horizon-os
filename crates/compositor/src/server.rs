//! The headless Wayland server: Smithay protocol state, the handler glue that
//! makes a client's window appear in the scene, and the event loop that drives
//! it. Owned by the `Compositor` type re-exported from the crate root.

use std::ffi::{OsStr, OsString};
use std::os::fd::AsFd;
use std::sync::Arc;
use std::time::Duration;

use smithay::desktop::{Space, Window};
use smithay::input::pointer::CursorImageStatus;
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
use smithay::utils::{Serial, Transform};
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
    // The seat global and the output global are advertised for their lifetime;
    // we hold them so they are not withdrawn, even though we do not read them
    // back yet (no input backend, no second output).
    #[allow(dead_code)]
    seat: Seat<State>,
    #[allow(dead_code)]
    outputs: OutputManagerState,
    #[allow(dead_code)]
    output: Output,
    space: Space<Window>,
    // Where the next toplevel is placed. Without a real layout we just step
    // windows across so several are distinct in the scene.
    next_x: i32,
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

        // xdg-shell requires a configure before the client attaches a buffer.
        // The client's initial commit (no buffer) is our cue to send it.
        if let Some(window) = self.window_for(surface) {
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
            next_x: 0,
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

    /// Composite the current scene into an offscreen framebuffer the size of the
    /// output and read the pixels back. This is the headless render path: it
    /// imports each window's shm buffer and paints the `Space` with a software
    /// (pixman) renderer, no display or GPU, so a test can assert on the result.
    #[cfg(feature = "render")]
    pub fn render(&mut self) -> Result<crate::render::RenderedFrame> {
        crate::render::render_space(&self.state.space, &self.state.output)
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

    // The scene the winit backend paints: the same `Space` the headless render
    // path composites.
    #[cfg(feature = "winit")]
    pub(crate) fn space(&self) -> &Space<Window> {
        &self.state.space
    }

    // Tell each mapped client it may draw its next frame. A static client shows
    // its first buffer without this, but an animating one waits on the callback.
    #[cfg(feature = "winit")]
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
    #[cfg(feature = "winit")]
    pub fn show(&mut self) -> Result<()> {
        crate::winit::run(self)
    }
}
