//! The on-screen winit backend: present the composited scene in a real window
//! nested inside an existing Wayland or X session.
//!
//! This is the part that needs a display and a GPU, so it is verified by eye on
//! a real Linux session, not in CI, the same way the Constellation's NAT
//! traversal waits for real machines while its core is tested on one host. What
//! it does test-cover, though, is the compositing itself: the frame is painted
//! by [`paint_space`], the exact code the headless render test asserts on, with
//! a GLES renderer in place of the offscreen pixman one. Only the windowing and
//! the GL present are new here.
//!
//! Input is forwarded: the window's keyboard and pointer events are translated
//! into seat actions on the compositor ([`Compositor::pointer_motion`] and the
//! rest), so a nested client is focusable and usable, not just visible. A real
//! DRM/KMS + libinput backend for bare metal comes after.

use std::time::{Duration, Instant};

use smithay::backend::input::{
    AbsolutePositionEvent, Axis, ButtonState, InputEvent, KeyState, KeyboardKeyEvent,
    PointerAxisEvent, PointerButtonEvent,
};
use smithay::backend::renderer::gles::GlesRenderer;
use smithay::backend::renderer::Color32F;
use smithay::backend::winit::{self, WinitEvent, WinitInput};
use smithay::reexports::winit::platform::pump_events::PumpStatus;
use smithay::utils::{Logical, Rectangle, Size, Transform};

use crate::render::paint_space;
use crate::server::ShellEvent;
use crate::{Compositor, Error, Result};

/// Open a nested window and run the compositor's render loop on it until the
/// window is closed. Drives the Wayland server (`comp`) between frames, so
/// clients connect and map exactly as in the headless core; their windows are
/// then painted into this window.
pub(crate) fn run(
    comp: &mut Compositor,
    mut on_shell: impl FnMut(ShellEvent) -> Option<Vec<u8>>,
) -> Result<()> {
    let (mut backend, mut winit) =
        winit::init::<GlesRenderer>().map_err(|e| Error::Render(format!("winit init: {e}")))?;
    backend.window().set_title("Horizon compositor");

    let start = Instant::now();
    let clear = Color32F::new(0.06, 0.06, 0.06, 1.0);

    loop {
        let mut closed = false;
        let mut inputs: Vec<InputEvent<WinitInput>> = Vec::new();
        // A resize keeps the window's own size, which `window_size()` reports
        // each frame, so we only collect input and the close request here.
        let status = winit.dispatch_new_events(|event| match event {
            WinitEvent::CloseRequested => closed = true,
            WinitEvent::Input(event) => inputs.push(event),
            _ => {}
        });
        if closed || matches!(status, PumpStatus::Exit(_)) {
            return Ok(());
        }

        // Route this batch of input to the focused client(s) before rendering.
        // Pointer positions arrive normalized to the window, so scale them to the
        // output the scene lives on.
        let (ow, oh) = comp.output_size();
        let output = Size::<i32, Logical>::from((ow, oh));
        for event in inputs {
            apply_input(comp, event, output);
        }

        // A press on the shell background (no client window over it) is offered to
        // the owner; if it redraws the surface (e.g. a Glass `sever` button was
        // clicked), upload the new background for this frame.
        if let Some((x, y)) = comp.take_shell_click() {
            if let Some(rgba) = on_shell(ShellEvent::Click(x, y)) {
                comp.set_shell_background(&rgba, ow, oh);
            }
        }

        // Keystrokes that arrived while no client held focus belong to the shell
        // (its command palette); offer each and upload any redraw it returns.
        for key in comp.take_shell_keys() {
            if let Some(rgba) = on_shell(ShellEvent::Key(key)) {
                comp.set_shell_background(&rgba, ow, oh);
            }
        }

        // Offer a tick so the owner can poll for changes made outside the shell
        // (e.g. the audit log grew) and refresh the background. The owner rate-
        // limits this, so most ticks return None and cost only a cheap check.
        if let Some(rgba) = on_shell(ShellEvent::Tick) {
            comp.set_shell_background(&rgba, ow, oh);
        }

        // Service Wayland clients (accept, dispatch, flush) between frames.
        comp.dispatch(Some(Duration::from_millis(16)))?;

        let size = backend.window_size();
        let damage = Rectangle::from_size(size);
        {
            let (renderer, mut framebuffer) = backend
                .bind()
                .map_err(|e| Error::Render(format!("bind: {e}")))?;
            // GL framebuffers have a bottom-left origin, so present flipped.
            paint_space(
                renderer,
                &mut framebuffer,
                comp.space(),
                size,
                Transform::Flipped180,
                clear,
                comp.background(),
            )?;
        }
        backend
            .submit(Some(&[damage]))
            .map_err(|e| Error::Render(format!("submit: {e}")))?;

        // Let animating clients draw their next frame.
        comp.send_frames(start.elapsed().as_millis() as u32);
    }
}

// Translate one winit input event into a seat action on the compositor. The
// pointer position is normalized to the window, so it scales to `output`; winit
// reports X keymap keycodes (evdev + 8), which the seat API takes as evdev.
fn apply_input(comp: &mut Compositor, event: InputEvent<WinitInput>, output: Size<i32, Logical>) {
    match event {
        InputEvent::PointerMotionAbsolute { event } => {
            let pos = event.position_transformed(output);
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
