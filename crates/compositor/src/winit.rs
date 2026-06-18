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
//! It is a viewer for now: it shows every client window but does not yet forward
//! input to them (keyboard and pointer focus come next), and a real DRM/KMS
//! backend for bare metal comes after.

use std::time::{Duration, Instant};

use smithay::backend::renderer::gles::GlesRenderer;
use smithay::backend::renderer::Color32F;
use smithay::backend::winit::{self, WinitEvent};
use smithay::reexports::winit::platform::pump_events::PumpStatus;
use smithay::utils::{Rectangle, Transform};

use crate::render::paint_space;
use crate::{Compositor, Error, Result};

/// Open a nested window and run the compositor's render loop on it until the
/// window is closed. Drives the Wayland server (`comp`) between frames, so
/// clients connect and map exactly as in the headless core; their windows are
/// then painted into this window.
pub(crate) fn run(comp: &mut Compositor) -> Result<()> {
    let (mut backend, mut winit) =
        winit::init::<GlesRenderer>().map_err(|e| Error::Render(format!("winit init: {e}")))?;
    backend.window().set_title("Horizon compositor");

    let start = Instant::now();
    let clear = Color32F::new(0.06, 0.06, 0.06, 1.0);

    loop {
        let mut closed = false;
        // Input forwarding to clients comes later; resize keeps the window's own
        // size, which `window_size()` reports each frame. So only the close
        // request matters here.
        let status = winit.dispatch_new_events(|event| {
            if let WinitEvent::CloseRequested = event {
                closed = true;
            }
        });
        if closed || matches!(status, PumpStatus::Exit(_)) {
            return Ok(());
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
            )?;
        }
        backend
            .submit(Some(&[damage]))
            .map_err(|e| Error::Render(format!("submit: {e}")))?;

        // Let animating clients draw their next frame.
        comp.send_frames(start.elapsed().as_millis() as u32);
    }
}
