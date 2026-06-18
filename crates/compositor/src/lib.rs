//! The Horizon Wayland compositor (L5, the experience layer).
//!
//! The default build is the headless core: a real Wayland display server that
//! real clients connect to. It owns the core protocol, [`wl_compositor`],
//! [`wl_shm`], [`xdg_shell`], [`wl_seat`], and [`wl_output`], and a scene graph
//! (a Smithay `Space`) that tracks every mapped toplevel. Two features paint it:
//!
//! - `render` adds a software (pixman) renderer that imports each client's shm
//!   buffer and composites the `Space` into an offscreen framebuffer, whose
//!   pixels are read back. No display and no GPU, so it is tested headlessly:
//!   `Compositor::render` is asserted on pixel by pixel, the same way the
//!   protocol is. This is the part that proves windows become pixels.
//! - `winit` (which builds on `render`) adds the on-screen backend: present the
//!   composited scene in a real window nested in an existing Wayland or X
//!   session, via `Compositor::show`. That needs real hardware, so it is
//!   verified by eye, not in CI, the same way the Constellation's networking
//!   core is fully tested on one host while only NAT traversal waits for real
//!   machines. The compositing it runs is the shared, tested path; only the
//!   windowing and GL present are new.
//! - `udev` (also building on `render`) adds the bare-metal backend: drive a real
//!   display directly off the GPU via DRM/KMS and libinput, with no session to
//!   nest in, through `Compositor::run_drm`. This is what Horizon boots into on
//!   hardware. It reuses the same compositing and seat routing the other paths do,
//!   so only the GPU/seat plumbing is new; like winit it is compile-checked in CI
//!   and eye-verified on bare metal.
//!
//! Input is routed through the seat by [`Compositor::pointer_motion`] and the
//! other input methods: pointer focus follows the cursor, a click focuses the
//! window under it, and keys go to that focus. A display backend feeds them raw
//! events (the `winit` one now, a libinput one on bare metal later). Like the
//! compositing, this routing is proven headlessly, a real client is checked to
//! receive the right enter/motion/button and key events, so only the backend
//! plumbing waits for a screen.
//!
//! Each app on Horizon is meant to be a confined Wayland client living in a
//! Cell; the exec path that makes that real already exists in the `cells`
//! crate. Glass, the live transparency surface over the Weave audit log, will
//! land here as a compositor surface drawn by this renderer.
//!
//! Linux only. On other hosts the crate compiles (so the workspace builds on
//! darwin) but [`available`] reports false and there is no `Compositor`.
//!
//! [`wl_compositor`]: https://wayland.app/protocols/wayland#wl_compositor
//! [`wl_shm`]: https://wayland.app/protocols/wayland#wl_shm
//! [`xdg_shell`]: https://wayland.app/protocols/xdg-shell
//! [`wl_seat`]: https://wayland.app/protocols/wayland#wl_seat
//! [`wl_output`]: https://wayland.app/protocols/wayland#wl_output

mod error;
pub use error::{Error, Result};

#[cfg(target_os = "linux")]
mod server;
#[cfg(target_os = "linux")]
pub use server::Compositor;

// Offscreen software compositing (the `render` feature) and the on-screen winit
// backend (the `winit` feature, which builds on it) live behind features so the
// default build stays protocol + scene only.
#[cfg(all(target_os = "linux", feature = "render"))]
mod render;
#[cfg(all(target_os = "linux", feature = "render"))]
pub use render::RenderedFrame;

#[cfg(all(target_os = "linux", feature = "winit"))]
mod winit;

// The bare-metal DRM/KMS + libinput backend (the `udev` feature): drive a real
// display directly off the GPU, the path Horizon boots into on hardware. Like
// winit it reuses the tested compositing and seat routing, so only the backend
// plumbing is new, and that needs a real GPU and a seat, so it is compile-checked
// in CI and eye-verified on bare metal.
#[cfg(all(target_os = "linux", feature = "udev"))]
mod drm;

/// Whether a compositor can run on this host. Linux only; elsewhere there is no
/// Wayland server to host and [`Compositor`] does not exist.
pub fn available() -> bool {
    cfg!(target_os = "linux")
}
