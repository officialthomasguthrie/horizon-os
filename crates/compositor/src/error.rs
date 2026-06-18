// Errors from building or driving the compositor. A failure names the step that
// refused, so a socket that would not bind reads differently from a loop that
// died.

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    // Setting up the display, event loop, or a protocol global failed.
    #[error("compositor init: {0}")]
    Init(String),
    // The Wayland listening socket could not be bound (no XDG_RUNTIME_DIR, or
    // every candidate name was taken).
    #[error("bind wayland socket: {0}")]
    Bind(String),
    // The event loop dispatch failed.
    #[error("event loop: {0}")]
    Loop(String),
    // Compositing a frame failed: a renderer would not start, a buffer would not
    // bind, or the framebuffer could not be read back. Only the render/winit
    // features reach this.
    #[error("render: {0}")]
    Render(String),
    // Not Linux: the compositor is a Linux Wayland server.
    #[error("compositor needs Linux (Wayland); this host has none")]
    Unsupported,
}

pub type Result<T> = std::result::Result<T, Error>;
